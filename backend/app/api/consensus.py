"""
BASCG T3-B — Multi-node Policy Consensus API
=============================================

Endpoints:
  POST /api/v1/consensus/proposals                  — Submit a new proposal
  GET  /api/v1/consensus/proposals                  — List proposals
  GET  /api/v1/consensus/proposals/{id}             — Proposal detail + votes
  POST /api/v1/consensus/proposals/{id}/vote        — Cast a signed vote
  POST /api/v1/consensus/proposals/{id}/tally       — Force tally (admin)
  POST /api/v1/consensus/expire                     — Sweep stale proposals (admin)
  GET  /api/v1/consensus/status                     — Config status
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_permission
from app.core.config import settings
from app.db.database import get_db
from app.services.consensus_service import (
    ALLOWED_THRESHOLD_KEYS,
    VALID_PROPOSAL_TYPES,
    consensus_service,
)

router = APIRouter()


# ── Pydantic request models ───────────────────────────────────────────────────

class ProposeRequest(BaseModel):
    proposal_type: str
    title:         str
    payload:       Dict[str, Any]
    description:   Optional[str] = None
    proposed_by:   Optional[str] = None   # override node_id (e.g. for cross-node relay)


class VoteRequest(BaseModel):
    node_id:   str
    vote:      str               # "accept" | "reject"
    reason:    Optional[str] = None
    signature: Optional[str] = None    # Ed25519 sig over vote payload
    signed_by: Optional[str] = None    # issuer key name


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_proposal(p, votes=None):
    return {
        "id":                 p.id,
        "proposal_type":      p.proposal_type,
        "title":              p.title,
        "description":        p.description,
        "payload":            p.payload,
        "proposed_by":        p.proposed_by,
        "status":             p.status,
        "expires_at":         p.expires_at.isoformat() if p.expires_at else None,
        "created_at":         p.created_at.isoformat() if p.created_at else None,
        "resolved_at":        p.resolved_at.isoformat() if p.resolved_at else None,
        "applied_policy_id":  p.applied_policy_id,
        "signed_by":          p.signed_by,
        **({"votes": [_fmt_vote(v) for v in votes]} if votes is not None else {}),
    }


def _fmt_vote(v):
    return {
        "id":         v.id,
        "node_id":    v.node_id,
        "vote":       v.vote,
        "reason":     v.reason,
        "signed_by":  v.signed_by,
        "voted_at":   v.voted_at.isoformat() if v.voted_at else None,
    }


def _check_enabled():
    if not bool(getattr(settings, "CONSENSUS_ENABLED", False)):
        raise HTTPException(
            status_code=503,
            detail=(
                "Consensus API is disabled. "
                "Set CONSENSUS_ENABLED=true to activate multi-node policy consensus."
            ),
        )


# ── POST /proposals ───────────────────────────────────────────────────────────

@router.post(
    "/proposals",
    summary="Submit a new multi-node policy consensus proposal",
    status_code=201,
)
async def create_proposal(
    body:         ProposeRequest,
    db:           AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Create a new governance policy proposal for consensus voting.

    proposal_type options:
      create_policy    — payload: {name, rules, policy_type, severity, …}
      update_policy    — payload: {policy_id, fields: {…}}
      disable_policy   — payload: {policy_id}
      update_threshold — payload: {threshold_key, value}
                         threshold_key must be one of: """ + ", ".join(sorted(ALLOWED_THRESHOLD_KEYS)) + """

    The proposal is signed with this node's Ed25519 key and enters 'pending' status.
    Other nodes vote via POST /proposals/{id}/vote.
    """
    _check_enabled()
    try:
        proposal = await consensus_service.propose(
            db            = db,
            proposal_type = body.proposal_type,
            title         = body.title,
            payload       = body.payload,
            proposed_by   = body.proposed_by,
            description   = body.description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _fmt_proposal(proposal)


# ── GET /proposals ────────────────────────────────────────────────────────────

@router.get(
    "/proposals",
    summary="List policy consensus proposals",
)
async def list_proposals(
    status: Optional[str] = Query(default=None,
                                  description="Filter: pending | accepted | rejected | expired"),
    limit:  int           = Query(default=50, ge=1, le=200),
    offset: int           = Query(default=0, ge=0),
    db:     AsyncSession  = Depends(get_db),
    current_user=Depends(require_permission("policies:read")),
):
    _check_enabled()
    proposals = await consensus_service.list_proposals(
        db, status=status, limit=limit, offset=offset
    )
    return {"proposals": [_fmt_proposal(p) for p in proposals], "count": len(proposals)}


# ── GET /proposals/{id} ───────────────────────────────────────────────────────

@router.get(
    "/proposals/{proposal_id}",
    summary="Get a proposal and its votes",
)
async def get_proposal(
    proposal_id: str,
    db:          AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:read")),
):
    _check_enabled()
    proposal = await consensus_service.get_proposal(db, proposal_id)
    if not proposal:
        raise HTTPException(status_code=404, detail=f"Proposal {proposal_id!r} not found")
    votes = await consensus_service.get_votes(db, proposal_id)
    return _fmt_proposal(proposal, votes=votes)


# ── POST /proposals/{id}/vote ─────────────────────────────────────────────────

@router.post(
    "/proposals/{proposal_id}/vote",
    summary="Cast a signed vote on a pending proposal",
)
async def cast_vote(
    proposal_id: str,
    body:        VoteRequest,
    db:          AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Cast a vote on an open proposal.

    For cross-node votes, include `signature` (Ed25519 over canonical JSON of
    {proposal_id, node_id, vote, voted_at}) and `signed_by` (issuer name).
    The issuer must be a trusted key registered via the T2-B regulator-key import API.
    """
    _check_enabled()
    try:
        vote = await consensus_service.cast_vote(
            db          = db,
            proposal_id = proposal_id,
            node_id     = body.node_id,
            vote        = body.vote,
            signature   = body.signature,
            signed_by   = body.signed_by,
            reason      = body.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return _fmt_vote(vote)


# ── POST /proposals/{id}/tally ────────────────────────────────────────────────

@router.post(
    "/proposals/{proposal_id}/tally",
    summary="Trigger a consensus tally for a proposal",
)
async def tally_proposal(
    proposal_id: str,
    db:          AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Count all valid votes for the proposal and apply the policy change if quorum is met.

    Quorum: accept_count / valid_votes >= CONSENSUS_QUORUM_THRESHOLD (default 0.67)
            AND valid_votes >= CONSENSUS_MIN_VOTES (default 2)

    On acceptance the governance policy is created or updated immediately.
    """
    _check_enabled()
    try:
        result = await consensus_service.tally(db, proposal_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "proposal_id":       result.proposal_id,
        "status":            result.status,
        "total_votes":       result.total_votes,
        "accept_count":      result.accept_count,
        "reject_count":      result.reject_count,
        "invalid_votes":     result.invalid_votes,
        "quorum_met":        result.quorum_met,
        "applied":           result.applied,
        "applied_policy_id": result.applied_policy_id,
    }


# ── POST /expire ──────────────────────────────────────────────────────────────

@router.post(
    "/expire",
    summary="Sweep and expire all stale proposals",
)
async def expire_stale(
    db:          AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """Mark all pending proposals past their TTL as expired."""
    _check_enabled()
    count = await consensus_service.expire_stale_proposals(db)
    return {"expired": count}


# ── GET /status ───────────────────────────────────────────────────────────────

@router.get(
    "/status",
    summary="Consensus configuration status",
)
async def consensus_status(
    current_user=Depends(require_permission("policies:read")),
):
    return {
        "enabled":                bool(getattr(settings, "CONSENSUS_ENABLED", False)),
        "node_id":                getattr(settings, "CONSENSUS_NODE_ID", "local-node"),
        "quorum_threshold":       float(getattr(settings, "CONSENSUS_QUORUM_THRESHOLD", 0.67)),
        "min_votes":              int(getattr(settings, "CONSENSUS_MIN_VOTES", 2)),
        "proposal_ttl_hours":     int(getattr(settings, "CONSENSUS_PROPOSAL_TTL_HOURS", 72)),
        "verify_vote_signatures": bool(getattr(settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", True)),
        "valid_proposal_types":   sorted(VALID_PROPOSAL_TYPES),
        "allowed_threshold_keys": sorted(ALLOWED_THRESHOLD_KEYS),
    }
