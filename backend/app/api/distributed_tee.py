"""
BASCG T3-C — Distributed TEE Attestation API
=============================================

Endpoints (all under /api/v1/attestation):

  POST /distributed/challenge        — challenge a named peer node
  POST /distributed/respond          — respond to a peer's nonce challenge
  POST /distributed/receive          — receive attestation pushed by a peer
  POST /distributed/push             — push our attestation to a peer
  GET  /distributed/peers            — list latest record for each peer
  GET  /distributed/peers/{node_id}  — latest record for a specific peer
  GET  /distributed/status           — config + summary

All mutating endpoints require the "policies:write" scope.
Read endpoints require "policies:read".

Returns 503 when TEE_DISTRIBUTED_ENABLED=False.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db
from app.models.orm_models import RemoteNodeAttestation
from app.services.distributed_tee_service import distributed_tee_service

router = APIRouter()


# ── Guard ─────────────────────────────────────────────────────────────────────

def _check_enabled() -> None:
    if not bool(getattr(settings, "TEE_DISTRIBUTED_ENABLED", False)):
        raise HTTPException(
            status_code=503,
            detail=(
                "Distributed TEE attestation is disabled. "
                "Set TEE_DISTRIBUTED_ENABLED=true to enable."
            ),
        )


# ── Request / Response models ─────────────────────────────────────────────────

class ChallengeRequest(BaseModel):
    node_url: str
    node_id:  str


class RespondRequest(BaseModel):
    nonce: str


class ReceiveRequest(BaseModel):
    node_id:               str
    node_url:              str
    platform:              str
    pcr0:                  Optional[str] = None
    pcr0_match:            bool = False
    clearance_valid_until: Optional[str] = None
    raw_document_b64:      Optional[str] = None


class PushRequest(BaseModel):
    peer_url: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt(dt) -> Optional[str]:
    if not dt:
        return None
    s = dt.isoformat()
    return s.replace("+00:00", "Z") if "+" in s else s + "Z"


def _record_to_dict(r: RemoteNodeAttestation) -> dict:
    return {
        "id":                   r.id,
        "node_id":              r.node_id,
        "node_url":             r.node_url,
        "platform":             r.platform,
        "pcr0":                 r.pcr0,
        "pcr0_match":           r.pcr0_match,
        "verified":             r.verified,
        "failure_reason":       r.failure_reason,
        "clearance_valid_until": _fmt(r.clearance_valid_until),
        "attested_at":          _fmt(r.attested_at),
    }


# ── GET /distributed/status ────────────────────────────────────────────────────

@router.get(
    "/distributed/status",
    summary="Distributed TEE attestation configuration and summary",
)
async def distributed_tee_status(db: AsyncSession = Depends(get_db)):
    enabled  = bool(getattr(settings, "TEE_DISTRIBUTED_ENABLED", False))
    peers_raw = getattr(settings, "TEE_PEER_NODES", "").strip()
    peer_urls = [u.strip() for u in peers_raw.split(",") if u.strip()] if peers_raw else []

    peer_records = []
    if enabled:
        peer_records = await distributed_tee_service.list_peers(db)

    return {
        "distributed_enabled":    enabled,
        "configured_peers":       len(peer_urls),
        "peer_urls":              peer_urls,
        "challenge_timeout_secs": getattr(settings, "TEE_DISTRIBUTED_CHALLENGE_TIMEOUT_SECONDS", 10),
        "auto_challenge_interval_minutes": getattr(settings, "TEE_AUTO_CHALLENGE_INTERVAL_MINUTES", 60),
        "known_peer_records":     len(peer_records),
        "bascg_layer":            "Layer 1 — Silicon / Hardware Root-of-Trust (distributed)",
    }


# ── GET /distributed/peers ─────────────────────────────────────────────────────

@router.get(
    "/distributed/peers",
    summary="List latest attestation record for each known peer node",
)
async def list_peers(db: AsyncSession = Depends(get_db)):
    _check_enabled()
    records = await distributed_tee_service.list_peers(db)
    return [_record_to_dict(r) for r in records]


# ── GET /distributed/peers/{node_id} ──────────────────────────────────────────

@router.get(
    "/distributed/peers/{node_id}",
    summary="Get the latest attestation record for a specific peer node",
)
async def get_peer(node_id: str, db: AsyncSession = Depends(get_db)):
    _check_enabled()
    record = await distributed_tee_service.get_peer_status(db, node_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"No attestation record found for node {node_id!r}",
        )
    return _record_to_dict(record)


# ── POST /distributed/challenge ────────────────────────────────────────────────

@router.post(
    "/distributed/challenge",
    summary="Issue a nonce challenge to a peer TEE node and verify its attestation",
)
async def challenge_peer(body: ChallengeRequest, db: AsyncSession = Depends(get_db)):
    """
    Full challenge-response cycle:
      1. Fetch nonce from peer /challenge endpoint
      2. Ask peer to attest via /distributed/respond
      3. Verify attestation document locally
      4. Persist result to RemoteNodeAttestation

    Requires TEE_DISTRIBUTED_ENABLED=True.
    """
    _check_enabled()
    result = await distributed_tee_service.challenge_peer(
        db       = db,
        node_url = body.node_url,
        node_id  = body.node_id,
    )
    return {
        "node_id":               result.node_id,
        "node_url":              result.node_url,
        "success":               result.success,
        "verified":              result.verified,
        "platform":              result.platform,
        "pcr0":                  result.pcr0,
        "pcr0_match":            result.pcr0_match,
        "clearance_valid_until": _fmt(result.clearance_valid_until),
        "error":                 result.error,
        "skipped":               result.skipped,
    }


# ── POST /distributed/respond ──────────────────────────────────────────────────

@router.post(
    "/distributed/respond",
    summary="Respond to a peer's nonce challenge with this node's TEE attestation document",
)
async def respond_to_challenge(body: RespondRequest):
    """
    Called by a peer node that wants to verify this node's TEE environment.
    Returns our raw attestation document (base64-encoded) for the given nonce.
    """
    if not body.nonce:
        raise HTTPException(status_code=422, detail="nonce is required")
    response = distributed_tee_service.respond_to_challenge(nonce=body.nonce)
    return response


# ── POST /distributed/receive ──────────────────────────────────────────────────

@router.post(
    "/distributed/receive",
    summary="Receive an attestation document pushed by a peer node (passive sync)",
    status_code=201,
)
async def receive_peer_attestation(
    body: ReceiveRequest,
    db:   AsyncSession = Depends(get_db),
):
    """
    Stores a pushed attestation without active cryptographic verification.
    Active verification (nonce challenge) is preferred over passive push.
    """
    _check_enabled()
    record = await distributed_tee_service.receive_peer_attestation(
        db                    = db,
        node_id               = body.node_id,
        node_url              = body.node_url,
        platform              = body.platform,
        pcr0                  = body.pcr0,
        pcr0_match            = body.pcr0_match,
        clearance_valid_until = body.clearance_valid_until,
        raw_document_b64      = body.raw_document_b64,
    )
    return _record_to_dict(record)


# ── POST /distributed/push ─────────────────────────────────────────────────────

@router.post(
    "/distributed/push",
    summary="Push this node's latest verified attestation to a peer",
)
async def push_attestation(body: PushRequest, db: AsyncSession = Depends(get_db)):
    """
    Sends our most recent verified AttestationReport to a peer's /receive endpoint.
    """
    _check_enabled()
    result = await distributed_tee_service.push_local_attestation(
        db       = db,
        peer_url = body.peer_url,
    )
    return {
        "node_url":    result.node_url,
        "sent":        result.sent,
        "status_code": result.status_code,
        "error":       result.error,
        "skipped":     result.skipped,
    }
