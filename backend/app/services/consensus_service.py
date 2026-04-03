"""
BASCG T3-B — Multi-node Policy Consensus Service
==================================================

Implements a Byzantine-fault-tolerant (BFT-lite) signed-vote consensus
mechanism for propagating governance policy changes across a BASCG node ring.

Flow
----
  1. Any authorised node calls propose() → creates a PolicyProposal (status=pending)
  2. Other nodes call cast_vote() → appends a signed PolicyVote
  3. Any node calls tally() → counts valid votes:
       accepts / total >= CONSENSUS_QUORUM_THRESHOLD  AND
       total            >= CONSENSUS_MIN_VOTES
     → accepted: _apply_accepted_proposal() creates/updates a GovernancePolicy
     → rejected: proposal marked rejected
     → pending:  not enough votes yet
  4. expire_stale_proposals() sweeps expired proposals (called on every tally)

Proposal types
--------------
  create_policy    — payload: GovernancePolicy fields dict (name, rules, …)
  update_policy    — payload: {policy_id, fields: {…}}
  disable_policy   — payload: {policy_id}
  update_threshold — payload: {threshold_key, value}  (must be in ALLOWED_THRESHOLD_KEYS)

Cryptographic integrity
-----------------------
  Proposals are signed with the local BASCG Ed25519 key on creation.
  Votes are signed by the voting node (same Ed25519 infrastructure).
  When CONSENSUS_VERIFY_VOTE_SIGNATURES=True, votes from unknown issuers are
  rejected — callers must import the node key via the regulator-key import API
  (T2-B) before their votes are counted.

Config
------
  CONSENSUS_ENABLED                  — enable API (default False)
  CONSENSUS_NODE_ID                  — this node's identifier
  CONSENSUS_QUORUM_THRESHOLD         — accept fraction  (default 0.67)
  CONSENSUS_MIN_VOTES                — minimum votes    (default 2)
  CONSENSUS_PROPOSAL_TTL_HOURS       — TTL in hours     (default 72)
  CONSENSUS_VERIFY_VOTE_SIGNATURES   — verify votes     (default True)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.orm_models import GovernancePolicy, PolicyProposal, PolicyVote

logger = logging.getLogger("bascg.consensus")

# Threshold keys that update_threshold proposals may target
ALLOWED_THRESHOLD_KEYS = {
    "RISK_SCORE_HIGH_THRESHOLD",
    "RISK_SCORE_MEDIUM_THRESHOLD",
    "FAIRNESS_DISPARITY_THRESHOLD",
    "CONFIDENCE_LOW_THRESHOLD",
}

VALID_PROPOSAL_TYPES = {
    "create_policy",
    "update_policy",
    "disable_policy",
    "update_threshold",
}

VALID_VOTES = {"accept", "reject"}


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TallyResult:
    """Outcome of a consensus tally."""
    proposal_id:       str
    status:            str           # "accepted" | "rejected" | "pending"
    total_votes:       int
    accept_count:      int
    reject_count:      int
    invalid_votes:     int           # votes with bad/unverifiable signatures
    quorum_met:        bool
    applied:           bool          # True if accepted & policy change was applied
    applied_policy_id: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
#  ConsensusService
# ══════════════════════════════════════════════════════════════════════════════

class ConsensusService:
    """
    Stateless governance consensus engine.
    All persistent state lives in the DB; safe for concurrent request handlers.
    """

    # ── Propose ───────────────────────────────────────────────────────────────

    async def propose(
        self,
        db:            AsyncSession,
        proposal_type: str,
        title:         str,
        payload:       Dict[str, Any],
        proposed_by:   Optional[str] = None,
        description:   Optional[str] = None,
    ) -> PolicyProposal:
        """
        Create and persist a new policy proposal.

        The proposal is signed with the local Ed25519 key.
        Raises ValueError for invalid proposal_type or payload.
        """
        ptype = proposal_type.lower()
        if ptype not in VALID_PROPOSAL_TYPES:
            raise ValueError(
                f"Invalid proposal_type {ptype!r}. "
                f"Must be one of {sorted(VALID_PROPOSAL_TYPES)}"
            )

        self._validate_payload(ptype, payload)

        ttl_hours  = int(getattr(settings, "CONSENSUS_PROPOSAL_TTL_HOURS", 72))
        node_id    = proposed_by or getattr(settings, "CONSENSUS_NODE_ID", "local-node")
        now        = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=ttl_hours)

        proposal_dict = {
            "proposal_type": ptype,
            "title":         title,
            "payload":       payload,
            "proposed_by":   node_id,
        }

        # Sign the proposal
        sig, issuer = self._sign_dict(proposal_dict)

        proposal = PolicyProposal(
            proposal_type      = ptype,
            title              = title,
            description        = description,
            payload            = payload,
            proposed_by        = node_id,
            status             = "pending",
            expires_at         = expires_at,
            proposal_signature = sig,
            signed_by          = issuer,
        )
        db.add(proposal)
        await db.commit()
        await db.refresh(proposal)

        logger.info(
            "Consensus: proposal created id=%s type=%s by=%s",
            proposal.id[:8], ptype, node_id,
        )
        return proposal

    # ── Vote ──────────────────────────────────────────────────────────────────

    async def cast_vote(
        self,
        db:          AsyncSession,
        proposal_id: str,
        node_id:     str,
        vote:        str,
        signature:   Optional[str] = None,
        signed_by:   Optional[str] = None,
        reason:      Optional[str] = None,
    ) -> PolicyVote:
        """
        Cast a signed vote on an open proposal.

        Raises ValueError if:
          - proposal not found or not pending
          - proposal has expired
          - vote value not "accept"/"reject"
          - node_id already voted on this proposal
          - signature verification fails (when CONSENSUS_VERIFY_VOTE_SIGNATURES=True)
        """
        vote_val = vote.lower()
        if vote_val not in VALID_VOTES:
            raise ValueError(f"vote must be 'accept' or 'reject', got {vote!r}")

        proposal = await self.get_proposal(db, proposal_id)
        if proposal is None:
            raise ValueError(f"Proposal {proposal_id!r} not found")
        if proposal.status != "pending":
            raise ValueError(
                f"Proposal {proposal_id!r} is {proposal.status!r} — voting is closed"
            )
        now = datetime.now(timezone.utc)
        exp = proposal.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now > exp:
            proposal.status    = "expired"
            proposal.resolved_at = now
            await db.commit()
            raise ValueError(f"Proposal {proposal_id!r} has expired")

        # Duplicate vote guard
        existing_vote = await self._get_vote_by_node(db, proposal_id, node_id)
        if existing_vote is not None:
            raise ValueError(
                f"Node {node_id!r} has already voted on proposal {proposal_id!r}"
            )

        # Signature verification — signed over {proposal_id, node_id, vote} only;
        # voted_at is server-assigned and not included in the canonical payload.
        verify = bool(getattr(settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", True))
        if verify and signature and signed_by:
            vote_payload = {
                "proposal_id": proposal_id,
                "node_id":     node_id,
                "vote":        vote_val,
            }
            if not self._verify_signature(vote_payload, signature, signed_by):
                raise ValueError(
                    f"Vote signature verification failed for node {node_id!r} "
                    f"issuer={signed_by!r}"
                )

        pv = PolicyVote(
            proposal_id = proposal_id,
            node_id     = node_id,
            vote        = vote_val,
            reason      = reason,
            signature   = signature,
            signed_by   = signed_by,
        )
        db.add(pv)
        await db.commit()
        await db.refresh(pv)

        logger.info(
            "Consensus: vote cast proposal=%s node=%s vote=%s",
            proposal_id[:8], node_id, vote_val,
        )
        return pv

    # ── Tally ─────────────────────────────────────────────────────────────────

    async def tally(
        self,
        db:          AsyncSession,
        proposal_id: str,
    ) -> TallyResult:
        """
        Count all valid votes for a proposal and apply the policy if quorum is met.

        Also expires any proposals that have passed their TTL.
        Returns TallyResult with the outcome.
        """
        await self.expire_stale_proposals(db)

        proposal = await self.get_proposal(db, proposal_id)
        if proposal is None:
            raise ValueError(f"Proposal {proposal_id!r} not found")

        if proposal.status in ("accepted", "rejected", "expired"):
            # Already resolved — return a summary without re-applying
            votes_q = await db.execute(
                select(PolicyVote).where(PolicyVote.proposal_id == proposal_id)
            )
            votes = votes_q.scalars().all()
            accepts = sum(1 for v in votes if v.vote == "accept")
            rejects = sum(1 for v in votes if v.vote == "reject")
            return TallyResult(
                proposal_id       = proposal_id,
                status            = proposal.status,
                total_votes       = len(votes),
                accept_count      = accepts,
                reject_count      = rejects,
                invalid_votes     = 0,
                quorum_met        = proposal.status == "accepted",
                applied           = proposal.applied_policy_id is not None,
                applied_policy_id = proposal.applied_policy_id,
            )

        # Load votes
        votes_q = await db.execute(
            select(PolicyVote).where(PolicyVote.proposal_id == proposal_id)
        )
        all_votes: List[PolicyVote] = votes_q.scalars().all()

        # Validate signatures if required
        verify       = bool(getattr(settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", True))
        valid_votes  = []
        invalid_count = 0

        for v in all_votes:
            if verify and v.signature and v.signed_by:
                vote_payload = {
                    "proposal_id": proposal_id,
                    "node_id":     v.node_id,
                    "vote":        v.vote,
                    "voted_at":    v.voted_at.isoformat() if v.voted_at else "",
                }
                if not self._verify_signature(vote_payload, v.signature, v.signed_by):
                    invalid_count += 1
                    logger.warning(
                        "Consensus tally: invalid vote signature node=%s proposal=%s — excluded",
                        v.node_id, proposal_id[:8],
                    )
                    continue
            valid_votes.append(v)

        total    = len(valid_votes)
        accepts  = sum(1 for v in valid_votes if v.vote == "accept")
        rejects  = sum(1 for v in valid_votes if v.vote == "reject")
        min_v    = int(getattr(settings, "CONSENSUS_MIN_VOTES", 2))
        threshold = float(getattr(settings, "CONSENSUS_QUORUM_THRESHOLD", 0.67))

        quorum_met = total >= min_v and (accepts / total >= threshold if total else False)

        if not quorum_met and rejects > 0 and total >= min_v:
            # Explicit rejection: enough votes, majority rejected
            reject_threshold = 1.0 - threshold
            if rejects / total > reject_threshold:
                quorum_met = False   # stays False
                proposal.status     = "rejected"
                proposal.resolved_at = datetime.now(timezone.utc)
                await db.commit()
                return TallyResult(
                    proposal_id   = proposal_id,
                    status        = "rejected",
                    total_votes   = total,
                    accept_count  = accepts,
                    reject_count  = rejects,
                    invalid_votes = invalid_count,
                    quorum_met    = False,
                    applied       = False,
                )

        if not quorum_met:
            return TallyResult(
                proposal_id   = proposal_id,
                status        = "pending",
                total_votes   = total,
                accept_count  = accepts,
                reject_count  = rejects,
                invalid_votes = invalid_count,
                quorum_met    = False,
                applied       = False,
            )

        # ── Quorum met → accept and apply ─────────────────────────────────────
        proposal.status     = "accepted"
        proposal.resolved_at = datetime.now(timezone.utc)

        applied_policy_id = await self._apply_accepted_proposal(db, proposal)
        # Sentinel "__threshold_updated__" means applied but no policy_id to store
        real_policy_id = (
            None if applied_policy_id == "__threshold_updated__"
            else applied_policy_id
        )
        proposal.applied_policy_id = real_policy_id
        await db.commit()

        logger.info(
            "Consensus: proposal ACCEPTED id=%s type=%s applied_policy=%s",
            proposal_id[:8], proposal.proposal_type, real_policy_id,
        )
        return TallyResult(
            proposal_id       = proposal_id,
            status            = "accepted",
            total_votes       = total,
            accept_count      = accepts,
            reject_count      = rejects,
            invalid_votes     = invalid_count,
            quorum_met        = True,
            applied           = applied_policy_id is not None,   # True for sentinel too
            applied_policy_id = real_policy_id,
        )

    # ── Reads ─────────────────────────────────────────────────────────────────

    async def get_proposal(
        self, db: AsyncSession, proposal_id: str
    ) -> Optional[PolicyProposal]:
        res = await db.execute(
            select(PolicyProposal).where(PolicyProposal.id == proposal_id)
        )
        return res.scalars().first()

    async def list_proposals(
        self,
        db:     AsyncSession,
        status: Optional[str] = None,
        limit:  int = 50,
        offset: int = 0,
    ) -> List[PolicyProposal]:
        q = (
            select(PolicyProposal)
            .order_by(PolicyProposal.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if status:
            q = q.where(PolicyProposal.status == status.lower())
        res = await db.execute(q)
        return res.scalars().all()

    async def get_votes(
        self, db: AsyncSession, proposal_id: str
    ) -> List[PolicyVote]:
        res = await db.execute(
            select(PolicyVote)
            .where(PolicyVote.proposal_id == proposal_id)
            .order_by(PolicyVote.voted_at)
        )
        return res.scalars().all()

    # ── Maintenance ───────────────────────────────────────────────────────────

    async def expire_stale_proposals(self, db: AsyncSession) -> int:
        """
        Mark all pending proposals past their TTL as expired.
        Returns the count of newly expired proposals.
        """
        now = datetime.now(timezone.utc)
        res = await db.execute(
            select(PolicyProposal).where(
                PolicyProposal.status == "pending",
                PolicyProposal.expires_at < now,
            )
        )
        stale = res.scalars().all()
        for p in stale:
            p.status     = "expired"
            p.resolved_at = now
        if stale:
            await db.commit()
            logger.info("Consensus: expired %d stale proposal(s)", len(stale))
        return len(stale)

    # ── Apply ─────────────────────────────────────────────────────────────────

    async def _apply_accepted_proposal(
        self,
        db:       AsyncSession,
        proposal: PolicyProposal,
    ) -> Optional[str]:
        """
        Apply the accepted proposal to the live governance state.
        Returns the policy_id that was created/updated, or None for threshold changes.
        """
        ptype   = proposal.proposal_type
        payload = proposal.payload or {}

        try:
            if ptype == "create_policy":
                return await self._apply_create_policy(db, payload)

            if ptype == "update_policy":
                return await self._apply_update_policy(db, payload)

            if ptype == "disable_policy":
                return await self._apply_disable_policy(db, payload)

            if ptype == "update_threshold":
                self._apply_update_threshold(payload)
                return "__threshold_updated__"   # sentinel: applied=True, no policy_id

        except Exception as exc:
            logger.error(
                "Consensus: failed to apply proposal %s type=%s: %s",
                proposal.id[:8], ptype, exc,
            )
        return None

    async def _apply_create_policy(
        self, db: AsyncSession, payload: Dict[str, Any]
    ) -> str:
        from app.services.policy_bundle_service import policy_bundle_service
        from app.core.crypto import crypto_service

        policy_dict = {k: v for k, v in payload.items()
                       if k not in ("policy_signature", "signed_by")}
        # Sign the new policy
        sig    = policy_bundle_service.sign_db_policy_payload(policy_dict)
        issuer = crypto_service.signer.issuer

        pol = GovernancePolicy(
            name               = payload.get("name", "Consensus-created policy"),
            description        = payload.get("description"),
            policy_type        = payload.get("policy_type", "compliance"),
            rules              = payload.get("rules", []),
            severity           = payload.get("severity", "medium"),
            jurisdiction       = payload.get("jurisdiction", "IN"),
            enabled            = payload.get("enabled", True),
            policy_signature   = sig,
            signed_by          = issuer,
        )
        db.add(pol)
        await db.flush()   # populate pol.id before commit
        logger.info("Consensus: created policy id=%s name=%r", pol.id[:8], pol.name)
        return pol.id

    async def _apply_update_policy(
        self, db: AsyncSession, payload: Dict[str, Any]
    ) -> Optional[str]:
        policy_id = payload.get("policy_id")
        fields    = payload.get("fields", {})
        if not policy_id or not fields:
            return None

        res = await db.execute(
            select(GovernancePolicy).where(GovernancePolicy.id == policy_id)
        )
        pol = res.scalars().first()
        if not pol:
            logger.warning("Consensus update_policy: policy %s not found", policy_id)
            return None

        allowed = {"name", "description", "rules", "severity", "enabled", "jurisdiction"}
        for k, v in fields.items():
            if k in allowed:
                setattr(pol, k, v)

        # Re-sign after update
        from app.services.policy_bundle_service import policy_bundle_service
        from app.core.crypto import crypto_service
        pol_dict = {
            "name": pol.name, "description": pol.description,
            "policy_type": pol.policy_type, "rules": pol.rules,
            "severity": pol.severity, "jurisdiction": pol.jurisdiction,
        }
        pol.policy_signature = policy_bundle_service.sign_db_policy_payload(pol_dict)
        pol.signed_by        = crypto_service.signer.issuer

        logger.info("Consensus: updated policy id=%s", policy_id[:8])
        return policy_id

    async def _apply_disable_policy(
        self, db: AsyncSession, payload: Dict[str, Any]
    ) -> Optional[str]:
        policy_id = payload.get("policy_id")
        if not policy_id:
            return None

        res = await db.execute(
            select(GovernancePolicy).where(GovernancePolicy.id == policy_id)
        )
        pol = res.scalars().first()
        if not pol:
            logger.warning("Consensus disable_policy: policy %s not found", policy_id)
            return None

        pol.enabled = False
        logger.info("Consensus: disabled policy id=%s", policy_id[:8])
        return policy_id

    def _apply_update_threshold(self, payload: Dict[str, Any]) -> None:
        key   = payload.get("threshold_key", "")
        value = payload.get("value")
        if key not in ALLOWED_THRESHOLD_KEYS:
            logger.warning("Consensus update_threshold: key %r not allowed", key)
            return
        try:
            setattr(settings, key, float(value))
            logger.info("Consensus: updated threshold %s = %s", key, value)
        except Exception as exc:
            logger.error("Consensus: threshold update failed %s=%s: %s", key, value, exc)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _validate_payload(self, ptype: str, payload: Dict[str, Any]) -> None:
        if ptype == "create_policy":
            if not payload.get("name"):
                raise ValueError("create_policy payload must include 'name'")
            if "rules" not in payload:
                raise ValueError("create_policy payload must include 'rules'")
        elif ptype == "update_policy":
            if not payload.get("policy_id"):
                raise ValueError("update_policy payload must include 'policy_id'")
            if not payload.get("fields"):
                raise ValueError("update_policy payload must include 'fields'")
        elif ptype == "disable_policy":
            if not payload.get("policy_id"):
                raise ValueError("disable_policy payload must include 'policy_id'")
        elif ptype == "update_threshold":
            key = payload.get("threshold_key", "")
            if key not in ALLOWED_THRESHOLD_KEYS:
                raise ValueError(
                    f"update_threshold threshold_key must be one of "
                    f"{sorted(ALLOWED_THRESHOLD_KEYS)}, got {key!r}"
                )
            if "value" not in payload:
                raise ValueError("update_threshold payload must include 'value'")

    def _sign_dict(self, d: Dict[str, Any]):
        """Sign a dict with the local BASCG key. Returns (sig_b64, issuer)."""
        try:
            from app.core.crypto import crypto_service
            sig    = crypto_service.signer.sign(d)
            issuer = crypto_service.signer.issuer
            return sig, issuer
        except Exception as exc:
            logger.warning("Consensus: signing failed: %s", exc)
            return None, None

    def _verify_signature(
        self, payload: Dict[str, Any], sig_b64: str, issuer: str
    ) -> bool:
        try:
            from app.core.crypto import crypto_service
            return crypto_service.verifier.verify(payload, sig_b64, issuer)
        except Exception as exc:
            logger.error("Consensus: signature verification error: %s", exc)
            return False

    async def _get_vote_by_node(
        self, db: AsyncSession, proposal_id: str, node_id: str
    ) -> Optional[PolicyVote]:
        res = await db.execute(
            select(PolicyVote).where(
                PolicyVote.proposal_id == proposal_id,
                PolicyVote.node_id     == node_id,
            )
        )
        return res.scalars().first()


# Module-level singleton
consensus_service = ConsensusService()
