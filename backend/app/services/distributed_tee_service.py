"""
BASCG T3-C — Distributed TEE Attestation Service
==================================================

Extends the local TEE attestation (T1-A) to a multi-node ring where every
node challenges its peers and verifies they are running inside genuine TEEs.

Architecture
------------

  Local node (this KavachX instance)
      │
      ├─ challenge_peer(node_url, node_id)
      │       1. GET  <peer>/api/v1/attestation/challenge         → nonce
      │       2. POST <peer>/api/v1/attestation/distributed/respond
      │              {nonce} → {raw_document_b64, platform, …}
      │       3. Verify doc locally with tee_attestation_service.verify_document()
      │       4. Persist RemoteNodeAttestation in local DB
      │
      ├─ respond_to_challenge(nonce)
      │       Generate THIS node's attestation document for the given nonce
      │       (called by the API handler when a peer challenges us)
      │
      ├─ push_local_attestation(db, peer_url)
      │       Push our latest verified AttestationReport to a peer node
      │       (passive sync — peer stores it as a RemoteNodeAttestation)
      │
      └─ get_peer_status(db, node_id)
              Return the latest RemoteNodeAttestation for a peer

Background worker (DistributedTEEWorker)
-----------------------------------------
  Periodically challenges all nodes listed in TEE_PEER_NODES.
  Starts only when TEE_DISTRIBUTED_ENABLED=True and TEE_PEER_NODES is set.

Config
------
  TEE_DISTRIBUTED_ENABLED                — enable API + worker (default False)
  TEE_PEER_NODES                         — comma-sep peer URLs
  TEE_DISTRIBUTED_CHALLENGE_TIMEOUT_SECONDS — HTTP timeout  (default 10)
  TEE_AUTO_CHALLENGE_INTERVAL_MINUTES    — worker cadence  (default 60)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.orm_models import AttestationReport, RemoteNodeAttestation

logger = logging.getLogger("bascg.distributed_tee")


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PeerChallengeResult:
    """Outcome of a single challenge-response cycle with a peer node."""
    node_id:              str
    node_url:             str
    success:              bool
    verified:             bool          # True if TEE document verified
    platform:             Optional[str] = None
    pcr0:                 Optional[str] = None
    pcr0_match:           bool = False
    clearance_valid_until: Optional[datetime] = None
    error:                Optional[str] = None
    skipped:              bool = False   # True when distributed mode disabled


@dataclass
class PushResult:
    """Outcome of pushing local attestation to a peer."""
    node_url:    str
    sent:        bool
    status_code: Optional[int] = None
    error:       Optional[str] = None
    skipped:     bool = False


# ══════════════════════════════════════════════════════════════════════════════
#  DistributedTEEService
# ══════════════════════════════════════════════════════════════════════════════

class DistributedTEEService:
    """
    Cross-node TEE attestation orchestrator.
    Stateless — all persistent state lives in the DB.
    """

    # ── Challenge a peer node ─────────────────────────────────────────────────

    async def challenge_peer(
        self,
        db:       AsyncSession,
        node_url: str,
        node_id:  str,
    ) -> PeerChallengeResult:
        """
        Issue a challenge to a peer node and verify its TEE attestation document.

        Steps:
          1. Fetch a fresh nonce from GET <peer>/api/v1/attestation/challenge
          2. Ask the peer to attest with POST .../distributed/respond
          3. Verify the returned document locally
          4. Persist result to RemoteNodeAttestation

        Returns PeerChallengeResult(skipped=True) when TEE_DISTRIBUTED_ENABLED=False.
        """
        if not bool(getattr(settings, "TEE_DISTRIBUTED_ENABLED", False)):
            return PeerChallengeResult(
                node_id = node_id,
                node_url= node_url,
                success = False,
                verified= False,
                skipped = True,
            )

        timeout = int(getattr(settings, "TEE_DISTRIBUTED_CHALLENGE_TIMEOUT_SECONDS", 10))
        base    = node_url.rstrip("/")

        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout) as client:
                # Step 1: get challenge nonce from peer
                ch_resp = await client.get(f"{base}/api/v1/attestation/challenge")
                if not ch_resp.is_success:
                    raise RuntimeError(
                        f"Challenge endpoint returned HTTP {ch_resp.status_code}"
                    )
                nonce = ch_resp.json().get("nonce", "")
                if not nonce:
                    raise RuntimeError("Peer returned empty nonce")

                # Step 2: ask peer to respond with its attestation document
                at_resp = await client.post(
                    f"{base}/api/v1/attestation/distributed/respond",
                    json={"nonce": nonce},
                )
                if not at_resp.is_success:
                    raise RuntimeError(
                        f"Distributed respond endpoint returned HTTP {at_resp.status_code}: "
                        f"{at_resp.text[:200]}"
                    )
                body = at_resp.json()

        except Exception as exc:
            logger.warning(
                "DistributedTEE: challenge failed node=%s url=%s: %s",
                node_id, node_url, exc,
            )
            result = PeerChallengeResult(
                node_id  = node_id,
                node_url = node_url,
                success  = False,
                verified = False,
                error    = str(exc),
            )
            await self._persist_result(db, result, nonce=None, raw_doc=None)
            return result

        raw_doc_b64 = body.get("raw_document_b64", "")
        platform    = body.get("platform", "mock")

        # Step 3: verify the document locally
        from app.services.tee_attestation_service import tee_attestation_service
        try:
            import base64
            raw_bytes = base64.b64decode(raw_doc_b64)
            attest_result = await tee_attestation_service.verify_document(
                db                 = db,
                raw_document_b64   = raw_doc_b64,
                expected_nonce     = nonce,
                model_id           = None,
                expected_pcr0      = body.get("expected_pcr0"),
            )
        except Exception as exc:
            attest_result = None
            logger.warning("DistributedTEE: verification failed for peer %s: %s", node_id, exc)

        if attest_result and attest_result.verified:
            clearance = attest_result.clearance_valid_until
            result = PeerChallengeResult(
                node_id              = node_id,
                node_url             = node_url,
                success              = True,
                verified             = True,
                platform             = attest_result.platform,
                pcr0                 = attest_result.pcr0,
                pcr0_match           = attest_result.pcr0_match,
                clearance_valid_until= clearance,
            )
        else:
            failure = getattr(attest_result, "failure_reason", "verification failed") if attest_result else "verification error"
            result = PeerChallengeResult(
                node_id  = node_id,
                node_url = node_url,
                success  = False,
                verified = False,
                platform = platform,
                error    = failure,
            )

        await self._persist_result(db, result, nonce=nonce, raw_doc=raw_doc_b64)
        return result

    # ── Respond to a challenge ────────────────────────────────────────────────

    def respond_to_challenge(self, nonce: str) -> Dict[str, Any]:
        """
        Generate THIS node's attestation document for a peer's challenge nonce.

        Returns a dict suitable for JSON response:
          {raw_document_b64, platform, node_id, expected_pcr0}
        """
        from app.services.tee_attestation_service import tee_attestation_service, MOCK_PCR0

        node_id  = getattr(settings, "CONSENSUS_NODE_ID", "local-node")
        mode     = getattr(settings, "TEE_ATTESTATION_MODE", "mock").lower()
        raw_b64  = tee_attestation_service.generate_mock_document(nonce=nonce)

        return {
            "node_id":          node_id,
            "platform":         mode,
            "raw_document_b64": raw_b64,
            "expected_pcr0":    MOCK_PCR0 if mode == "mock" else None,
        }

    # ── Push local attestation to a peer ─────────────────────────────────────

    async def push_local_attestation(
        self,
        db:       AsyncSession,
        peer_url: str,
    ) -> PushResult:
        """
        Push our latest verified AttestationReport to a peer node.

        The peer stores it via POST .../distributed/receive.
        Skipped when TEE_DISTRIBUTED_ENABLED=False or no verified local attestation.
        """
        if not bool(getattr(settings, "TEE_DISTRIBUTED_ENABLED", False)):
            return PushResult(node_url=peer_url, sent=False, skipped=True)

        # Find our latest verified local report
        res = await db.execute(
            select(AttestationReport)
            .where(AttestationReport.verified.is_(True))
            .where(AttestationReport.clearance_valid_until.isnot(None))
            .order_by(AttestationReport.created_at.desc())
            .limit(1)
        )
        report = res.scalars().first()
        if not report:
            return PushResult(
                node_url = peer_url,
                sent     = False,
                error    = "No local verified attestation to push",
            )

        node_id = getattr(settings, "CONSENSUS_NODE_ID", "local-node")
        payload = {
            "node_id":          node_id,
            "platform":         report.platform,
            "raw_document_b64": report.raw_document_b64 or "",
            "pcr0":             report.pcr0,
            "pcr0_match":       report.pcr0_match,
            "clearance_valid_until": (
                report.clearance_valid_until.isoformat()
                if report.clearance_valid_until else None
            ),
        }

        timeout = int(getattr(settings, "TEE_DISTRIBUTED_CHALLENGE_TIMEOUT_SECONDS", 10))
        endpoint = peer_url.rstrip("/") + "/api/v1/attestation/distributed/receive"

        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(endpoint, json=payload)
            if resp.is_success:
                return PushResult(node_url=peer_url, sent=True, status_code=resp.status_code)
            return PushResult(
                node_url    = peer_url,
                sent        = False,
                status_code = resp.status_code,
                error       = f"HTTP {resp.status_code}: {resp.text[:200]}",
            )
        except Exception as exc:
            return PushResult(node_url=peer_url, sent=False, error=str(exc))

    # ── Receive attestation pushed from a peer ────────────────────────────────

    async def receive_peer_attestation(
        self,
        db:       AsyncSession,
        node_id:  str,
        node_url: str,
        platform: str,
        pcr0:     Optional[str],
        pcr0_match: bool,
        clearance_valid_until: Optional[str],
        raw_document_b64: Optional[str] = None,
    ) -> RemoteNodeAttestation:
        """
        Store an attestation pushed by a peer node (passive sync).
        No cryptographic verification is performed here — the peer's report is
        stored as-is.  Active verification (with nonce challenge) is preferred.
        """
        cvu = _parse_dt(clearance_valid_until)
        record = RemoteNodeAttestation(
            node_id              = node_id,
            node_url             = node_url,
            platform             = platform,
            pcr0                 = pcr0,
            pcr0_match           = pcr0_match,
            verified             = False,   # pushed attestations are unverified
            clearance_valid_until= cvu,
            raw_document_b64     = raw_document_b64,
        )
        db.add(record)
        await db.commit()
        await db.refresh(record)
        logger.info(
            "DistributedTEE: received pushed attestation from node=%s platform=%s",
            node_id, platform,
        )
        return record

    # ── Peer status ───────────────────────────────────────────────────────────

    async def get_peer_status(
        self, db: AsyncSession, node_id: str
    ) -> Optional[RemoteNodeAttestation]:
        """Return the most recent attestation record for a peer node."""
        res = await db.execute(
            select(RemoteNodeAttestation)
            .where(RemoteNodeAttestation.node_id == node_id)
            .order_by(RemoteNodeAttestation.attested_at.desc())
            .limit(1)
        )
        return res.scalars().first()

    async def list_peers(
        self, db: AsyncSession
    ) -> List[RemoteNodeAttestation]:
        """Return the latest attestation record for each distinct peer node."""
        # Fetch all records ordered by time desc; deduplicate by node_id in Python
        res = await db.execute(
            select(RemoteNodeAttestation)
            .order_by(RemoteNodeAttestation.attested_at.desc())
        )
        all_records = res.scalars().all()
        seen: set = set()
        latest: List[RemoteNodeAttestation] = []
        for r in all_records:
            if r.node_id not in seen:
                seen.add(r.node_id)
                latest.append(r)
        return latest

    # ── Bulk challenge ────────────────────────────────────────────────────────

    async def challenge_all_peers(
        self, db: AsyncSession
    ) -> List[PeerChallengeResult]:
        """Challenge every node listed in TEE_PEER_NODES."""
        raw = getattr(settings, "TEE_PEER_NODES", "").strip()
        if not raw:
            return []
        peer_urls = [u.strip() for u in raw.split(",") if u.strip()]
        results = []
        for url in peer_urls:
            # Derive a stable node_id from the URL (last path segment or hostname)
            node_id = url.rstrip("/").rsplit("/", 1)[-1] or url
            r = await self.challenge_peer(db, url, node_id)
            results.append(r)
        return results

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _persist_result(
        self,
        db:      AsyncSession,
        result:  PeerChallengeResult,
        nonce:   Optional[str],
        raw_doc: Optional[str],
    ) -> None:
        record = RemoteNodeAttestation(
            node_id              = result.node_id,
            node_url             = result.node_url,
            platform             = result.platform,
            pcr0                 = result.pcr0,
            pcr0_match           = result.pcr0_match,
            verified             = result.verified,
            failure_reason       = result.error,
            clearance_valid_until= result.clearance_valid_until,
            raw_document_b64     = raw_doc,
            nonce                = nonce,
        )
        db.add(record)
        try:
            await db.commit()
        except Exception as exc:
            logger.error("DistributedTEE: failed to persist result: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
#  Background worker
# ══════════════════════════════════════════════════════════════════════════════

class DistributedTEEWorker:
    """
    Periodic background worker that re-challenges all configured peer nodes.

    Lifecycle (mirrors nair_sync_worker / sovereign_ledger_sync pattern):
      start_background_worker() — called from FastAPI lifespan
      stop()                    — called on shutdown
    """

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None

    def start_background_worker(self) -> None:
        if not bool(getattr(settings, "TEE_DISTRIBUTED_ENABLED", False)):
            logger.info(
                "Distributed TEE worker disabled (TEE_DISTRIBUTED_ENABLED=false)"
            )
            return
        peers = getattr(settings, "TEE_PEER_NODES", "").strip()
        if not peers:
            logger.info(
                "Distributed TEE worker disabled: TEE_PEER_NODES not configured"
            )
            return
        if self._task and not self._task.done():
            return
        self._task = asyncio.ensure_future(self._worker_loop())
        logger.info(
            "Distributed TEE worker started — interval=%d min peers=%s",
            getattr(settings, "TEE_AUTO_CHALLENGE_INTERVAL_MINUTES", 60),
            peers,
        )

    def stop(self) -> None:
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("Distributed TEE worker stopped")

    async def _worker_loop(self) -> None:
        interval = int(
            getattr(settings, "TEE_AUTO_CHALLENGE_INTERVAL_MINUTES", 60)
        ) * 60

        while True:
            await asyncio.sleep(interval)
            try:
                from app.db.database import AsyncSessionLocal
                async with AsyncSessionLocal() as db:
                    results = await distributed_tee_service.challenge_all_peers(db)
                    ok      = sum(1 for r in results if r.verified)
                    failed  = sum(1 for r in results if not r.verified and not r.skipped)
                    logger.info(
                        "Distributed TEE cycle: challenged=%d ok=%d failed=%d",
                        len(results), ok, failed,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("Distributed TEE worker error: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


# Module-level singletons
distributed_tee_service = DistributedTEEService()
distributed_tee_worker  = DistributedTEEWorker()
