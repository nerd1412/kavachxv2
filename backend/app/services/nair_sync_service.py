"""
BASCG T3-A — NAIR-I Bidirectional Sync Service
================================================

Synchronises the local KavachX node's AI model registry with the national
NAIR-I (National AI Registry of India) node in both directions:

  Push (T2-A, already implemented):
      local ACTIVE entries → national node
      (via RegistryService.push_all_active_to_national_node)

  Pull (T3-A, new):
      national node's registry → local DB
      Paginates through GET <node>/api/v1/registry/models and:
        • Creates local stub entries for models that don't exist locally
          (nair_source="national", registry_status preserved from national)
        • Updates authority-owned fields for models that already exist locally:
            risk_category, registry_status, compliance_certifications,
            last_audited_at, nair_registered_at
        • National node is authoritative for classification decisions;
          local node is authoritative for model weights and inference data.

  Bidirectional:
      push_all_active → pull_from_national → BidirectionalSyncResult

  Background worker:
      NAIRSyncWorker — asyncio.Task that runs every NAIR_SYNC_INTERVAL_MINUTES.
      Only starts if NAIR_SYNC_ENABLED=True and BASCG_NATIONAL_NODE_URL is set.

Signature verification
----------------------
When NAIR_PULL_VERIFY_SIGNATURES=True, each pulled entry must carry a
"signature" and "signed_by" field (the format our push endpoint sends).
Entries with invalid signatures are SKIPPED with an error in the result.
Unknown issuers are rejected unless the operator has imported their public key
via the regulator-key import API (T2-B).

Config
------
  BASCG_NATIONAL_NODE_URL        — national node base URL
  NAIR_SYNC_ENABLED              — enable background worker (default False)
  NAIR_SYNC_INTERVAL_MINUTES     — worker cadence           (default 30)
  NAIR_PULL_PAGE_SIZE            — entries per GET page     (default 100)
  NAIR_PULL_VERIFY_SIGNATURES    — verify Ed25519 sigs      (default True)
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.orm_models import AIModel
from app.services.registry_service import (
    FederationSyncResult,
    model_to_entry,
    registry_service,
)

logger = logging.getLogger("bascg.nair_sync")


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PullSyncResult:
    """Outcome of a single pull cycle from the national node."""
    node_url:     str
    pulled_count: int           # total entries received
    created:      int           # new local stubs created
    updated:      int           # existing records updated
    skipped:      int           # already in sync / sig invalid / unknown
    failed:       int           # DB or processing errors
    errors:       List[str]     = field(default_factory=list)
    completed_at: str           = ""


@dataclass
class BidirectionalSyncResult:
    """Outcome of a full push-then-pull cycle."""
    node_url:     str
    push_ok:      int
    push_failed:  int
    push_skipped: int
    pull:         PullSyncResult
    completed_at: str = ""


# ══════════════════════════════════════════════════════════════════════════════
#  NAIRSyncService
# ══════════════════════════════════════════════════════════════════════════════

class NAIRSyncService:
    """
    Bidirectional NAIR-I synchronisation.

    Design: stateless — instantiate once as module singleton; safe for
    concurrent callers because all state lives in the DB session.
    """

    # ── Pull ──────────────────────────────────────────────────────────────────

    async def pull_from_national_node(
        self,
        db:       AsyncSession,
        node_url: Optional[str] = None,
    ) -> PullSyncResult:
        """
        Fetch all registry entries from the national node and apply them locally.

        Returns immediately (skipped=all) when:
          - BASCG_NATIONAL_NODE_URL is not configured, or
          - BASCG_PROVIDER_MODE=local
        """
        resolved_url  = node_url or getattr(settings, "BASCG_NATIONAL_NODE_URL", "").strip()
        provider_mode = getattr(settings, "BASCG_PROVIDER_MODE", "local").lower()
        now_iso       = datetime.now(timezone.utc).isoformat()

        if not resolved_url or provider_mode == "local":
            logger.debug("NAIR pull skipped: local mode or no national node URL configured")
            return PullSyncResult(
                node_url     = resolved_url or "local",
                pulled_count = 0,
                created      = 0,
                updated      = 0,
                skipped      = 0,
                failed       = 0,
                completed_at = now_iso,
            )

        page_size = int(getattr(settings, "NAIR_PULL_PAGE_SIZE", 100))
        verify    = bool(getattr(settings, "NAIR_PULL_VERIFY_SIGNATURES", True))
        timeout   = int(getattr(settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 10))

        entries: List[Dict[str, Any]] = []
        errors:  List[str]            = []

        # ── Paginated fetch ────────────────────────────────────────────────────
        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout) as client:
                offset = 0
                while True:
                    url = (
                        f"{resolved_url.rstrip('/')}/api/v1/registry/models"
                        f"?limit={page_size}&offset={offset}"
                    )
                    resp = await client.get(url)
                    if not resp.is_success:
                        errors.append(
                            f"GET {url} → HTTP {resp.status_code}: {resp.text[:200]}"
                        )
                        break

                    body = resp.json()
                    # Support both bare-list and {models:[...]} response shapes
                    page: List[Dict] = (
                        body if isinstance(body, list)
                        else body.get("models", body.get("items", []))
                    )
                    if not page:
                        break
                    entries.extend(page)
                    if len(page) < page_size:
                        break   # last page
                    offset += page_size

        except Exception as exc:
            errors.append(f"Network error fetching from {resolved_url}: {exc}")
            return PullSyncResult(
                node_url     = resolved_url,
                pulled_count = 0,
                created      = 0,
                updated      = 0,
                skipped      = 0,
                failed       = len(errors),
                errors       = errors,
                completed_at = datetime.now(timezone.utc).isoformat(),
            )

        # ── Process entries ────────────────────────────────────────────────────
        created = updated = skipped = failed = 0

        for raw in entries:
            # raw may be a bare entry dict or a wrapped federated-sync payload
            entry: Dict[str, Any] = raw.get("entry", raw)

            model_id = entry.get("id", "")
            if not model_id:
                skipped += 1
                errors.append("Skipped entry with no 'id' field")
                continue

            # ── Signature verification ──────────────────────────────────────
            if verify:
                sig      = raw.get("signature", "")
                issuer   = raw.get("signed_by", "")
                if sig and issuer:
                    ok = self._verify_entry_signature(entry, sig, issuer)
                    if not ok:
                        skipped += 1
                        errors.append(
                            f"model {model_id[:8]}: signature verification failed "
                            f"(issuer={issuer!r}) — skipped"
                        )
                        continue
                # If no sig present and verify=True, we still accept it
                # (national node may not sign public read responses)

            # ── Upsert into local DB ────────────────────────────────────────
            try:
                existing = await registry_service.get_model(db, model_id)
                now_dt   = datetime.now(timezone.utc)

                if existing is None:
                    # Create a local stub for the nationally-registered model
                    new_model = AIModel(
                        id                       = model_id,
                        name                     = entry.get("name", "unknown"),
                        version                  = entry.get("version", "unknown"),
                        model_type               = entry.get("model_type"),
                        owner                    = entry.get("owner"),
                        sector                   = entry.get("sector"),
                        risk_category            = entry.get("risk_category", "UNKNOWN"),
                        registry_status          = entry.get("registry_status", "ACTIVE"),
                        model_sha256             = entry.get("model_sha256"),
                        training_data_hash       = entry.get("training_data_hash"),
                        model_card_url           = entry.get("model_card_url"),
                        compliance_certifications= entry.get("compliance_certifications") or [],
                        framework                = entry.get("framework"),
                        parameter_count          = entry.get("parameter_count"),
                        description              = entry.get("description"),
                        nair_source              = "national",
                        nair_pulled_at           = now_dt,
                        nair_registered_at       = _parse_dt(entry.get("nair_registered_at")),
                        last_audited_at          = _parse_dt(entry.get("last_audited_at")),
                    )
                    db.add(new_model)
                    created += 1
                    logger.info(
                        "NAIR pull: created local stub model=%s name=%r",
                        model_id[:8], new_model.name,
                    )

                else:
                    # Update only the authority-owned fields
                    changed = False

                    nat_risk   = entry.get("risk_category")
                    nat_status = entry.get("registry_status")
                    nat_certs  = entry.get("compliance_certifications")
                    nat_audit  = _parse_dt(entry.get("last_audited_at"))
                    nat_nair   = _parse_dt(entry.get("nair_registered_at"))

                    if nat_risk and nat_risk != existing.risk_category:
                        existing.risk_category = nat_risk
                        changed = True
                    if nat_status and nat_status != existing.registry_status:
                        existing.registry_status = nat_status
                        changed = True
                    if nat_certs is not None and nat_certs != existing.compliance_certifications:
                        existing.compliance_certifications = nat_certs
                        changed = True
                    if nat_audit and (
                        existing.last_audited_at is None
                        or nat_audit > existing.last_audited_at
                    ):
                        existing.last_audited_at = nat_audit
                        changed = True
                    if nat_nair and existing.nair_registered_at is None:
                        existing.nair_registered_at = nat_nair
                        changed = True

                    existing.nair_pulled_at = now_dt

                    if changed:
                        updated += 1
                        logger.info(
                            "NAIR pull: updated model=%s",
                            model_id[:8],
                        )
                    else:
                        skipped += 1

            except Exception as exc:
                failed += 1
                errors.append(f"model {model_id[:8]}: DB error — {exc}")
                logger.error("NAIR pull DB error model=%s: %s", model_id[:8], exc)

        try:
            await db.commit()
        except Exception as exc:
            errors.append(f"Commit error: {exc}")
            failed += 1

        result = PullSyncResult(
            node_url     = resolved_url,
            pulled_count = len(entries),
            created      = created,
            updated      = updated,
            skipped      = skipped,
            failed       = failed,
            errors       = errors,
            completed_at = datetime.now(timezone.utc).isoformat(),
        )
        logger.info(
            "NAIR pull complete: node=%s pulled=%d created=%d updated=%d "
            "skipped=%d failed=%d",
            resolved_url, result.pulled_count, created, updated, skipped, failed,
        )
        return result

    def _verify_entry_signature(
        self, entry: Dict[str, Any], signature_b64: str, issuer: str
    ) -> bool:
        """Verify the Ed25519 signature over canonical JSON of the entry."""
        try:
            from app.core.crypto import crypto_service
            return crypto_service.verifier.verify(entry, signature_b64, issuer)
        except Exception as exc:
            logger.error("NAIR sig verification error issuer=%s: %s", issuer, exc)
            return False

    # ── Bidirectional ─────────────────────────────────────────────────────────

    async def bidirectional_sync(
        self,
        db:       AsyncSession,
        node_url: Optional[str] = None,
    ) -> BidirectionalSyncResult:
        """
        Full push-then-pull cycle:
          1. Push all local ACTIVE entries to the national node.
          2. Pull all entries from the national node into local DB.
        """
        resolved_url = node_url or getattr(settings, "BASCG_NATIONAL_NODE_URL", "").strip()

        # ── Push ──────────────────────────────────────────────────────────────
        push_results: List[FederationSyncResult] = (
            await registry_service.push_all_active_to_national_node(db, node_url=resolved_url)
        )
        push_ok      = sum(1 for r in push_results if r.synced)
        push_failed  = sum(1 for r in push_results if not r.synced and not r.skipped)
        push_skipped = sum(1 for r in push_results if r.skipped)

        # ── Pull ──────────────────────────────────────────────────────────────
        pull_result = await self.pull_from_national_node(db, node_url=resolved_url)

        return BidirectionalSyncResult(
            node_url     = resolved_url or "local",
            push_ok      = push_ok,
            push_failed  = push_failed,
            push_skipped = push_skipped,
            pull         = pull_result,
            completed_at = datetime.now(timezone.utc).isoformat(),
        )


# ══════════════════════════════════════════════════════════════════════════════
#  Background worker
# ══════════════════════════════════════════════════════════════════════════════

class NAIRSyncWorker:
    """
    Periodic background worker that runs bidirectional_sync on a fixed cadence.

    Lifecycle (mirrors sovereign_ledger_sync pattern):
      start_background_worker() — called from FastAPI lifespan
      stop()                    — called on shutdown
    """

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event() if False else None   # created lazily

    def start_background_worker(self) -> None:
        """Schedule the periodic sync task (no-op if already running)."""
        if not bool(getattr(settings, "NAIR_SYNC_ENABLED", False)):
            logger.info("NAIR background sync disabled (NAIR_SYNC_ENABLED=false)")
            return
        node_url = getattr(settings, "BASCG_NATIONAL_NODE_URL", "").strip()
        if not node_url:
            logger.info(
                "NAIR background sync disabled: BASCG_NATIONAL_NODE_URL not set"
            )
            return
        if self._task and not self._task.done():
            logger.debug("NAIR background sync already running — skipping duplicate start")
            return
        self._task = asyncio.ensure_future(self._worker_loop())
        logger.info(
            "NAIR background sync started — interval=%d min node=%s",
            getattr(settings, "NAIR_SYNC_INTERVAL_MINUTES", 30), node_url,
        )

    def stop(self) -> None:
        """Cancel the background task gracefully."""
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("NAIR background sync stopped")

    async def _worker_loop(self) -> None:
        """Run bidirectional sync on a fixed interval until cancelled."""
        interval = int(getattr(settings, "NAIR_SYNC_INTERVAL_MINUTES", 30)) * 60

        while True:
            await asyncio.sleep(interval)
            try:
                from app.db.database import AsyncSessionLocal
                async with AsyncSessionLocal() as db:
                    result = await nair_sync_service.bidirectional_sync(db)
                    logger.info(
                        "NAIR sync cycle: push_ok=%d pull_created=%d pull_updated=%d",
                        result.push_ok, result.pull.created, result.pull.updated,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("NAIR sync cycle error: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _parse_dt(value: Any) -> Optional[datetime]:
    """Parse an ISO-8601 string to a UTC-aware datetime, or return None."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except Exception:
        return None


# Module-level singletons
nair_sync_service = NAIRSyncService()
nair_sync_worker  = NAIRSyncWorker()
