"""
BASCG Registry Service — NAIR-I Business Logic + Federation Layer
==================================================================

Separates pure business logic from the HTTP layer in api/registry.py.

Responsibilities
----------------
  1. Core CRUD operations on AIModel (the NAIR-I registry):
       get_model, list_models, get_stats,
       submit_model_hash, update_risk_category,
       update_registry_status, patch_metadata

  2. Federation:
       sync_to_national_node(db, model_id, node_url=None)
         → Signs the registry entry with the local BASCG Ed25519 key and
           POSTs it to the national node endpoint.
         → In local/dev mode (BASCG_NATIONAL_NODE_URL empty or
           BASCG_PROVIDER_MODE=local): returns a stub result without making
           any network call.

       push_all_active_to_national_node(db, node_url=None)
         → Convenience batch wrapper.

Federation payload format (POST to <node>/api/v1/registry/federated-sync):
  {
    "entry":           { ...full registry entry dict... },
    "signed_by":       "<issuer string>",
    "signature":       "<base64 Ed25519 signature over canonical JSON of entry>",
    "sync_timestamp":  "<ISO-8601 UTC>",
    "source_node":     "<BASCG_NATIONAL_NODE_URL of sending node, or 'local'>",
  }

The receiving node can verify the signature against the sender's public key
(registered in its BASCG_TRUSTED_PUBLIC_KEYS_JSON) to prevent spoofed syncs.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.orm_models import AIModel

logger = logging.getLogger("kavachx.registry")

VALID_RISK   = {"LOW", "MEDIUM", "HIGH", "PROHIBITED", "UNKNOWN"}
VALID_STATUS = {"PENDING", "ACTIVE", "SUSPENDED", "DEREGISTERED"}


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FederationSyncResult:
    model_id:    str
    node_url:    str
    synced:      bool
    status_code: Optional[int]  = None
    signed_by:   str            = "local"
    error:       Optional[str]  = None
    skipped:     bool           = False   # True when federation is disabled locally


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _fmt(dt) -> Optional[str]:
    if not dt:
        return None
    s = dt.isoformat()
    return s.replace("+00:00", "Z") if "+" in s else s + "Z"


def model_to_entry(m: AIModel, full: bool = False) -> Dict[str, Any]:
    """Serialise an AIModel ORM row to a registry-entry dict."""
    entry: Dict[str, Any] = {
        "id":               m.id,
        "name":             m.name,
        "version":          m.version,
        "model_type":       m.model_type,
        "owner":            m.owner,
        "sector":           m.sector,
        "risk_category":    m.risk_category,
        "registry_status":  m.registry_status,
        "model_sha256":     m.model_sha256,
        "registered_at":    _fmt(m.registered_at),
        "nair_registered_at": _fmt(m.nair_registered_at),
        "last_audited_at":  _fmt(m.last_audited_at),
    }
    if full:
        entry.update({
            "description":               m.description,
            "training_data_hash":        m.training_data_hash,
            "model_card_url":            m.model_card_url,
            "compliance_certifications": m.compliance_certifications,
            "framework":                 m.framework,
            "parameter_count":           m.parameter_count,
            "status":                    m.status,
        })
    return entry


# ══════════════════════════════════════════════════════════════════════════════
#  RegistryService
# ══════════════════════════════════════════════════════════════════════════════

class RegistryService:
    """
    NAIR-I registry business logic and national federation sync.

    Design: stateless — safe to call from multiple concurrent request handlers.
    """

    # ── Core reads ────────────────────────────────────────────────────────────

    async def get_model(self, db: AsyncSession, model_id: str) -> Optional[AIModel]:
        res = await db.execute(select(AIModel).where(AIModel.id == model_id))
        return res.scalars().first()

    async def list_models(
        self,
        db: AsyncSession,
        *,
        limit:           int           = 50,
        offset:          int           = 0,
        risk_category:   Optional[str] = None,
        registry_status: Optional[str] = None,
        sector:          Optional[str] = None,
    ) -> List[AIModel]:
        q = (
            select(AIModel)
            .order_by(AIModel.registered_at.desc())
            .limit(limit)
            .offset(offset)
        )
        if risk_category:
            q = q.where(AIModel.risk_category == risk_category.upper())
        if registry_status:
            q = q.where(AIModel.registry_status == registry_status.upper())
        if sector:
            q = q.where(AIModel.sector == sector.lower())
        result = await db.execute(q)
        return result.scalars().all()

    async def get_stats(self, db: AsyncSession) -> Dict[str, Any]:
        total = (await db.execute(func.count(AIModel.id))).scalar() or 0

        risk_counts: Dict[str, int] = {}
        for cat in VALID_RISK:
            cnt = (await db.execute(
                select(func.count(AIModel.id)).where(AIModel.risk_category == cat)
            )).scalar() or 0
            risk_counts[cat] = cnt

        status_counts: Dict[str, int] = {}
        for s in VALID_STATUS:
            cnt = (await db.execute(
                select(func.count(AIModel.id)).where(AIModel.registry_status == s)
            )).scalar() or 0
            status_counts[s] = cnt

        hashed = (await db.execute(
            select(func.count(AIModel.id)).where(AIModel.model_sha256.isnot(None))
        )).scalar() or 0

        return {
            "total_registered_models": total,
            "models_with_weight_hash": hashed,
            "hash_coverage_pct":       round(hashed / total * 100, 1) if total else 0,
            "risk_distribution":       risk_counts,
            "registry_status":         status_counts,
            "bascg_layer":             "Layer 4 — National AI Registry (NAIR-I)",
            "legal_basis": {
                "it_act": "S.43A — Reasonable security practices",
                "meity":  "National AI Strategy — Model Registration Mandate",
            },
        }

    # ── Core writes ───────────────────────────────────────────────────────────

    async def submit_model_hash(
        self,
        db:                 AsyncSession,
        model_id:           str,
        sha256:             str,
        training_data_hash: Optional[str] = None,
        framework:          Optional[str] = None,
        parameter_count:    Optional[str] = None,
        model_card_url:     Optional[str] = None,
    ) -> AIModel:
        m = await self.get_model(db, model_id)
        if not m:
            raise ValueError(f"Model {model_id!r} not found")

        m.model_sha256       = sha256
        if training_data_hash: m.training_data_hash = training_data_hash
        if framework:          m.framework          = framework
        if parameter_count:    m.parameter_count    = parameter_count
        if model_card_url:     m.model_card_url     = model_card_url

        # Promote to ACTIVE once a hash is submitted
        if m.registry_status == "PENDING":
            m.registry_status    = "ACTIVE"
            m.nair_registered_at = datetime.now(timezone.utc)

        await db.commit()
        await db.refresh(m)
        logger.info("NAIR-I hash submitted: model=%s sha256=%.16s", model_id[:8], sha256)
        return m

    async def update_risk_category(
        self,
        db:                       AsyncSession,
        model_id:                 str,
        risk_category:            str,
        compliance_certifications: Optional[List] = None,
    ) -> AIModel:
        cat = risk_category.upper()
        if cat not in VALID_RISK:
            raise ValueError(f"Invalid risk_category {cat!r}. Must be one of {VALID_RISK}")

        m = await self.get_model(db, model_id)
        if not m:
            raise ValueError(f"Model {model_id!r} not found")

        m.risk_category   = cat
        m.last_audited_at = datetime.now(timezone.utc)
        if compliance_certifications is not None:
            m.compliance_certifications = compliance_certifications
        if cat == "PROHIBITED":
            m.registry_status = "SUSPENDED"

        await db.commit()
        await db.refresh(m)
        logger.info("NAIR-I risk updated: model=%s risk=%s", model_id[:8], cat)
        return m

    async def update_registry_status(
        self,
        db:              AsyncSession,
        model_id:        str,
        registry_status: str,
        reason:          Optional[str] = None,
    ) -> AIModel:
        s = registry_status.upper()
        if s not in VALID_STATUS:
            raise ValueError(f"Invalid registry_status {s!r}. Must be one of {VALID_STATUS}")

        m = await self.get_model(db, model_id)
        if not m:
            raise ValueError(f"Model {model_id!r} not found")

        m.registry_status = s
        m.last_audited_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(m)
        logger.info(
            "NAIR-I status updated: model=%s status=%s reason=%s",
            model_id[:8], s, reason,
        )
        return m

    async def patch_metadata(
        self,
        db:                       AsyncSession,
        model_id:                 str,
        sector:                   Optional[str]  = None,
        model_card_url:           Optional[str]  = None,
        compliance_certifications: Optional[List] = None,
        framework:                Optional[str]  = None,
        parameter_count:          Optional[str]  = None,
    ) -> AIModel:
        m = await self.get_model(db, model_id)
        if not m:
            raise ValueError(f"Model {model_id!r} not found")

        if sector                    is not None: m.sector                    = sector.lower()
        if model_card_url            is not None: m.model_card_url            = model_card_url
        if compliance_certifications is not None: m.compliance_certifications = compliance_certifications
        if framework                 is not None: m.framework                 = framework
        if parameter_count           is not None: m.parameter_count           = parameter_count

        await db.commit()
        await db.refresh(m)
        return m

    # ── Federation ────────────────────────────────────────────────────────────

    async def sync_to_national_node(
        self,
        db:       AsyncSession,
        model_id: str,
        node_url: Optional[str] = None,
    ) -> FederationSyncResult:
        """
        Push a signed registry entry to the national BASCG node.

        Local/dev mode (BASCG_NATIONAL_NODE_URL empty or BASCG_PROVIDER_MODE=local):
          Returns FederationSyncResult(synced=False, skipped=True) — no network call.

        Production mode:
          Signs the full registry entry with the local Ed25519 key and POSTs it to
          <node_url>/api/v1/registry/federated-sync.
          Returns FederationSyncResult(synced=True) on HTTP 200/201, or
          FederationSyncResult(synced=False, error=...) on failure.
        """
        from app.core.crypto import crypto_service

        resolved_url = node_url or getattr(settings, "BASCG_NATIONAL_NODE_URL", "").strip()
        provider_mode = getattr(settings, "BASCG_PROVIDER_MODE", "local").lower()

        # ── Local / stub mode ─────────────────────────────────────────────────
        if not resolved_url or provider_mode == "local":
            logger.debug(
                "Federation sync skipped (local mode): model=%s node_url=%r",
                model_id[:8], resolved_url or "(not configured)",
            )
            return FederationSyncResult(
                model_id  = model_id,
                node_url  = resolved_url or "local",
                synced    = False,
                skipped   = True,
                signed_by = crypto_service.signer.issuer,
                error     = None,
            )

        # ── Build and sign the payload ────────────────────────────────────────
        m = await self.get_model(db, model_id)
        if not m:
            return FederationSyncResult(
                model_id  = model_id,
                node_url  = resolved_url,
                synced    = False,
                signed_by = crypto_service.signer.issuer,
                error     = f"Model {model_id!r} not found in local registry",
            )

        entry     = model_to_entry(m, full=True)
        issuer    = crypto_service.signer.issuer
        signature = crypto_service.signer.sign(entry)
        timestamp = datetime.now(timezone.utc).isoformat()

        payload = {
            "entry":          entry,
            "signed_by":      issuer,
            "signature":      signature,
            "sync_timestamp": timestamp,
            "source_node":    resolved_url,
        }

        # ── HTTP push ─────────────────────────────────────────────────────────
        endpoint = resolved_url.rstrip("/") + "/api/v1/registry/federated-sync"
        timeout  = int(getattr(settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 10))

        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(endpoint, json=payload)

            if resp.status_code in (200, 201, 202):
                logger.info(
                    "Federation sync OK: model=%s node=%s status=%d",
                    model_id[:8], resolved_url, resp.status_code,
                )
                return FederationSyncResult(
                    model_id    = model_id,
                    node_url    = resolved_url,
                    synced      = True,
                    status_code = resp.status_code,
                    signed_by   = issuer,
                )
            else:
                err = f"HTTP {resp.status_code}: {resp.text[:200]}"
                logger.warning(
                    "Federation sync FAILED: model=%s node=%s error=%s",
                    model_id[:8], resolved_url, err,
                )
                return FederationSyncResult(
                    model_id    = model_id,
                    node_url    = resolved_url,
                    synced      = False,
                    status_code = resp.status_code,
                    signed_by   = issuer,
                    error       = err,
                )

        except Exception as exc:
            err = str(exc)
            logger.error(
                "Federation sync ERROR: model=%s node=%s error=%s",
                model_id[:8], resolved_url, err,
            )
            return FederationSyncResult(
                model_id  = model_id,
                node_url  = resolved_url,
                synced    = False,
                signed_by = issuer,
                error     = err,
            )

    async def push_all_active_to_national_node(
        self,
        db:       AsyncSession,
        node_url: Optional[str] = None,
    ) -> List[FederationSyncResult]:
        """
        Sync all ACTIVE registry entries to the national node.
        Results for skipped/failed models are included in the returned list.
        """
        res = await db.execute(
            select(AIModel).where(AIModel.registry_status == "ACTIVE")
        )
        models  = res.scalars().all()
        results = []
        for m in models:
            r = await self.sync_to_national_node(db, m.id, node_url=node_url)
            results.append(r)
        return results


# Module-level singleton
registry_service = RegistryService()
