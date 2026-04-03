"""
BASCG Control Plane API
========================

Unified API for the Bharat AI Sovereign Control Grid — visibility, demo, and
production-readiness across all 4 pillars.

Endpoints:
  GET  /api/v1/bascg/status               — Live provider mode + health of all 4 pillars
  GET  /api/v1/bascg/production-readiness — Step-by-step checklist to reach production
  POST /api/v1/bascg/admin/import-regulator-key — Import a regulator Ed25519 public key (T2-B)
  DELETE /api/v1/bascg/admin/regulator-keys/{issuer} — Remove a regulator key at runtime
  GET  /api/v1/bascg/admin/trusted-keys   — List all currently trusted issuer keys
  POST /api/v1/bascg/demo/anchor-cycle    — Seed demo AuditLogs + trigger Merkle anchor (Pillar 1)
  POST /api/v1/bascg/demo/issue-nael      — Issue a dev NAEL license for a model (Pillar 3)
  POST /api/v1/bascg/demo/scan-media      — Run synthetic media scan via governance pipeline (Pillar 4)
  GET  /api/v1/bascg/demo/bootstrap-status — Show what demo data exists across all pillars
"""

import base64
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_permission, get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.services.bascg_status_service import bascg_status_service

router = APIRouter()


# ── GET /status ────────────────────────────────────────────────────────────────

@router.get("/status", summary="BASCG Grid: live provider mode + health of all 4 pillars")
async def get_bascg_status():
    """
    Returns the live configuration of every BASCG pillar — which provider is
    active (local/mock vs production), whether it is operational, and what
    environment variables to change to switch to production.

    Use this endpoint to confirm:
      • Pillar 1 (Forensic): MockTSA vs RFC3161 vs Blockchain
      • Pillar 2 (Regulatory): ephemeral key vs persistent Ed25519 seed
      • Pillar 3 (Licensing): NAEL soft enforcement vs hard enforcement
      • Pillar 4 (Synthetic Media): mock detector vs external API
    """
    grid = bascg_status_service.get_status()
    return {
        "bascg_grid":           "Bharat AI Sovereign Control Grid",
        "provider_mode":        grid.provider_mode,
        "environment":          grid.environment,
        "readiness_score_pct":  grid.readiness_score,
        "operational_pillars":  f"{grid.operational_count}/{len(grid.pillars)}",
        "local_demo_ready":     grid.local_demo_ready,
        "production_ready":     grid.production_ready,
        "pillars": [
            {
                "name":             p.name,
                "layer":            p.layer,
                "provider_mode":    p.provider_mode,
                "local_ready":      p.local_ready,
                "production_ready": p.production_ready,
                "operational":      p.operational,
                "status":           p.status_detail,
                "config":           p.config_keys,
                "production_steps": p.production_steps,
            }
            for p in grid.pillars
        ],
        "production_gaps": grid.production_gaps,
    }


# ── GET /production-readiness ──────────────────────────────────────────────────

@router.get("/production-readiness", summary="BASCG step-by-step production readiness checklist")
async def production_readiness():
    """
    Structured checklist of everything needed to move each pillar from
    local simulation to national production deployment.
    """
    grid = bascg_status_service.get_status()

    checklist = []
    for p in grid.pillars:
        items = []
        for step in p.production_steps:
            items.append({"done": False, "action": step})
        if not items:
            items.append({"done": True, "action": f"{p.name} is production-ready"})
        checklist.append({
            "pillar":            p.name,
            "layer":             p.layer,
            "current_mode":      p.provider_mode,
            "production_ready":  p.production_ready,
            "items":             items,
        })

    done_count = sum(1 for p in grid.pillars if p.production_ready)
    return {
        "title":          "BASCG Local-to-Production Bridge — Readiness Checklist",
        "pillars_ready":  f"{done_count}/{len(grid.pillars)}",
        "checklist":      checklist,
        "next_step":      grid.production_gaps[0] if grid.production_gaps else "All pillars production-ready!",
        "docs": {
            "signing_keys":  "Run `python scripts/generate_dev_keys.py` to generate Ed25519 keypair",
            "tsa_providers": "FreeTSA (free): https://freetsa.org/tsr | DigiCert: https://timestamp.digicert.com",
            "nael":          "POST /api/v1/nael/issue to issue licenses before enabling NAEL_ENFORCEMENT_ENABLED",
        },
    }


# ── POST /demo/anchor-cycle ────────────────────────────────────────────────────

@router.post(
    "/demo/anchor-cycle",
    summary="BASCG Demo — seed AuditLogs and trigger Merkle anchor (Pillar 1)",
)
async def demo_anchor_cycle(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Seeds a batch of demo AuditLog entries with valid SHA-256 chain hashes,
    then triggers a full Sovereign Ledger anchor cycle.

    This demonstrates Pillar 1 (Forensic Integrity) end-to-end:
      AuditLog rows → MerkleTree → TSA timestamp → LedgerAnchor row

    Returns the resulting LedgerAnchor with Merkle root and TSA receipt.
    """
    from app.models.orm_models import AuditLog
    from app.services.sovereign_ledger_sync import sovereign_ledger_sync

    # Seed 5 demo audit log entries with a proper SHA-256 chain
    demo_logs = []
    prev_hash: Optional[str] = None
    for i in range(5):
        payload = {
            "event_type": "bascg_demo",
            "entity_id":  str(uuid.uuid4()),
            "step":       i,
            "ts":         datetime.now(timezone.utc).isoformat(),
        }
        import json
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        payload_hash = hashlib.sha256(body).hexdigest()
        chain_hash   = hashlib.sha256(((prev_hash or "") + payload_hash).encode()).hexdigest()

        log = AuditLog(
            event_type  = "bascg_demo",
            entity_id   = payload["entity_id"],
            entity_type = "demo",
            actor       = "bascg_demo",
            action      = f"demo_step_{i}",
            details     = payload,
            risk_level  = "low",
            prev_hash   = prev_hash,
            chain_hash  = chain_hash,
        )
        db.add(log)
        demo_logs.append(log)
        prev_hash = chain_hash

    await db.flush()  # assign IDs

    # Trigger anchor cycle
    anchor = await sovereign_ledger_sync.run_anchor_cycle(db)
    if anchor is None:
        raise HTTPException(
            status_code=409,
            detail="Anchor cycle skipped — fewer logs than LEDGER_ANCHOR_MIN_BATCH_SIZE. "
                   "Demo logs were seeded; retry or lower LEDGER_ANCHOR_MIN_BATCH_SIZE.",
        )

    return {
        "pillar":          "Forensic Integrity",
        "demo_logs_seeded": len(demo_logs),
        "anchor_id":       anchor.id,
        "merkle_root":     anchor.merkle_root,
        "log_count":       anchor.log_count,
        "tsa_provider":    anchor.tsa_provider,
        "tsa_serial":      anchor.tsa_serial,
        "anchor_status":   anchor.anchor_status,
        "anchored_at":     anchor.anchored_at.isoformat() if anchor.anchored_at else None,
        "message": (
            "Forensic anchor complete. "
            f"Merkle root {anchor.merkle_root[:16]}… signed by {anchor.tsa_provider}. "
            "To upgrade to IT Act S.65B admissibility: set SOVEREIGN_LEDGER_MODE=rfc3161."
        ),
    }


# ── POST /demo/issue-nael ──────────────────────────────────────────────────────

class IssueNAELRequest(BaseModel):
    model_id:             str
    sector_restrictions:  list = []
    risk_classification:  str  = "MEDIUM"
    valid_days:           int  = 365


@router.post(
    "/demo/issue-nael",
    summary="BASCG Demo — issue a NAEL dev license for a model (Pillar 3)",
)
async def demo_issue_nael(
    body: IssueNAELRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Issues a National AI Execution License (NAEL) for the specified model.

    This activates Pillar 3 (Licensing Enforcement) locally:
      • Signs the token with the current BASCG_SIGNING_KEY_SEED_B64 (or ephemeral key)
      • Stores the NAELLicense row in the DB
      • The governance pipeline will now validate this license before inference

    Production bridge: When NAEL_ENFORCEMENT_ENABLED=true and
    NAEL_AUTO_PROVISION_DEV=false, only manually issued licenses are accepted.
    """
    from app.services.nael_service import nael_service

    try:
        lic = await nael_service.issue_license(
            db                    = db,
            model_id              = body.model_id,
            sector_restrictions   = body.sector_restrictions,
            risk_classification   = body.risk_classification,
            licensed_tee_platforms = ["mock"],
            valid_days            = body.valid_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return {
        "pillar":              "Licensing Enforcement",
        "license_id":          lic.id,
        "model_id":            lic.model_id,
        "risk_classification": lic.risk_classification,
        "sector_restrictions": lic.sector_restrictions,
        "valid_from":          lic.valid_from.isoformat() if lic.valid_from else None,
        "valid_until":         lic.valid_until.isoformat() if lic.valid_until else None,
        "issued_by":           lic.issued_by,
        "message": (
            f"NAEL license issued. Model {body.model_id[:8]}… is now licensed for inference. "
            "Enable NAEL_ENFORCEMENT_ENABLED=true to hard-enforce this check."
        ),
    }


# ── POST /demo/scan-media ──────────────────────────────────────────────────────

class ScanMediaRequest(BaseModel):
    content_b64:   str
    content_type:  Optional[str] = "image/jpeg"
    filename:      Optional[str] = None


@router.post(
    "/demo/scan-media",
    summary="BASCG Demo — scan base64 media via synthetic media shield (Pillar 4)",
)
async def demo_scan_media(
    body: ScanMediaRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Demonstrates Pillar 4 (Synthetic Media Shield) by scanning base64-encoded
    media content through the detection pipeline.

    Test vectors (pass as content_b64 after base64-encoding):
      b"SYNTHETIC_TEST" → confidence=0.95, ALERT/BLOCK
      b"REAL_TEST"      → confidence=0.05, PASS

    Python quick-test:
        import base64
        base64.b64encode(b"SYNTHETIC_TEST").decode()  # → "U1lOVEhFVElDX1RFU1Q="
    """
    from app.services.synthetic_media_service import synthetic_media_service

    try:
        content = base64.b64decode(body.content_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in content_b64")

    submitted_by = getattr(current_user, "username", None)
    result = await synthetic_media_service.scan(
        content      = content,
        content_type = body.content_type,
        filename     = body.filename,
        submitted_by = submitted_by,
        db           = db,
    )

    return {
        "pillar":            "Synthetic Media Shield",
        "scan_id":           result.scan_id,
        "is_synthetic":      result.detection.is_synthetic,
        "confidence":        result.detection.confidence,
        "labels":            result.detection.labels,
        "enforcement_action": result.enforcement_action,
        "election_context":  result.election_context,
        "evidence_hash":     result.evidence_hash,
        "message": (
            f"Synthetic media scan complete. "
            f"Confidence={result.detection.confidence:.0%} → {result.enforcement_action}. "
            "To use a real detector: set SYNTHETIC_MEDIA_MODE=api."
        ),
    }


# ── GET /demo/bootstrap-status ────────────────────────────────────────────────

@router.get(
    "/demo/bootstrap-status",
    summary="BASCG Demo — show existing demo data across all pillars",
)
async def demo_bootstrap_status(db: AsyncSession = Depends(get_db)):
    """
    Quick visibility into what demo/live data exists for each pillar.
    Run this after `POST /demo/anchor-cycle` and `POST /demo/issue-nael`
    to confirm all 4 pillars have data.
    """
    from app.models.orm_models import (
        LedgerAnchor, AuditLog, NAELLicense,
        GovernancePolicy, SyntheticMediaScanRecord,
    )

    anchor_count  = (await db.execute(func.count(LedgerAnchor.id))).scalar() or 0
    log_count     = (await db.execute(func.count(AuditLog.id))).scalar() or 0
    nael_count    = (await db.execute(func.count(NAELLicense.id))).scalar() or 0
    policy_count  = (await db.execute(func.count(GovernancePolicy.id))).scalar() or 0
    scan_count    = (await db.execute(func.count(SyntheticMediaScanRecord.id))).scalar() or 0

    # Latest anchor
    latest_anchor = None
    res = await db.execute(
        select(LedgerAnchor).order_by(LedgerAnchor.created_at.desc()).limit(1)
    )
    a = res.scalars().first()
    if a:
        latest_anchor = {
            "id": a.id, "root": a.merkle_root[:16] + "…",
            "status": a.anchor_status, "logs": a.log_count,
            "provider": a.tsa_provider,
        }

    grid = bascg_status_service.get_status()

    return {
        "pillars": {
            "forensic_integrity": {
                "ledger_anchors":  anchor_count,
                "audit_logs":      log_count,
                "latest_anchor":   latest_anchor,
                "tsa_mode":        getattr(settings, "SOVEREIGN_LEDGER_MODE", "mock"),
                "ready":           anchor_count > 0,
            },
            "regulatory_authority": {
                "signed_policies":  policy_count,
                "signing_key_set":  bool(getattr(settings, "BASCG_SIGNING_KEY_SEED_B64", "")),
                "ready":            True,  # policy_bundle_service always active
            },
            "licensing_enforcement": {
                "nael_licenses":       nael_count,
                "enforcement_enabled": getattr(settings, "NAEL_ENFORCEMENT_ENABLED", False),
                "auto_provision":      getattr(settings, "NAEL_AUTO_PROVISION_DEV", True),
                "ready":               nael_count > 0 or getattr(settings, "NAEL_AUTO_PROVISION_DEV", True),
            },
            "synthetic_media_shield": {
                "scans_run":    scan_count,
                "detector_mode": getattr(settings, "SYNTHETIC_MEDIA_MODE", "mock"),
                "epm_enabled":  getattr(settings, "ELECTION_PROTECTION_ENABLED", False),
                "ready":        True,  # always operational
            },
        },
        "overall_readiness_pct": grid.readiness_score,
        "local_demo_ready":      grid.local_demo_ready,
        "production_ready":      grid.production_ready,
        "tip": (
            "Run POST /api/v1/bascg/demo/anchor-cycle and POST /api/v1/bascg/demo/issue-nael "
            "to populate all pillars with demo data."
            if anchor_count == 0 or nael_count == 0
            else "All demo data present. Check GET /api/v1/bascg/production-readiness for next steps."
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  T2-B: Regulator Key Import Admin API
# ══════════════════════════════════════════════════════════════════════════════

class ImportRegulatorKeyRequest(BaseModel):
    issuer:         str   # e.g. "MeitY-BASCG-v1" or "RBI-AI-Gov"
    public_key_b64: str   # base64-encoded 32-byte Ed25519 raw public key
    persist:        bool  = True  # write to bascg_regulator_keys.json sidecar


@router.post(
    "/admin/import-regulator-key",
    summary="Import a regulator Ed25519 public key into the live trust store",
)
async def import_regulator_key(
    body: ImportRegulatorKeyRequest,
    current_user=Depends(require_permission("policies:write")),
):
    """
    Registers a sovereign regulator's Ed25519 public key in the BASCG trust
    store at runtime — no restart required.

    Once imported, NAEL tokens and policy bundles signed by that regulator
    are immediately verifiable.  Requires *policies:write* permission.

    **Persistence**: when `persist=true` (default), the key is written to
    `bascg_regulator_keys.json` and reloaded on the next server start.
    To make it permanent across deployments, add the issuer:key pair to
    `BASCG_TRUSTED_PUBLIC_KEYS_JSON` in your deployment environment.

    **Security notes**:
    - Cannot shadow the local `dev-local` issuer.
    - Imported keys are audited in the server log.
    - Every import requires *policies:write* (admin-only) authorisation.
    """
    from app.core.crypto import crypto_service, DEV_ISSUER as _crypto_dev

    try:
        crypto_service.import_regulator_key(body.issuer, body.public_key_b64)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    trusted_keys = crypto_service.list_trusted_keys()

    if body.persist:
        # Persist only non-local keys to the sidecar
        to_persist = {
            k: v for k, v in trusted_keys.items()
            if k != _crypto_dev
        }
        try:
            save_regulator_keys(to_persist)
        except Exception as exc:
            import logging as _log
            _log.getLogger("kavachx.bascg").warning(
                "Failed to persist regulator key to sidecar: %s", exc
            )

    return {
        "imported":        True,
        "issuer":          body.issuer,
        "trusted_issuers": list(trusted_keys.keys()),
        "total_trusted":   len(trusted_keys),
        "persisted":       body.persist,
        "deployment_tip": (
            f"To make this key permanent across restarts, add to "
            f"BASCG_TRUSTED_PUBLIC_KEYS_JSON: "
            f'{{"{body.issuer}": "{body.public_key_b64}"}}'
        ),
    }


@router.delete(
    "/admin/regulator-keys/{issuer}",
    summary="Remove a regulator key from the live trust store",
)
async def remove_regulator_key(
    issuer: str,
    persist: bool = True,
    current_user=Depends(require_permission("policies:write")),
):
    """
    Removes a regulator's public key from the live trust store.
    The `dev-local` issuer is protected and cannot be removed.
    Requires *policies:write* permission.
    """
    from app.core.crypto import crypto_service

    removed = crypto_service.remove_regulator_key(issuer)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail=f"Issuer {issuer!r} not found in trust store, or is protected.",
        )

    trusted_keys = crypto_service.list_trusted_keys()

    if persist:
        from app.core.config import save_regulator_keys
        from app.core.crypto import DEV_ISSUER as _crypto_dev
        to_persist = {k: v for k, v in trusted_keys.items() if k != _crypto_dev}
        try:
            save_regulator_keys(to_persist)
        except Exception as exc:
            import logging as _log
            _log.getLogger("kavachx.bascg").warning(
                "Failed to update regulator keys sidecar after removal: %s", exc
            )

    return {
        "removed":         True,
        "issuer":          issuer,
        "trusted_issuers": list(trusted_keys.keys()),
        "total_trusted":   len(trusted_keys),
    }


@router.get(
    "/admin/trusted-keys",
    summary="List all currently trusted BASCG issuer keys",
)
async def list_trusted_keys(
    current_user=Depends(require_permission("policies:write")),
):
    """
    Returns every issuer currently in the live trust store with its
    base64-encoded public key.  Useful for auditing which regulators
    have been granted signing authority on this node.
    """
    from app.core.crypto import crypto_service, DEV_ISSUER

    trusted_keys = crypto_service.list_trusted_keys()
    return {
        "trusted_issuers": [
            {
                "issuer":        issuer,
                "public_key_b64": pub_b64,
                "is_local":      issuer == DEV_ISSUER,
            }
            for issuer, pub_b64 in trusted_keys.items()
        ],
        "total": len(trusted_keys),
    }
