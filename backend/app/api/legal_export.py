"""
BASCG T3-D — Legal Bundle Export API
======================================

Endpoints (all under /api/v1/legal-export):

  POST /inference/{inference_id}  — Export evidence bundle for a single inference
  POST /time-window               — Export evidence bundle for a calendar window
  GET  /records                   — List previous export records (metadata only)
  GET  /records/{record_id}       — Get a specific export record
  GET  /status                    — Service config and capabilities

All endpoints are enabled by default (LEGAL_EXPORT_ENABLED=True).
Returns 503 when disabled.

Authentication: requires "policies:read" scope.
(Exporting is a read-heavy operation; the auth boundary is the scope check.)
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db
from app.services.legal_bundle_service import (
    legal_bundle_service,
    _serialize_export_record,
)

router = APIRouter()


# ── Guard ─────────────────────────────────────────────────────────────────────

def _check_enabled() -> None:
    if not bool(getattr(settings, "LEGAL_EXPORT_ENABLED", True)):
        raise HTTPException(
            status_code=503,
            detail=(
                "Legal bundle export is disabled. "
                "Set LEGAL_EXPORT_ENABLED=true to enable."
            ),
        )


# ── Request models ────────────────────────────────────────────────────────────

class TimeWindowRequest(BaseModel):
    since:           datetime
    until:           datetime
    model_id_filter: Optional[str] = None
    actor:           Optional[str] = None


# ── GET /status ───────────────────────────────────────────────────────────────

@router.get("/status", summary="Legal bundle export configuration and capabilities")
async def legal_export_status(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    from app.models.orm_models import LegalExportRecord

    total = (await db.execute(func.count(LegalExportRecord.id))).scalar() or 0

    return {
        "legal_export_enabled":           getattr(settings, "LEGAL_EXPORT_ENABLED", True),
        "sign_bundles":                   getattr(settings, "LEGAL_EXPORT_SIGN_BUNDLES", True),
        "include_raw_documents":          getattr(settings, "LEGAL_EXPORT_INCLUDE_RAW_DOCUMENTS", False),
        "max_audit_logs_per_bundle":      getattr(settings, "LEGAL_EXPORT_MAX_AUDIT_LOGS", 1000),
        "total_export_records":           total,
        "supported_bundle_types":         ["inference", "time_window"],
        "legal_basis": {
            "act":          "IT Act 2000 S.65B",
            "jurisdiction": "India",
            "standard":     "BASCG-3.6",
        },
        "production_note": (
            "In production set LEGAL_EXPORT_SIGN_BUNDLES=true and configure an "
            "HSM-backed Ed25519 key via BASCG_SIGNING_KEY_SEED_B64 or AWS KMS. "
            "Pair with SOVEREIGN_LEDGER_MODE=rfc3161 for TSA-timestamped Merkle proofs."
        ),
    }


# ── POST /inference/{inference_id} ────────────────────────────────────────────

@router.post(
    "/inference/{inference_id}",
    summary="Export a court-admissible evidence bundle for a single AI inference decision",
)
async def export_inference_bundle(
    inference_id: str,
    actor:        Optional[str] = Query(None, description="Requesting actor (username / system)"),
    db:           AsyncSession  = Depends(get_db),
):
    """
    Assembles all governance artefacts for the given inference:

    - Inference event record (decision, risk score, violations)
    - Tamper-evident audit log chain (SHA-256 linked)
    - Merkle proof for each anchored audit log
    - TSA timestamp token (RFC 3161 or mock-HMAC)
    - Governance policies that were evaluated
    - NAEL license for the model
    - TEE attestation report for the compute node
    - Synthetic media scan result (if applicable)

    The bundle is Ed25519-signed and SHA-256 hashed.
    A LegalExportRecord is persisted for the audit trail.
    """
    _check_enabled()
    try:
        bundle = await legal_bundle_service.export_inference_bundle(
            db           = db,
            inference_id = inference_id,
            actor        = actor or "api",
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return bundle.to_dict()


# ── POST /time-window ─────────────────────────────────────────────────────────

@router.post(
    "/time-window",
    summary="Export a court-admissible evidence bundle for a calendar time window",
)
async def export_time_window_bundle(
    body: TimeWindowRequest,
    db:   AsyncSession = Depends(get_db),
):
    """
    Assembles all governance artefacts for the given time range:

    - All inference events in the window (optionally filtered by model_id)
    - All audit logs in the window
    - Merkle proofs for anchored logs
    - Governance policies, NAEL licenses, TEE attestations per model
    - Peer node attestations recorded in the window

    Useful for compliance audits, regulatory submissions, and incident response.
    Succeeds even if no events exist in the window (returns empty artefacts).
    """
    _check_enabled()
    if body.since >= body.until:
        raise HTTPException(
            status_code=422,
            detail="'since' must be earlier than 'until'",
        )
    bundle = await legal_bundle_service.export_time_window_bundle(
        db              = db,
        since           = body.since,
        until           = body.until,
        model_id_filter = body.model_id_filter,
        actor           = body.actor or "api",
    )
    return bundle.to_dict()


# ── GET /records ──────────────────────────────────────────────────────────────

@router.get(
    "/records",
    summary="List previous legal bundle export records (metadata only — not full bundles)",
)
async def list_export_records(
    limit:       int           = Query(50, le=200),
    bundle_type: Optional[str] = Query(None, description="Filter by type: inference | time_window"),
    db:          AsyncSession  = Depends(get_db),
):
    _check_enabled()
    records = await legal_bundle_service.list_export_records(
        db          = db,
        limit       = limit,
        bundle_type = bundle_type,
    )
    return [_serialize_export_record(r) for r in records]


# ── GET /records/{record_id} ──────────────────────────────────────────────────

@router.get(
    "/records/{record_id}",
    summary="Get a specific legal bundle export record by ID",
)
async def get_export_record(
    record_id: str,
    db:        AsyncSession = Depends(get_db),
):
    _check_enabled()
    record = await legal_bundle_service.get_export_record(db, record_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Export record {record_id!r} not found",
        )
    return _serialize_export_record(record)
