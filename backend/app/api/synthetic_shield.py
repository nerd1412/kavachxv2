"""
BASCG Phase 3 — Synthetic Media Shield API
==========================================

Endpoints:
  POST /api/v1/synthetic-shield/scan        — Scan uploaded file for AI generation
  GET  /api/v1/synthetic-shield/scans       — List scan records (paginated + filtered)
  GET  /api/v1/synthetic-shield/scans/{id}  — Full scan record with evidence bundle
  GET  /api/v1/synthetic-shield/status      — Service status + Election Protection Mode state
"""

import logging
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_permission, get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.models.orm_models import SyntheticMediaScanRecord
from app.services.synthetic_media_service import synthetic_media_service

logger = logging.getLogger(__name__)

router = APIRouter()

_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MiB hard limit


class ScanUrlRequest(BaseModel):
    url: str


# ── Serialiser ────────────────────────────────────────────────────────────────

def _fmt(dt) -> Optional[str]:
    if not dt:
        return None
    s = dt.isoformat()
    return s.replace("+00:00", "Z") if "+" in s else s + "Z"


def _scan_to_dict(r: SyntheticMediaScanRecord, full: bool = False) -> dict:
    out = {
        "id":                r.id,
        "content_hash":      r.content_hash,
        "content_type":      r.content_type,
        "filename":          r.filename,
        "detector":          r.detector,
        "is_synthetic":      r.is_synthetic,
        "confidence":        r.confidence,
        "detection_labels":  r.detection_labels,
        "enforcement_action": r.enforcement_action,
        "policy_violations": r.policy_violations,
        "election_context":  r.election_context,
        "election_state":    r.election_state,
        "escalated_to_eci":  r.escalated_to_eci,
        "evidence_hash":     r.evidence_hash,
        "submitted_by":      r.submitted_by,
        "created_at":        _fmt(r.created_at),
    }
    if full:
        out["evidence_bundle"] = r.evidence_bundle
        out["raw_response"]    = r.raw_response
    return out


# ── POST /scan ─────────────────────────────────────────────────────────────────

@router.post("/scan", summary="Scan media file for AI/deepfake generation (BASCG P3)")
async def scan_media(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """
    Upload a file (image, video, or audio) and receive a deepfake detection verdict.

    Returns:
      - is_synthetic: bool
      - confidence: 0.0–1.0
      - detection_labels: list of detected manipulation signals
      - enforcement_action: PASS | ALERT | BLOCK | ESCALATE
      - evidence_bundle: tamper-evident JSON package for legal records
      - election_context: True if Election Protection Mode was active
    """
    try:
        content = await file.read()
    except Exception as exc:
        logger.error("Failed to read uploaded file: %s", exc)
        raise HTTPException(status_code=400, detail="Failed to read uploaded file")

    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed: {_MAX_UPLOAD_BYTES // (1024*1024)} MiB",
        )
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded")

    # Extract caller context for audit — current_user is a dict from JWT decode
    source_ip    = request.client.host if request.client else None
    submitted_by = (
        current_user.get("email")
        or current_user.get("sub")
        or current_user.get("username")
        if isinstance(current_user, dict)
        else getattr(current_user, "email", None) or getattr(current_user, "sub", None)
    )

    try:
        result = await synthetic_media_service.scan(
            content       = content,
            content_type  = file.content_type or "application/octet-stream",
            filename      = file.filename or "upload",
            submitted_by  = submitted_by,
            source_ip     = source_ip,
            db            = db,
        )
    except Exception as exc:
        logger.exception("Synthetic media scan failed for file %r: %s", file.filename, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {type(exc).__name__}: {exc}",
        )

    return _transform_result(result)


@router.post("/scan-url", summary="Scan a public URL (YouTube/Reel/Image)")
async def scan_url(
    req:               ScanUrlRequest,
    current_user:      dict = Depends(get_current_user),
    db:                AsyncSession = Depends(get_db),
    request:           Request = None
):
    """
    Fetch a remote asset (video/image/social link) and verify its authenticity.
    Supports YouTube, Instagram Reels, TikTok, and direct file links.
    """
    source_ip    = request.client.host if request and request.client else None
    submitted_by = (
        current_user.get("email") or current_user.get("sub") or current_user.get("username")
        if isinstance(current_user, dict) else "anonymous"
    )

    try:
        result = await synthetic_media_service.scan_url(
            url           = req.url,
            submitted_by  = submitted_by,
            source_ip     = source_ip,
            db            = db,
        )
    except Exception as exc:
        logger.exception("Synthetic media scan (URL) failed for %r: %s", req.url, exc)
        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(exc)}",
        )

    return _transform_result(result)


def _transform_result(result):
    """Unified responder for scan results."""
    return {
        "scan_id":           result.scan_id,
        "content_hash":      result.content_hash,
        "is_synthetic":      result.detection.is_synthetic,
        "confidence":        result.detection.confidence,
        "detection_labels":  result.detection.labels,
        "enforcement_action": result.enforcement_action,
        "policy_violations": result.policy_violations,
        "election_context":  result.election_context,
        "election_state":    result.election_state,
        "escalated_to_eci":  result.escalated_to_eci,
        "evidence_hash":     result.evidence_hash,
        "evidence_bundle":   result.evidence_bundle,
        "raw_response":      result.detection.raw_response,
        "detailed_report": {
            "verdict": result.detection.verdict or (
                "Synthetic manipulation likely" if result.detection.is_synthetic else "Authentic patterns detected"
            ),
            "signals": result.detection.raw_response.get("signals", {}),
            "detector": result.detection.detector,
            "origin_metadata": result.detection.raw_response.get("origin_metadata", "None found"),
        },
        "created_at":        result.created_at,
        "bascg_layer":       "Layer 3 — Synthetic Media Shield (P3)",
    }


# ── GET /scans ─────────────────────────────────────────────────────────────────

@router.get("/scans", summary="List synthetic media scan records")
async def list_scans(
    limit:             int = Query(50, le=200),
    offset:            int = Query(0, ge=0),
    enforcement_action: Optional[str] = None,
    is_synthetic:      Optional[bool] = None,
    election_context:  Optional[bool] = None,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:read")),
):
    q = (
        select(SyntheticMediaScanRecord)
        .order_by(SyntheticMediaScanRecord.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    if enforcement_action is not None:
        q = q.where(SyntheticMediaScanRecord.enforcement_action == enforcement_action.upper())
    if is_synthetic is not None:
        q = q.where(SyntheticMediaScanRecord.is_synthetic == is_synthetic)
    if election_context is not None:
        q = q.where(SyntheticMediaScanRecord.election_context == election_context)

    result = await db.execute(q)
    return [_scan_to_dict(r) for r in result.scalars().all()]


# ── GET /scans/{id} ────────────────────────────────────────────────────────────

@router.get("/scans/{scan_id}", summary="Full synthetic media scan record with evidence bundle")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:read")),
):
    res = await db.execute(
        select(SyntheticMediaScanRecord).where(SyntheticMediaScanRecord.id == scan_id)
    )
    r = res.scalars().first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    return _scan_to_dict(r, full=True)


# ── GET /status ────────────────────────────────────────────────────────────────

@router.get("/status", summary="Synthetic Media Shield service status")
async def shield_status(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    total = (await db.execute(select(func.count(SyntheticMediaScanRecord.id)))).scalar() or 0
    synthetic_count = (await db.execute(
        select(func.count(SyntheticMediaScanRecord.id)).where(SyntheticMediaScanRecord.is_synthetic == True)
    )).scalar() or 0
    escalated_count = (await db.execute(
        select(func.count(SyntheticMediaScanRecord.id)).where(SyntheticMediaScanRecord.escalated_to_eci == True)
    )).scalar() or 0

    epm_enabled    = bool(getattr(settings, "ELECTION_PROTECTION_ENABLED", False))
    election_state = getattr(settings, "ELECTION_PROTECTION_STATE", None)
    mode           = getattr(settings, "SYNTHETIC_MEDIA_MODE", "mock")
    threshold      = float(getattr(settings, "SYNTHETIC_MEDIA_CONFIDENCE_THRESHOLD", 0.65))

    return {
        "service":                    "BASCG Synthetic Media Shield",
        "bascg_layer":                "Layer 3 — Synthetic Media Shield (P3)",
        "detector_mode":              mode,
        "confidence_threshold":       threshold,
        "election_protection_enabled": epm_enabled,
        "election_protection_state":  election_state,
        "total_scans":                total,
        "synthetic_detected":         synthetic_count,
        "detection_rate_pct":         round(synthetic_count / total * 100, 1) if total else 0,
        "escalated_to_eci":           escalated_count,
        "legal_basis": {
            "dpdp":     "S.4 — Lawful processing of personal/biometric data",
            "it_act":   "S.66E / S.67A/B — Privacy & obscene material prohibitions",
            "eci":      "ECI Model Code of Conduct — synthetic political media ban",
        },
    }
