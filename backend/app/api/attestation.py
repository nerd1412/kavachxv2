"""
BASCG Phase 1 — TEE Attestation API  (Layer 1: Silicon Root-of-Trust)
=======================================================================

Endpoints:
  GET  /api/v1/attestation/challenge              — Issue a nonce challenge
  POST /api/v1/attestation/verify                 — Verify an attestation document
  GET  /api/v1/attestation/reports                — List attestation reports
  GET  /api/v1/attestation/reports/{id}           — Get a single report
  POST /api/v1/attestation/mock-document          — Generate a mock attestation doc (dev only)
  GET  /api/v1/attestation/status                 — TEE config + totals
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db
from app.models.orm_models import AttestationReport
from app.services.tee_attestation_service import tee_attestation_service, MOCK_PCR0

router = APIRouter()


# ── Request / Response models ─────────────────────────────────────────────────

class VerifyRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    raw_document_b64:  str
    expected_nonce:    str
    model_id:          Optional[str] = None
    expected_pcr0:     Optional[str] = None
    nael_license_id:   Optional[str] = None


class MockDocumentRequest(BaseModel):
    nonce:     Optional[str] = None
    user_data: Optional[str] = None  # base64-encoded bytes to embed in user_data


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt(dt) -> Optional[str]:
    if not dt:
        return None
    s = dt.isoformat()
    return s.replace("+00:00", "Z") if "+" in s else s + "Z"


def _report_to_dict(r: AttestationReport) -> dict:
    return {
        "id":                   r.id,
        "platform":             r.platform,
        "model_id":             r.model_id,
        "nael_license_id":      r.nael_license_id,
        "pcr0":                 r.pcr0,
        "verified":             r.verified,
        "pcr0_match":           r.pcr0_match,
        "nael_valid":           r.nael_valid,
        "failure_reason":       r.failure_reason,
        "clearance_valid_until": _fmt(r.clearance_valid_until),
        "created_at":           _fmt(r.created_at),
    }


# ── GET /status ───────────────────────────────────────────────────────────────

@router.get("/status", summary="TEE attestation configuration and statistics")
async def attestation_status(db: AsyncSession = Depends(get_db)):
    total    = (await db.execute(func.count(AttestationReport.id))).scalar() or 0
    verified = (await db.execute(
        func.count(AttestationReport.id).filter(AttestationReport.verified.is_(True))
    )).scalar() or 0
    failed   = total - verified

    return {
        "tee_attestation_mode": getattr(settings, "TEE_ATTESTATION_MODE", "mock"),
        "mock_pcr0":            MOCK_PCR0,
        "clearance_ttl_minutes": tee_attestation_service.CLEARANCE_TTL_MINUTES,
        "total_reports":        total,
        "verified":             verified,
        "failed":               failed,
        "bascg_layer":          "Layer 1 — Silicon / Hardware Root-of-Trust",
        "supported_platforms": {
            "mock":      "Local HMAC-signed simulation (no hardware required)",
            "aws-nitro": "AWS Nitro Enclaves COSE_Sign1 (ECDSA-P384, requires cbor2)",
        },
        "production_note": (
            "Set TEE_ATTESTATION_MODE=aws-nitro and deploy on r6i/m6i/i3en instances. "
            "Future: Intel SGX DCAP when Indian DC hardware adoption increases."
        ),
    }


# ── GET /challenge ────────────────────────────────────────────────────────────

@router.get("/challenge", summary="Issue a TEE attestation nonce challenge")
async def get_challenge():
    """
    Returns a fresh 32-byte nonce that the enclave must embed in its
    attestation document.  This prevents replay attacks.

    The caller must present the same nonce when calling POST /verify.
    Nonces are single-use — store server-side in Redis/DB for production.
    (This demo returns the nonce directly; production should store it.)
    """
    nonce = tee_attestation_service.generate_nonce()
    return {
        "nonce":      nonce,
        "expires_in": "300s",
        "instruction": (
            "Embed this nonce in your TEE attestation document's nonce field, "
            "then submit the document to POST /api/v1/attestation/verify"
        ),
    }


# ── POST /mock-document ───────────────────────────────────────────────────────

@router.post("/mock-document", summary="Generate a mock attestation document (dev only)")
async def generate_mock_document(body: MockDocumentRequest):
    """
    Generates a mock TEE attestation document for testing the verification pipeline.
    Only available when TEE_ATTESTATION_MODE=mock.
    """
    if getattr(settings, "TEE_ATTESTATION_MODE", "mock") != "mock":
        raise HTTPException(
            status_code=403,
            detail="Mock document generation only available in TEE_ATTESTATION_MODE=mock",
        )
    import base64 as b64
    nonce     = body.nonce or tee_attestation_service.generate_nonce()
    user_data = b64.b64decode(body.user_data) if body.user_data else None
    doc_b64   = tee_attestation_service.generate_mock_document(nonce=nonce, user_data=user_data)
    return {
        "nonce":            nonce,
        "raw_document_b64": doc_b64,
        "pcr0":             MOCK_PCR0,
        "platform":         "mock",
        "usage":            "Submit raw_document_b64 + nonce to POST /api/v1/attestation/verify",
    }


# ── POST /verify ──────────────────────────────────────────────────────────────

@router.post("/verify", summary="Verify a TEE attestation document")
async def verify_attestation(body: VerifyRequest, db: AsyncSession = Depends(get_db)):
    """
    Full attestation verification pipeline:
      1. Decode + cryptographically verify the document (HMAC / COSE_Sign1)
      2. Check nonce matches issued challenge (anti-replay)
      3. Check PCR0 == expected enclave image hash
      4. Validate NAEL token embedded in user_data (if present)
      5. Persist AttestationReport
      6. Return clearance_valid_until on success

    On success: use clearance_valid_until to gate model inference without
    re-attesting on every request (cache attestation for TTL duration).
    """
    result = await tee_attestation_service.verify_document(
        db               = db,
        raw_document_b64 = body.raw_document_b64,
        expected_nonce   = body.expected_nonce,
        model_id         = body.model_id,
        expected_pcr0    = body.expected_pcr0,
        nael_license_id  = body.nael_license_id,
    )
    return {
        "verified":             result.verified,
        "pcr0_match":           result.pcr0_match,
        "nael_valid":           result.nael_valid,
        "platform":             result.platform,
        "module_id":            result.module_id,
        "pcr0":                 result.pcr0,
        "expected_pcr0":        result.expected_pcr0,
        "failure_reason":       result.failure_reason,
        "clearance_valid_until": _fmt(result.clearance_valid_until),
        "silicon_to_sovereign":  result.verified and result.pcr0_match,
    }


# ── GET /reports ──────────────────────────────────────────────────────────────

@router.get("/reports", summary="List TEE attestation reports")
async def list_reports(
    limit:    int = Query(50, le=200),
    verified: Optional[bool] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    q = select(AttestationReport).order_by(desc(AttestationReport.created_at)).limit(limit)
    if verified is not None:
        q = q.where(AttestationReport.verified.is_(verified))
    result = await db.execute(q)
    return [_report_to_dict(r) for r in result.scalars().all()]


# ── GET /reports/{id} ─────────────────────────────────────────────────────────

@router.get("/reports/{report_id}", summary="Get a TEE attestation report by ID")
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(
        select(AttestationReport).where(AttestationReport.id == report_id)
    )
    r = res.scalars().first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Report {report_id!r} not found")
    detail = _report_to_dict(r)
    detail["nonce"] = r.nonce
    detail["user_data_b64"] = r.user_data_b64
    return detail
