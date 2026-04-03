"""
BASCG Phase 1 — NAEL (National AI Execution License) API
=========================================================

Endpoints:
  POST /api/v1/nael/issue                — Issue a new NAEL license for a model
  GET  /api/v1/nael/models/{model_id}    — Get active license for a model
  GET  /api/v1/nael/licenses/{id}        — Get license by ID
  POST /api/v1/nael/licenses/{id}/revoke — Revoke a license
  POST /api/v1/nael/validate             — Validate a model for a sector/TEE (dry-run)
  GET  /api/v1/nael/status               — NAEL enforcement config + totals
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db
from app.models.orm_models import NAELLicense
from app.services.nael_service import nael_service

router = APIRouter()


# ── Request / Response models ─────────────────────────────────────────────────

class IssueRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    model_id:               str
    sector_restrictions:    List[str]  = []
    risk_classification:    str        = "MEDIUM"
    licensed_tee_platforms: List[str]  = []
    model_sha256:           Optional[str] = None
    valid_days:             int        = 365


class RevokeRequest(BaseModel):
    reason: str = "manual revocation"


class ValidateRequest(BaseModel):
    model_config = {"protected_namespaces": ()}
    model_id:     str
    sector:       Optional[str] = None
    tee_platform: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt(dt) -> Optional[str]:
    if not dt:
        return None
    s = dt.isoformat()
    return s.replace("+00:00", "Z") if "+" in s else s + "Z"


def _lic_to_dict(lic: NAELLicense) -> dict:
    return {
        "id":                     lic.id,
        "model_id":               lic.model_id,
        "model_sha256":           lic.model_sha256,
        "sector_restrictions":    lic.sector_restrictions,
        "risk_classification":    lic.risk_classification,
        "licensed_tee_platforms": lic.licensed_tee_platforms,
        "issued_by":              lic.issued_by,
        "issued_at":              _fmt(lic.issued_at),
        "valid_from":             _fmt(lic.valid_from),
        "valid_until":            _fmt(lic.valid_until),
        "revoked":                lic.revoked,
        "revocation_reason":      lic.revocation_reason,
    }


# ── GET /status ───────────────────────────────────────────────────────────────

@router.get("/status", summary="NAEL enforcement status and totals")
async def nael_status(db: AsyncSession = Depends(get_db)):
    total    = (await db.execute(func.count(NAELLicense.id))).scalar() or 0
    active   = (await db.execute(
        func.count(NAELLicense.id).filter(NAELLicense.revoked.is_(False))
    )).scalar() or 0
    revoked  = total - active

    return {
        "nael_enforcement_enabled": getattr(settings, "NAEL_ENFORCEMENT_ENABLED", False),
        "note": (
            "NAEL enforcement is ON — models without a valid license will be BLOCKED."
            if getattr(settings, "NAEL_ENFORCEMENT_ENABLED", False)
            else "NAEL enforcement is OFF (onboarding mode) — missing licenses produce ALERT only."
        ),
        "trusted_issuers": (
            [settings.BASCG_SIGNING_KEY_SEED_B64[:4] + "…"] if
            getattr(settings, "BASCG_SIGNING_KEY_SEED_B64", "") else ["dev-local (ephemeral)"]
        ),
        "total_licenses": total,
        "active_licenses": active,
        "revoked_licenses": revoked,
        "legal_basis": {
            "framework": "National AI Execution Licensing (NAEL)",
            "bascg_layer": "Layer 2 — Grid Engine",
            "token_algorithm": "Ed25519",
        },
    }


# ── POST /issue ───────────────────────────────────────────────────────────────

@router.post("/issue", summary="Issue a new NAEL license for a registered AI model")
async def issue_license(body: IssueRequest, db: AsyncSession = Depends(get_db)):
    """
    Issues a cryptographically signed NAEL token for the specified model.
    The token is stored in the nael_licenses table and returned in full.
    """
    try:
        lic = await nael_service.issue_license(
            db                     = db,
            model_id               = body.model_id,
            sector_restrictions    = body.sector_restrictions,
            risk_classification    = body.risk_classification,
            licensed_tee_platforms = body.licensed_tee_platforms,
            model_sha256           = body.model_sha256,
            valid_days             = body.valid_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    result = _lic_to_dict(lic)
    result["license_token"] = lic.license_token   # include signed JWT for embedding
    return result


# ── GET /models/{model_id} ────────────────────────────────────────────────────

@router.get("/models/{model_id}", summary="Get the active NAEL license for a model")
async def get_model_license(model_id: str, db: AsyncSession = Depends(get_db)):
    lic = await nael_service.get_license_for_model(db, model_id)
    if not lic:
        raise HTTPException(
            status_code=404,
            detail=f"No active NAEL license found for model {model_id}. "
                   "Issue one via POST /api/v1/nael/issue",
        )
    return _lic_to_dict(lic)


# ── GET /licenses/{id} ────────────────────────────────────────────────────────

@router.get("/licenses/{license_id}", summary="Get a NAEL license by ID")
async def get_license(license_id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(NAELLicense).where(NAELLicense.id == license_id))
    lic = res.scalars().first()
    if not lic:
        raise HTTPException(status_code=404, detail=f"License {license_id!r} not found")
    return _lic_to_dict(lic)


# ── POST /licenses/{id}/revoke ────────────────────────────────────────────────

@router.post("/licenses/{license_id}/revoke", summary="Revoke a NAEL license")
async def revoke_license(
    license_id: str, body: RevokeRequest, db: AsyncSession = Depends(get_db)
):
    try:
        lic = await nael_service.revoke_license(db, license_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {
        "id":               lic.id,
        "revoked":          lic.revoked,
        "revocation_reason": lic.revocation_reason,
        "message":          f"License {license_id[:8]}… revoked. Affected model will be blocked on next inference.",
    }


# ── POST /validate ────────────────────────────────────────────────────────────

@router.post("/validate", summary="Dry-run NAEL validation for a model + sector")
async def validate(body: ValidateRequest, db: AsyncSession = Depends(get_db)):
    """
    Simulates the NAEL gate check without triggering a real inference.
    Useful for regulators to test compliance before enforcement is enabled.
    """
    result = await nael_service.validate_for_inference(
        db           = db,
        model_id     = body.model_id,
        sector       = body.sector,
        tee_platform = body.tee_platform,
    )
    return {
        "model_id":   body.model_id,
        "sector":     body.sector,
        "valid":      result.valid,
        "action":     result.action,
        "reason":     result.reason,
        "license_id": result.license_id,
        "enforcement_active": getattr(settings, "NAEL_ENFORCEMENT_ENABLED", False),
    }
