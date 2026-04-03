"""
BASCG Phase 1 — National AI Registry (NAIR-I)  (P2 + T3-A)
============================================================

NAIR-I is the sovereign database for all AI models operating in high-risk sectors
in Bharat.  It provides:

  • Cryptographic model identity (SHA-256 of weights prevents swap attacks)
  • Dynamic risk classification (LOW → MEDIUM → HIGH → PROHIBITED)
  • Full provenance trail (training data hash, model card, certifications)
  • Public registry view for MeitY, RBI, SEBI, MoHFW auditors
  • Federation: signed push to the national BASCG node  (T2-A)
  • Bidirectional sync: pull from national node          (T3-A)

Endpoints:
  GET  /api/v1/registry                          — Public registry overview
  GET  /api/v1/registry/models                   — Searchable registry listing
  GET  /api/v1/registry/models/{id}              — Full registry entry
  PATCH /api/v1/registry/models/{id}/submit-hash — Submit model weight SHA-256
  PATCH /api/v1/registry/models/{id}/risk        — Update risk classification
  PATCH /api/v1/registry/models/{id}/status      — Update registry status
  PATCH /api/v1/registry/models/{id}             — Update provenance metadata
  POST  /api/v1/registry/models/{id}/sync        — Push entry to national node
  POST  /api/v1/registry/sync-all                — Push all ACTIVE entries (push-only)
  POST  /api/v1/registry/sync-pull               — Pull from national node  (T3-A)
  POST  /api/v1/registry/sync-bidirectional      — Full bidirectional sync  (T3-A)
  GET  /api/v1/registry/stats                    — Registry statistics
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import require_permission
from app.db.database import get_db
from app.services.registry_service import registry_service, model_to_entry

router = APIRouter()


# ── Request models ─────────────────────────────────────────────────────────────

class SubmitHashRequest(BaseModel):
    model_sha256:       str
    training_data_hash: Optional[str] = None
    framework:          Optional[str] = None
    parameter_count:    Optional[str] = None
    model_card_url:     Optional[str] = None


class RiskUpdateRequest(BaseModel):
    risk_category:             str
    compliance_certifications: Optional[list] = None


class StatusUpdateRequest(BaseModel):
    registry_status: str
    reason:          Optional[str] = None


class RegistryPatchRequest(BaseModel):
    sector:                    Optional[str]  = None
    model_card_url:            Optional[str]  = None
    compliance_certifications: Optional[list] = None
    framework:                 Optional[str]  = None
    parameter_count:           Optional[str]  = None


# ── GET /stats ─────────────────────────────────────────────────────────────────

@router.get("/stats", summary="NAIR-I registry statistics")
async def registry_stats(db: AsyncSession = Depends(get_db)):
    return await registry_service.get_stats(db)


# ── GET / (public overview) ────────────────────────────────────────────────────

@router.get("/", summary="NAIR-I public registry overview")
async def registry_overview(db: AsyncSession = Depends(get_db)):
    """Public-facing summary for MeitY, RBI, SEBI, MoHFW auditors."""
    from sqlalchemy import select
    from app.models.orm_models import AIModel

    stats = await registry_service.get_stats(db)
    res   = await db.execute(
        select(AIModel)
        .where(AIModel.risk_category.in_(["HIGH", "PROHIBITED"]))
        .where(AIModel.registry_status == "ACTIVE")
        .order_by(AIModel.registered_at.desc())
        .limit(10)
    )
    flagged = [model_to_entry(m) for m in res.scalars().all()]
    return {**stats, "high_risk_active_models": flagged}


# ── GET /models ────────────────────────────────────────────────────────────────

@router.get("/models", summary="Search the NAIR-I model registry")
async def list_registry_models(
    limit:           int = Query(50, le=200),
    offset:          int = Query(0, ge=0),
    risk_category:   Optional[str] = None,
    registry_status: Optional[str] = None,
    sector:          Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    models = await registry_service.list_models(
        db,
        limit=limit, offset=offset,
        risk_category=risk_category,
        registry_status=registry_status,
        sector=sector,
    )
    return [model_to_entry(m) for m in models]


# ── GET /models/{id} ──────────────────────────────────────────────────────────

@router.get("/models/{model_id}", summary="Full NAIR-I registry entry for a model")
async def get_registry_entry(model_id: str, db: AsyncSession = Depends(get_db)):
    m = await registry_service.get_model(db, model_id)
    if not m:
        raise HTTPException(status_code=404, detail=f"Model {model_id!r} not found")
    return model_to_entry(m, full=True)


# ── PATCH /models/{id}/submit-hash ────────────────────────────────────────────

@router.patch(
    "/models/{model_id}/submit-hash",
    summary="Submit model weight SHA-256 to the NAIR-I registry",
)
async def submit_model_hash(
    model_id: str,
    body: SubmitHashRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Registers the SHA-256 of the model's weight file.
    This fingerprint prevents silent model weight substitution — any inference
    environment can verify the hash before execution.
    """
    try:
        m = await registry_service.submit_model_hash(
            db, model_id,
            sha256             = body.model_sha256,
            training_data_hash = body.training_data_hash,
            framework          = body.framework,
            parameter_count    = body.parameter_count,
            model_card_url     = body.model_card_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    from app.services.registry_service import _fmt
    return {
        "id":                m.id,
        "model_sha256":      m.model_sha256,
        "registry_status":   m.registry_status,
        "nair_registered_at": _fmt(m.nair_registered_at),
        "message": "Model hash registered. NAIR-I entry is now ACTIVE.",
    }


# ── PATCH /models/{id}/risk ────────────────────────────────────────────────────

@router.patch(
    "/models/{model_id}/risk",
    summary="Update NAIR-I risk classification for a model",
)
async def update_risk_category(
    model_id: str,
    body: RiskUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    try:
        m = await registry_service.update_risk_category(
            db, model_id,
            risk_category            = body.risk_category,
            compliance_certifications = body.compliance_certifications,
        )
    except ValueError as exc:
        detail = str(exc)
        status = 400 if "Invalid" in detail else 404
        raise HTTPException(status_code=status, detail=detail)

    from app.services.registry_service import _fmt
    return {
        "id":              m.id,
        "risk_category":   m.risk_category,
        "registry_status": m.registry_status,
        "last_audited_at": _fmt(m.last_audited_at),
    }


# ── PATCH /models/{id}/status ─────────────────────────────────────────────────

@router.patch(
    "/models/{model_id}/status",
    summary="Update NAIR-I registry status (ACTIVE / SUSPENDED / DEREGISTERED)",
)
async def update_registry_status(
    model_id: str,
    body: StatusUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    try:
        m = await registry_service.update_registry_status(
            db, model_id,
            registry_status = body.registry_status,
            reason          = body.reason,
        )
    except ValueError as exc:
        detail = str(exc)
        status = 400 if "Invalid" in detail else 404
        raise HTTPException(status_code=status, detail=detail)

    from app.services.registry_service import _fmt
    return {
        "id":              m.id,
        "registry_status": m.registry_status,
        "last_audited_at": _fmt(m.last_audited_at),
        "reason":          body.reason,
    }


# ── PATCH /models/{id} ────────────────────────────────────────────────────────

@router.patch(
    "/models/{model_id}",
    summary="Update NAIR-I provenance metadata for a model",
)
async def patch_registry_entry(
    model_id: str,
    body: RegistryPatchRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    try:
        m = await registry_service.patch_metadata(
            db, model_id,
            sector                   = body.sector,
            model_card_url           = body.model_card_url,
            compliance_certifications = body.compliance_certifications,
            framework                = body.framework,
            parameter_count          = body.parameter_count,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return model_to_entry(m, full=True)


# ── POST /models/{id}/sync ────────────────────────────────────────────────────

@router.post(
    "/models/{model_id}/sync",
    summary="Push a signed NAIR-I entry to the national BASCG node",
)
async def sync_model_to_national_node(
    model_id:  str,
    node_url:  Optional[str] = Query(default=None, description="Override national node URL"),
    db:        AsyncSession  = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Signs the model's full registry entry with the local BASCG Ed25519 key and
    POSTs it to <node>/api/v1/registry/federated-sync for sovereign-registry federation.

    In local/dev mode (BASCG_NATIONAL_NODE_URL not configured), returns
    skipped=true without making any network call.
    """
    result = await registry_service.sync_to_national_node(db, model_id, node_url=node_url)
    return {
        "model_id":    result.model_id,
        "node_url":    result.node_url,
        "synced":      result.synced,
        "skipped":     result.skipped,
        "status_code": result.status_code,
        "signed_by":   result.signed_by,
        "error":       result.error,
    }


# ── POST /sync-all ─────────────────────────────────────────────────────────────

@router.post(
    "/sync-all",
    summary="Push all ACTIVE NAIR-I entries to the national BASCG node",
)
async def sync_all_to_national_node(
    node_url: Optional[str] = Query(default=None, description="Override national node URL"),
    db:       AsyncSession  = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """Convenience batch endpoint — syncs every ACTIVE model in one call."""
    results = await registry_service.push_all_active_to_national_node(db, node_url=node_url)
    return {
        "total":   len(results),
        "synced":  sum(1 for r in results if r.synced),
        "skipped": sum(1 for r in results if r.skipped),
        "failed":  sum(1 for r in results if not r.synced and not r.skipped),
        "results": [
            {
                "model_id":    r.model_id,
                "synced":      r.synced,
                "skipped":     r.skipped,
                "status_code": r.status_code,
                "signed_by":   r.signed_by,
                "error":       r.error,
            }
            for r in results
        ],
    }


# ── POST /sync-pull (T3-A) ─────────────────────────────────────────────────────

@router.post(
    "/sync-pull",
    summary="Pull NAIR-I entries from the national node into the local registry",
)
async def sync_pull_from_national_node(
    node_url: Optional[str] = Query(default=None, description="Override national node URL"),
    db:       AsyncSession  = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Fetches all registry entries from the national BASCG node and applies them locally.
    New nationally-registered models are created as local stubs (nair_source="national").
    Existing models have their authority-owned fields (risk_category, registry_status,
    compliance_certifications) updated to match the national record.
    """
    from app.services.nair_sync_service import nair_sync_service
    result = await nair_sync_service.pull_from_national_node(db, node_url=node_url)
    return {
        "node_url":     result.node_url,
        "pulled_count": result.pulled_count,
        "created":      result.created,
        "updated":      result.updated,
        "skipped":      result.skipped,
        "failed":       result.failed,
        "errors":       result.errors[:20],   # cap for response size
        "completed_at": result.completed_at,
    }


# ── POST /sync-bidirectional (T3-A) ───────────────────────────────────────────

@router.post(
    "/sync-bidirectional",
    summary="Full bidirectional NAIR-I sync: push all ACTIVE entries then pull from national node",
)
async def sync_bidirectional(
    node_url: Optional[str] = Query(default=None, description="Override national node URL"),
    db:       AsyncSession  = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """
    Runs a complete push-then-pull cycle:
      1. Pushes all ACTIVE local registry entries to the national node.
      2. Pulls all entries from the national node and applies them locally.
    Returns a summary of both operations.
    """
    from app.services.nair_sync_service import nair_sync_service
    result = await nair_sync_service.bidirectional_sync(db, node_url=node_url)
    return {
        "node_url":     result.node_url,
        "push": {
            "ok":      result.push_ok,
            "failed":  result.push_failed,
            "skipped": result.push_skipped,
        },
        "pull": {
            "pulled_count": result.pull.pulled_count,
            "created":      result.pull.created,
            "updated":      result.pull.updated,
            "skipped":      result.pull.skipped,
            "failed":       result.pull.failed,
            "errors":       result.pull.errors[:20],
        },
        "completed_at": result.completed_at,
    }
