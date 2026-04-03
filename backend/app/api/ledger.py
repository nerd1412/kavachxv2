"""
BASCG Phase 1 — Sovereign Ledger API
=====================================

Exposes the Forensic Integrity Layer for:
  • Regulators (MeitY, RBI, SEBI) querying anchor status
  • Legal/compliance teams retrieving Merkle proofs for court admissibility
  • DevOps manually triggering anchor cycles

Endpoints:
  GET  /api/v1/ledger/status                         — Worker health + totals
  GET  /api/v1/ledger/anchors                        — Paginated list of anchors
  GET  /api/v1/ledger/anchors/{anchor_id}            — Full anchor detail
  GET  /api/v1/ledger/anchors/{anchor_id}/proof/{i}  — Merkle proof for leaf i
  GET  /api/v1/ledger/logs/{log_id}/proof            — Proof by AuditLog ID
  POST /api/v1/ledger/trigger                        — Manual anchor cycle
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import get_db
from app.models.orm_models import AuditLog, LedgerAnchor
from app.models.schemas import LedgerAnchorOut, MerkleProofOut, MerkleProofStep
from app.services.sovereign_ledger_sync import sovereign_ledger_sync

router = APIRouter()


# ── helpers ───────────────────────────────────────────────────────────────────

def _fmt(dt) -> Optional[str]:
    if not dt:
        return None
    s = dt.isoformat()
    return s if s.endswith("Z") else s.replace("+00:00", "Z") + (
        "" if "+" in s or s.endswith("Z") else "Z"
    )


def _anchor_to_out(a: LedgerAnchor) -> LedgerAnchorOut:
    return LedgerAnchorOut(
        id                 = a.id,
        batch_start_log_id = a.batch_start_log_id,
        batch_end_log_id   = a.batch_end_log_id,
        log_count          = a.log_count,
        merkle_root        = a.merkle_root,
        tsa_provider       = a.tsa_provider,
        tsa_serial         = a.tsa_serial,
        tsa_timestamp      = _fmt(a.tsa_timestamp),
        anchor_status      = a.anchor_status,
        error_message      = a.error_message,
        created_at         = _fmt(a.created_at) or "",
        anchored_at        = _fmt(a.anchored_at),
    )


# ── GET /status ───────────────────────────────────────────────────────────────

@router.get("/status", summary="Sovereign Ledger sync status and statistics")
async def ledger_status(db: AsyncSession = Depends(get_db)):
    """
    Returns current configuration and aggregate anchor statistics.
    Useful for regulator dashboards and health checks.
    """
    total_anchors = (await db.execute(func.count(LedgerAnchor.id))).scalar() or 0
    anchored      = (await db.execute(
        func.count(LedgerAnchor.id).filter(LedgerAnchor.anchor_status == "anchored")
    )).scalar() or 0
    failed        = (await db.execute(
        func.count(LedgerAnchor.id).filter(LedgerAnchor.anchor_status == "failed")
    )).scalar() or 0
    unanchored_logs = (await db.execute(
        func.count(AuditLog.id).filter(AuditLog.merkle_anchor_id.is_(None))
    )).scalar() or 0

    # Latest anchor
    res    = await db.execute(
        select(LedgerAnchor).order_by(desc(LedgerAnchor.created_at)).limit(1)
    )
    latest = res.scalars().first()

    return {
        "sovereign_ledger_enabled":        getattr(settings, "SOVEREIGN_LEDGER_ENABLED", True),
        "sovereign_ledger_mode":           getattr(settings, "SOVEREIGN_LEDGER_MODE",    "mock"),
        "ledger_anchor_interval_minutes":  getattr(settings, "LEDGER_ANCHOR_INTERVAL_MINUTES", 5),
        "tsa_url":                         getattr(settings, "TSA_URL", "https://freetsa.org/tsr"),
        "total_anchors":                   total_anchors,
        "anchored":                        anchored,
        "failed":                          failed,
        "unanchored_logs_pending":         unanchored_logs,
        "latest_anchor": {
            "id":            latest.id            if latest else None,
            "merkle_root":   latest.merkle_root   if latest else None,
            "status":        latest.anchor_status if latest else None,
            "anchored_at":   _fmt(latest.anchored_at) if latest else None,
            "log_count":     latest.log_count     if latest else None,
        },
        "legal_basis": {
            "it_act_section":  "S.65B — Electronic Records",
            "dpdp_sections":   ["S.8 Data Integrity", "S.10 Data Fiduciary Accountability"],
            "compliance_note": (
                "Each anchored Merkle root is independently witnessed by a TSA, "
                "making audit logs tamper-evident and court-admissible under IT Act 2000."
            ),
        },
    }


# ── GET /anchors ──────────────────────────────────────────────────────────────

@router.get("/anchors", response_model=list[LedgerAnchorOut],
            summary="List Merkle anchor batches")
async def list_anchors(
    limit:  int = Query(50, le=200),
    offset: int = Query(0,  ge=0),
    status: Optional[str] = Query(None, description="Filter by anchor_status: pending|anchored|failed"),
    db: AsyncSession = Depends(get_db),
):
    q = select(LedgerAnchor).order_by(desc(LedgerAnchor.created_at)).limit(limit).offset(offset)
    if status:
        q = q.where(LedgerAnchor.anchor_status == status)
    result = await db.execute(q)
    return [_anchor_to_out(a) for a in result.scalars().all()]


# ── GET /anchors/{anchor_id} ──────────────────────────────────────────────────

@router.get("/anchors/{anchor_id}", response_model=LedgerAnchorOut,
            summary="Get a single Merkle anchor by ID")
async def get_anchor(anchor_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(LedgerAnchor).where(LedgerAnchor.id == anchor_id))
    anchor = result.scalars().first()
    if not anchor:
        raise HTTPException(status_code=404, detail=f"Anchor {anchor_id!r} not found")
    return _anchor_to_out(anchor)


# ── GET /anchors/{anchor_id}/proof/{leaf_index} ───────────────────────────────

@router.get(
    "/anchors/{anchor_id}/proof/{leaf_index}",
    response_model=MerkleProofOut,
    summary="Generate Merkle proof for a specific leaf in an anchor batch",
)
async def get_proof_by_anchor(
    anchor_id:  str,
    leaf_index: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns a self-contained Merkle proof package.

    The caller can verify tamper-evidence without any server interaction:
    1. Compute `leaf_hash = SHA256(bytes.fromhex(audit_log.chain_hash)).hex()`
    2. Apply each proof step (left/right sibling combination)
    3. Assert the final hash equals `merkle_root`
    4. Independently verify `tsa_token_b64` against the TSA certificate
    """
    try:
        raw = await sovereign_ledger_sync.get_merkle_proof(anchor_id, leaf_index, db)
    except (ValueError, IndexError) as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return MerkleProofOut(
        anchor_id         = raw["anchor_id"],
        merkle_root       = raw["merkle_root"],
        leaf_index        = raw["leaf_index"],
        leaf_hash         = raw["leaf_hash"],
        proof             = [MerkleProofStep(**s) for s in raw["proof"]],
        log_count         = raw["log_count"],
        tsa_provider      = raw["tsa_provider"],
        tsa_token_b64     = raw["tsa_token_b64"],
        tsa_timestamp     = raw["tsa_timestamp"],
        anchor_status     = raw["anchor_status"],
        verification_hint = raw["verification_hint"],
    )


# ── GET /logs/{log_id}/proof ──────────────────────────────────────────────────

@router.get(
    "/logs/{log_id}/proof",
    response_model=MerkleProofOut,
    summary="Get Merkle proof for an AuditLog by its ID",
)
async def get_proof_by_log(log_id: str, db: AsyncSession = Depends(get_db)):
    """
    Convenience endpoint: looks up the AuditLog, finds its anchor, and returns
    the proof package — no need to know the anchor_id or leaf_index.
    """
    try:
        raw = await sovereign_ledger_sync.get_proof_for_log(log_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    return MerkleProofOut(
        anchor_id         = raw["anchor_id"],
        merkle_root       = raw["merkle_root"],
        leaf_index        = raw["leaf_index"],
        leaf_hash         = raw["leaf_hash"],
        proof             = [MerkleProofStep(**s) for s in raw["proof"]],
        log_count         = raw["log_count"],
        tsa_provider      = raw["tsa_provider"],
        tsa_token_b64     = raw["tsa_token_b64"],
        tsa_timestamp     = raw["tsa_timestamp"],
        anchor_status     = raw["anchor_status"],
        verification_hint = raw["verification_hint"],
    )


# ── POST /trigger ─────────────────────────────────────────────────────────────

@router.post("/trigger", summary="Manually trigger a Sovereign Ledger anchor cycle")
async def trigger_anchor_cycle(db: AsyncSession = Depends(get_db)):
    """
    Forces an immediate anchor cycle outside the scheduled interval.
    Useful for: admin testing, pre-audit snapshots, post-incident evidence collection.
    """
    anchor = await sovereign_ledger_sync.run_anchor_cycle(db)
    if anchor is None:
        return {
            "status":  "skipped",
            "message": (
                f"No un-anchored logs met the minimum batch size "
                f"({getattr(settings, 'LEDGER_ANCHOR_MIN_BATCH_SIZE', 1)}). "
                "Nothing to anchor."
            ),
        }
    return {
        "status":      anchor.anchor_status,
        "anchor_id":   anchor.id,
        "merkle_root": anchor.merkle_root,
        "log_count":   anchor.log_count,
        "tsa_provider": anchor.tsa_provider,
        "anchored_at": _fmt(anchor.anchored_at),
        "error":       anchor.error_message,
    }
