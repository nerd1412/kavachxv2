"""Audit Log API."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.db.database import get_db
from app.models.orm_models import AuditLog, InferenceEvent
from typing import Optional

router = APIRouter()


def _fmt_ts(dt):
    """Return ISO-8601 UTC string with 'Z' suffix, or None."""
    if not dt:
        return None
    return dt.isoformat().replace("+00:00", "Z") + ("" if dt.isoformat().endswith("Z") or "+" in dt.isoformat() else "Z")


@router.get("/logs")
async def get_audit_logs(
    limit: int = Query(100, le=500),
    event_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    result = await db.execute(query)
    logs = result.scalars().all()
    return [
        {
            "id": l.id, "event_type": l.event_type, "entity_id": l.entity_id,
            "entity_type": l.entity_type, "actor": l.actor, "action": l.action,
            "details": l.details, "risk_level": l.risk_level,
            "timestamp": _fmt_ts(l.timestamp),
        }
        for l in logs
    ]


@router.get("/events")
async def get_events(limit: int = Query(50, le=200), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(InferenceEvent).order_by(desc(InferenceEvent.timestamp)).limit(limit)
    )
    events = result.scalars().all()
    return [
        {
            "id": e.id, "model_id": e.model_id,
            "enforcement_decision": e.enforcement_decision,
            "risk_score": e.risk_score, "confidence": e.confidence,
            "fairness_flags": e.fairness_flags,
            "policy_violations": e.policy_violations,
            "timestamp": _fmt_ts(e.timestamp),
        }
        for e in events
    ]

