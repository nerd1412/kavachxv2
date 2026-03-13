"""Dashboard API."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timedelta, timezone
from app.db.database import get_db
from app.models.orm_models import InferenceEvent, AIModel, AuditLog, FairnessMetric

router = APIRouter()


from app.db.cache import dashboard_cache

@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    cached = await dashboard_cache.get("dashboard_stats")
    if cached:
        return cached

    total = (await db.execute(select(func.count(InferenceEvent.id)))).scalar() or 0
    blocked = (await db.execute(select(func.count(InferenceEvent.id)).where(InferenceEvent.enforcement_decision == "BLOCK"))).scalar() or 0
    alert_ct = (await db.execute(select(func.count(InferenceEvent.id)).where(InferenceEvent.enforcement_decision == "ALERT"))).scalar() or 0
    pass_ct = (await db.execute(select(func.count(InferenceEvent.id)).where(InferenceEvent.enforcement_decision == "PASS"))).scalar() or 0
    avg_risk = float((await db.execute(select(func.avg(InferenceEvent.risk_score)))).scalar() or 0.0)
    active_models = (await db.execute(select(func.count(AIModel.id)).where(AIModel.status == "active"))).scalar() or 0
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    violations_today = (await db.execute(select(func.count(AuditLog.id)).where(AuditLog.timestamp >= today))).scalar() or 0
    recent = (await db.execute(select(InferenceEvent).order_by(desc(InferenceEvent.timestamp)).limit(100))).scalars().all()
    fairness_issues = sum(1 for e in recent if e.fairness_flags and len(e.fairness_flags) > 0)
    pass_rate = (pass_ct / total) if total > 0 else 1.0
    
    result = {
        "total_inferences": total, "blocked_count": blocked, "alert_count": alert_ct,
        "pass_rate": round(pass_rate, 3), "avg_risk_score": round(avg_risk, 3),
        "active_models": active_models, "policy_violations_today": violations_today,
        "fairness_issues_detected": fairness_issues,
    }
    await dashboard_cache.set("dashboard_stats", result)
    return result


@router.get("/risk-trend")
async def get_risk_trend(hours: int = 24, db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    result = await db.execute(
        select(InferenceEvent)
        .where(InferenceEvent.timestamp >= since)
        .order_by(InferenceEvent.timestamp)
    )
    events = result.scalars().all()

    # Build 24 hourly buckets: each bucket = hour offset from 'hours' ago
    # e.g. bucket 0 = oldest hour, bucket 23 = most recent hour
    buckets = [[] for _ in range(hours)]
    for e in events:
        ts = e.timestamp
        if ts and ts.tzinfo is None:
            from datetime import timezone as _tz
            ts = ts.replace(tzinfo=_tz.utc)
        if ts and ts >= since:
            # Which hour bucket does this fall in?
            elapsed_seconds = (now - ts).total_seconds()
            bucket_idx = max(0, min(hours - 1, hours - 1 - int(elapsed_seconds // 3600)))
            buckets[bucket_idx].append(e.risk_score or 0)

    result_data = []
    for i, bucket in enumerate(buckets):
        hour_offset = i - (hours - 1)  # negative = past hours, 0 = current hour
        label_dt = now + timedelta(hours=hour_offset)
        result_data.append({
            "hour": label_dt.strftime("%H:00"),
            "avg_risk": round(sum(bucket) / len(bucket), 3) if bucket else 0,
            "count": len(bucket),
        })

    return result_data



@router.get("/enforcement-breakdown")
async def get_enforcement_breakdown(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(InferenceEvent.enforcement_decision, func.count(InferenceEvent.id)).group_by(InferenceEvent.enforcement_decision))
    rows = result.all()
    return {row[0]: row[1] for row in rows if row[0]}


@router.get("/compliance-summary")
async def get_compliance_summary():
    return [
        {"framework": "EU AI Act", "score": 82, "status": "compliant"},
        {"framework": "DPDP 2023", "score": 76, "status": "partial"},
        {"framework": "RBI Fairness", "score": 91, "status": "compliant"},
        {"framework": "NIST AI RMF", "score": 69, "status": "partial"},
    ]
