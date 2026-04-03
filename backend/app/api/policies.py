"""Governance Policies API."""
import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.models.orm_models import GovernancePolicy
from app.core.auth import require_permission, get_current_user
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

router = APIRouter()


class RuleCreate(BaseModel):
    field: str
    operator: str
    value: float
    action: str


class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    policy_type: str = "fairness"
    rules: Optional[List[RuleCreate]] = []
    severity: str = "medium"
    jurisdiction: str = "IN"


class ToggleBody(BaseModel):
    enabled: bool


BUILT_IN_POLICIES = [
    {"id": "builtin-confidence", "name": "Low Confidence Block", "description": "Blocks inferences with confidence below 0.50", "policy_type": "safety", "severity": "high", "jurisdiction": "GLOBAL", "rules": [{"field": "confidence", "operator": "lt", "value": 0.50, "action": "BLOCK"}]},
    {"id": "builtin-fairness", "name": "Fairness Disparity Alert", "description": "Alerts when demographic disparity exceeds 20%", "policy_type": "fairness", "severity": "medium", "jurisdiction": "IN", "rules": [{"field": "fairness_disparity", "operator": "gt", "value": 0.20, "action": "ALERT"}]},
    {"id": "builtin-risk", "name": "High Risk Escalation", "description": "Routes high-risk inferences (>75) to human review", "policy_type": "compliance", "severity": "critical", "jurisdiction": "IN", "rules": [{"field": "risk_score", "operator": "gt", "value": 0.75, "action": "HUMAN_REVIEW"}]},
    {"id": "builtin-llm-safety", "name": "LLM Safety Guard", "description": "Blocks LLM outputs with toxicity score > 0.5", "policy_type": "llm_safety", "severity": "critical", "jurisdiction": "GLOBAL", "rules": [{"field": "toxicity_score", "operator": "gt", "value": 0.50, "action": "BLOCK"}]},
    {"id": "builtin-caste-proxy", "name": "Caste-Proxy Detection", "description": "Flags potential caste-based discrimination via proxy variables", "policy_type": "fairness", "severity": "critical", "jurisdiction": "IN", "rules": [{"field": "caste_proxy_score", "operator": "gt", "value": 0.15, "action": "ALERT"}]},
    {"id": "builtin-dpdp", "name": "DPDP Compliance Check", "description": "Ensures data processing complies with India DPDP 2023", "policy_type": "compliance", "severity": "high", "jurisdiction": "IN", "rules": [{"field": "dpdp_consent_present", "operator": "eq", "value": 0, "action": "BLOCK"}]},
]


@router.get("/")
async def list_policies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(GovernancePolicy))
    custom = result.scalars().all()
    built_in = [{"enabled": True, "created_at": "2026-01-01T00:00:00Z", **p} for p in BUILT_IN_POLICIES]
    custom_out = [{
        "id": p.id, "name": p.name, "description": p.description,
        "policy_type": p.policy_type, "rules": p.rules, "severity": p.severity,
        "jurisdiction": p.jurisdiction, "enabled": p.enabled,
        "created_at": p.created_at.isoformat() if p.created_at else None,
    } for p in custom]
    return built_in + custom_out


@router.post("/")
async def create_policy(policy: PolicyCreate, db: AsyncSession = Depends(get_db), current_user=Depends(require_permission("policies:write"))):
    from app.services.policy_bundle_service import policy_bundle_service
    from app.core.crypto import crypto_service as _cs
    policy_id = str(uuid.uuid4())
    rules_raw = [r.model_dump() for r in policy.rules]

    # BASCG P0: auto-sign so GovernanceService._load_federated_policies accepts it
    policy_dict = {
        "id": policy_id, "name": policy.name,
        "description": policy.description or "",
        "policy_type": policy.policy_type, "severity": policy.severity,
        "jurisdiction": policy.jurisdiction, "rules": rules_raw,
    }
    sig = policy_bundle_service.sign_db_policy_payload(policy_dict)

    new = GovernancePolicy(
        id=policy_id, name=policy.name, description=policy.description,
        policy_type=policy.policy_type, rules=rules_raw,
        severity=policy.severity, jurisdiction=policy.jurisdiction,
        policy_signature=sig, signed_by=_cs.signer.issuer, bundle_version="1.0",
    )
    db.add(new)
    await db.commit()
    await db.refresh(new)
    return {"id": new.id, "name": new.name, "enabled": new.enabled, "signed_by": new.signed_by}


@router.put("/{policy_id}")
async def update_policy(
    policy_id: str,
    policy: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(require_permission("policies:write")),
):
    """Full policy update. Re-signs the row so governance engine accepts it."""
    if policy_id.startswith("builtin"):
        raise HTTPException(status_code=400, detail="Cannot modify built-in baseline policies")
    result = await db.execute(select(GovernancePolicy).where(GovernancePolicy.id == policy_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")

    from app.services.policy_bundle_service import policy_bundle_service
    from app.core.crypto import crypto_service as _cs

    rules_raw = [r.model_dump() for r in policy.rules]
    policy_dict = {
        "id": policy_id, "name": policy.name,
        "description": policy.description or "",
        "policy_type": policy.policy_type, "severity": policy.severity,
        "jurisdiction": policy.jurisdiction, "rules": rules_raw,
    }
    sig = policy_bundle_service.sign_db_policy_payload(policy_dict)

    p.name = policy.name
    p.description = policy.description
    p.policy_type = policy.policy_type
    p.rules = rules_raw
    p.severity = policy.severity
    p.jurisdiction = policy.jurisdiction
    p.policy_signature = sig
    p.signed_by = _cs.signer.issuer
    await db.commit()
    await db.refresh(p)
    return {
        "id": p.id, "name": p.name, "description": p.description,
        "policy_type": p.policy_type, "severity": p.severity,
        "jurisdiction": p.jurisdiction, "enabled": p.enabled,
        "signed_by": p.signed_by,
    }


@router.patch("/{policy_id}/toggle")
async def toggle_policy(policy_id: str, body: ToggleBody, db: AsyncSession = Depends(get_db), current_user=Depends(require_permission("policies:write"))):
    if policy_id.startswith("builtin"):
        raise HTTPException(status_code=400, detail="Cannot toggle built-in baseline policies — they are always active")
    result = await db.execute(select(GovernancePolicy).where(GovernancePolicy.id == policy_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    p.enabled = body.enabled
    await db.commit()
    return {"id": p.id, "enabled": p.enabled}


@router.delete("/{policy_id}")
async def delete_policy(policy_id: str, db: AsyncSession = Depends(get_db), current_user=Depends(require_permission("policies:delete"))):
    if policy_id.startswith("builtin"):
        raise HTTPException(status_code=400, detail="Cannot delete built-in baseline policies")
    result = await db.execute(select(GovernancePolicy).where(GovernancePolicy.id == policy_id))
    p = result.scalar_one_or_none()
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    await db.delete(p)
    await db.commit()
    return {"deleted": policy_id}
