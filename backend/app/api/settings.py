"""
Settings & Platform Configuration API
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.core.config import settings, save_thresholds
from app.core.auth import require_permission

router = APIRouter()

class ThresholdsModel(BaseModel):
    risk_high: float
    risk_medium: float
    fairness_disparity: float
    confidence_low: float

@router.get("/thresholds", response_model=ThresholdsModel)
async def get_thresholds(current_user=Depends(require_permission("dashboard:read"))):
    return {
        "risk_high": settings.RISK_SCORE_HIGH_THRESHOLD,
        "risk_medium": settings.RISK_SCORE_MEDIUM_THRESHOLD,
        "fairness_disparity": settings.FAIRNESS_DISPARITY_THRESHOLD,
        "confidence_low": settings.CONFIDENCE_LOW_THRESHOLD,
    }

@router.put("/thresholds", response_model=ThresholdsModel)
async def update_thresholds(
    data: ThresholdsModel, 
    current_user=Depends(require_permission("dashboard:read"))  # Allowing dashboard readers to edit for demo, ideally should be configure:system
):
    save_thresholds(data.model_dump())
    return {
        "risk_high": settings.RISK_SCORE_HIGH_THRESHOLD,
        "risk_medium": settings.RISK_SCORE_MEDIUM_THRESHOLD,
        "fairness_disparity": settings.FAIRNESS_DISPARITY_THRESHOLD,
        "confidence_low": settings.CONFIDENCE_LOW_THRESHOLD,
    }
