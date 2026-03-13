"""Model Registry API."""
import uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.database import get_db
from app.models.orm_models import AIModel
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

router = APIRouter()


class ModelCreate(BaseModel):
    name: str
    version: str
    model_type: str = "classification"
    owner: Optional[str] = None
    description: Optional[str] = None


class StatusUpdate(BaseModel):
    status: str


@router.get("/")
async def list_models(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AIModel).order_by(AIModel.registered_at.desc()))
    models = result.scalars().all()
    return [
        {
            "id": m.id, "name": m.name, "version": m.version, "model_type": m.model_type,
            "owner": m.owner, "description": m.description, "status": m.status,
            "registered_at": m.registered_at.isoformat() if m.registered_at else None,
        }
        for m in models
    ]


@router.post("/")
async def create_model(model: ModelCreate, db: AsyncSession = Depends(get_db)):
    new = AIModel(
        id=str(uuid.uuid4()),
        name=model.name,
        version=model.version,
        model_type=model.model_type,
        owner=model.owner,
        description=model.description,
        status="active",
    )
    db.add(new)
    await db.commit()
    await db.refresh(new)
    return {"id": new.id, "name": new.name, "version": new.version, "status": new.status}


@router.get("/{model_id}")
async def get_model(model_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AIModel).where(AIModel.id == model_id))
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    return {"id": model.id, "name": model.name, "version": model.version, "model_type": model.model_type, "owner": model.owner, "description": model.description, "status": model.status}


@router.patch("/{model_id}/status")
async def update_model_status(model_id: str, body: StatusUpdate, db: AsyncSession = Depends(get_db)):
    if body.status not in ("active", "suspended", "archived"):
        raise HTTPException(status_code=400, detail="Invalid status")
    result = await db.execute(select(AIModel).where(AIModel.id == model_id))
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")
    model.status = body.status
    await db.commit()
    return {"id": model.id, "status": model.status}
