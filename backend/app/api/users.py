"""
User management API — Super Admin only.
"""
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import ROLES, get_current_user, hash_password, validate_password
from app.db.database import get_db
from app.models.orm_models import User

router = APIRouter()

VALID_ROLES = list(ROLES.keys())


def _require_superadmin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="Super Admin access required")
    return current_user


def _user_to_dict(user: User, include_stats: bool = False) -> dict:
    role_info = ROLES.get(user.role, {})
    d = {
        "id":            user.id,
        "name":          user.name,
        "email":         user.email,
        "role":          user.role,
        "role_label":    role_info.get("label", user.role),
        "permissions":   role_info.get("permissions", []),
        "is_active":     user.is_active,
        "created_at":    user.created_at.isoformat() + "Z" if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() + "Z" if user.last_login_at else None,
        "created_by":    user.created_by,
    }
    return d


# ── Schemas ───────────────────────────────────────────────────────────────────

class CreateUserRequest(BaseModel):
    name:     str
    email:    str
    password: str
    role:     str


class UpdateUserRequest(BaseModel):
    name:      Optional[str] = None
    role:      Optional[str] = None
    is_active: Optional[bool] = None


class AdminResetPasswordRequest(BaseModel):
    new_password: str


# ── GET /users ────────────────────────────────────────────────────────────────

@router.get("", summary="List all users (Super Admin)")
async def list_users(
    limit:     int = Query(50, le=200),
    offset:    int = Query(0, ge=0),
    role:      Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: dict = Depends(_require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    q = select(User).order_by(User.created_at.desc()).limit(limit).offset(offset)
    if role:
        q = q.where(User.role == role)
    if is_active is not None:
        q = q.where(User.is_active == is_active)

    users  = (await db.execute(q)).scalars().all()
    total  = (await db.execute(select(func.count(User.id)))).scalar() or 0
    return {"users": [_user_to_dict(u) for u in users], "total": total}


# ── POST /users ───────────────────────────────────────────────────────────────

@router.post("", summary="Create a new user (Super Admin)", status_code=201)
async def create_user(
    body: CreateUserRequest,
    current_user: dict = Depends(_require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    email = body.email.strip().lower()

    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role. Must be one of: {VALID_ROLES}")

    existing = (await db.execute(select(User).where(User.email == email))).scalars().first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    pw_errors = validate_password(body.password)
    if pw_errors:
        raise HTTPException(status_code=422, detail={"password_errors": pw_errors})

    user = User(
        name            = body.name.strip(),
        email           = email,
        hashed_password = hash_password(body.password),
        role            = body.role,
        is_active       = True,
        created_by      = current_user["id"],
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return _user_to_dict(user)


# ── GET /users/{id} ───────────────────────────────────────────────────────────

@router.get("/{user_id}", summary="Get user by ID (Super Admin)")
async def get_user(
    user_id: str,
    current_user: dict = Depends(_require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_to_dict(user)


# ── PUT /users/{id} ───────────────────────────────────────────────────────────

@router.put("/{user_id}", summary="Update user (Super Admin)")
async def update_user(
    user_id: str,
    body: UpdateUserRequest,
    current_user: dict = Depends(_require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent superadmin from deactivating themselves
    if user.id == current_user["id"] and body.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    if body.name is not None:
        user.name = body.name.strip()
    if body.role is not None:
        if body.role not in VALID_ROLES:
            raise HTTPException(status_code=422, detail=f"Invalid role")
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active

    await db.commit()
    await db.refresh(user)
    return _user_to_dict(user)


# ── POST /users/{id}/reset-password ──────────────────────────────────────────

@router.post("/{user_id}/reset-password", summary="Admin password reset (Super Admin)")
async def admin_reset_password(
    user_id: str,
    body: AdminResetPasswordRequest,
    current_user: dict = Depends(_require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    pw_errors = validate_password(body.new_password)
    if pw_errors:
        raise HTTPException(status_code=422, detail={"password_errors": pw_errors})

    user.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"message": f"Password reset for {user.email}"}


# ── DELETE /users/{id} ────────────────────────────────────────────────────────

@router.delete("/{user_id}", summary="Deactivate user (Super Admin, soft delete)")
async def deactivate_user(
    user_id: str,
    current_user: dict = Depends(_require_superadmin),
    db: AsyncSession = Depends(get_db),
):
    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    user = (await db.execute(select(User).where(User.id == user_id))).scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    await db.commit()
    return {"message": f"User {user.email} deactivated"}
