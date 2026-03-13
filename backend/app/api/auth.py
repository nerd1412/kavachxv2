"""Auth API endpoints."""
from datetime import timedelta
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.core.auth import authenticate_user, create_access_token, ROLES, SEEDED_USERS

router = APIRouter()


class LoginRequest(BaseModel):
    email: str
    password: str


@router.post("/login")
async def login(body: LoginRequest):
    user = authenticate_user(body.email, body.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": body.email}, expires_delta=timedelta(hours=8))
    role_info = ROLES.get(user["role"], {})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": body.email,
            "role": user["role"],
            "role_label": role_info.get("label", user["role"]),
            "permissions": role_info.get("permissions", []),
            "avatar": user["avatar"],
        }
    }


@router.get("/demo-accounts")
async def demo_accounts():
    """Returns available demo accounts for login screen."""
    accounts = []
    for em, u in SEEDED_USERS.items():
        role_info = ROLES.get(u["role"], {})
        accounts.append({
            "email": em,
            "name": u["name"],
            "role": u["role"],
            "role_label": role_info.get("label"),
            "password": u["plain_password"],
            "description": role_info.get("description"),
        })
    return {"demo_accounts": accounts}
