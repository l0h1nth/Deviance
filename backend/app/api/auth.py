from fastapi import APIRouter, Header, HTTPException

from app.schemas.auth import LoginRequest, LoginResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest):
    service = AuthService()
    if not service.authenticate(credentials.username, credentials.password):
        raise HTTPException(401, "Invalid username or password")
    token, expires_in = service.create_token(credentials.username)
    return {"access_token": token, "expires_in": expires_in,
            "user": {"username": credentials.username, "role": "administrator", "display_name": "SOC Administrator"}}


@router.get("/me")
def me(authorization: str | None = Header(default=None)):
    token = authorization.removeprefix("Bearer ") if authorization else ""
    payload = AuthService().verify_token(token)
    if not payload: raise HTTPException(401, "Authentication required")
    return {"username": payload["sub"], "role": payload["role"], "display_name": "SOC Administrator"}

