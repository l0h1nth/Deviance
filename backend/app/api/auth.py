from fastapi import APIRouter, HTTPException, Request, Response

from app.schemas.auth import LoginRequest, LoginResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/login", response_model=LoginResponse)
def login(credentials: LoginRequest, response: Response):
    service = AuthService()
    if not service.authenticate(credentials.username, credentials.password):
        raise HTTPException(401, "Invalid username or password")
    token, expires_in = service.create_token(credentials.username)
    response.set_cookie("deviance_session", token, max_age=expires_in, httponly=True,
                        secure=service.settings.environment.lower() not in {"development", "demo", "test"},
                        samesite="strict", path="/")
    return {"access_token": token, "expires_in": expires_in,
            "user": {"username": credentials.username, "role": "administrator", "display_name": "SOC Administrator"}}


@router.get("/me")
def me(request: Request):
    payload = request.state.user
    return {"username": payload["sub"], "role": payload["role"], "display_name": "SOC Administrator"}


@router.post("/logout", status_code=204)
def logout(response: Response):
    response.delete_cookie("deviance_session", path="/")
