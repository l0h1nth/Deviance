import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import alerts, auth, drift, events, health, ingestion, metrics, models, notifications, profiles, simulations
from app.config import get_settings
from app.database import models as database_models
from app.database.session import Base, engine
from app.services.auth_service import AuthService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings(); settings.data_dir.mkdir(parents=True, exist_ok=True); settings.model_dir.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(engine); yield


settings = get_settings()
app = FastAPI(title="Deviance API", version="1.0.0", lifespan=lifespan,
              description="ML-first behavioral anomaly detection for access telemetry")
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=False,
                   allow_methods=["GET", "POST", "PATCH", "OPTIONS"], allow_headers=["Content-Type", "Authorization"])


@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 5_000_000: return JSONResponse({"detail": "request body too large"}, 413)
    protected = request.url.path.startswith("/api/") and request.url.path not in {"/api/health", "/api/auth/login"}
    if protected and request.method != "OPTIONS":
        authorization = request.headers.get("authorization", "")
        token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else request.query_params.get("token", "")
        payload = AuthService().verify_token(token)
        if not payload: return JSONResponse({"detail": "Authentication required"}, 401)
        request.state.user = payload
    try: return await call_next(request)
    except Exception:
        logging.exception("Unhandled request error")
        return JSONResponse({"detail": "internal server error"}, 500)


for router in (auth.router, health.router, ingestion.router, events.router, alerts.router, profiles.router, metrics.router, drift.router, models.router, simulations.router, notifications.router):
    app.include_router(router, prefix="/api")
