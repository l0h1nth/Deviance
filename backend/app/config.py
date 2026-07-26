from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "Deviance"
    environment: str = "development"
    database_url: str = f"sqlite:///{ROOT / 'data' / 'deviance.db'}"
    model_dir: Path = ROOT / "data" / "models"
    data_dir: Path = ROOT / "data"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    alert_threshold: float = 50.0
    minimum_user_history: int = 12
    minimum_peer_history: int = 25
    profile_update_max_risk: float = 29.0
    max_batch_size: int = 500
    stream_partition_count: int = 32
    random_seed: int = 42
    admin_username: str = "admin"
    admin_password: str = "admin"
    auth_secret: str = "deviance-hackathon-change-me"
    auth_token_hours: int = 8
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    @property
    def allowed_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
