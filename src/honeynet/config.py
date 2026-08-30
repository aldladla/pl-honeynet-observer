from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./data/honeynet.db"
    sensor_id: str = "local-sensor-01"
    report_pseudonym_key: str = "local-development-only"
    geoip_country_db_path: str | None = None
    geoip_asn_db_path: str | None = None
    cowrie_artifact_root: Path | None = None
    dashboard_event_limit: int = Field(default=50_000, ge=10_001, le=250_000)


@lru_cache
def get_settings() -> Settings:
    return Settings()
