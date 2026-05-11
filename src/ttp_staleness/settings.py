from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TTP_", env_file=".env", extra="ignore")

    cache_dir: Path = Path.home() / ".cache" / "ttp-staleness"
    cache_ttl_hours: int = 24
    attack_domain: str = "enterprise-attack"
    # TODO(detect-forge): `no_cache` is unused — cli.py reads only the
    # --no-cache flag, so the documented TTP_NO_CACHE env var has no effect.
    # Wire it through cli.scan (e.g. ttl = 0 if no_cache or settings.no_cache).
    no_cache: bool = False


settings = Settings()
