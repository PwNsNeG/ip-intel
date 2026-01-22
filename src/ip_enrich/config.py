from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load .env from current working directory (repo root when you run it there)
load_dotenv()


def _to_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class Settings:
    abuseipdb_api_key: str
    abuseipdb_max_age_days: int
    abuseipdb_verbose: bool
    request_timeout_seconds: int


def load_settings() -> Settings:
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    max_age_raw = os.getenv("ABUSEIPDB_MAX_AGE_DAYS", "90").strip()
    try:
        max_age = int(max_age_raw)
    except ValueError:
        max_age = 90

    # AbuseIPDB docs allow 1..365; keep it safe
    max_age = max(1, min(365, max_age))

    verbose = _to_bool(os.getenv("ABUSEIPDB_VERBOSE", "false"), default=False)

    timeout_raw = os.getenv("REQUEST_TIMEOUT_SECONDS", "15").strip()
    try:
        timeout = int(timeout_raw)
    except ValueError:
        timeout = 15
    timeout = max(1, min(120, timeout))

    return Settings(
        abuseipdb_api_key=api_key,
        abuseipdb_max_age_days=max_age,
        abuseipdb_verbose=verbose,
        request_timeout_seconds=timeout,
    )

