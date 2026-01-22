from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBError(RuntimeError):
    pass


@dataclass(frozen=True)
class AbuseIPDBResult:
    normalized: dict[str, Any]
    raw: dict[str, Any]


def fetch_abuseipdb_check(
    *,
    ip: str,
    api_key: str,
    max_age_days: int = 90,
    verbose: bool = False,
    timeout_seconds: int = 15,
) -> AbuseIPDBResult:
    """
    Calls AbuseIPDB /check endpoint and returns:
      - normalized fields for scoring/reporting
      - raw JSON response (full)
    """
    if not api_key:
        raise AbuseIPDBError("Missing ABUSEIPDB_API_KEY. Put it in .env or export it in your shell.")

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    params: dict[str, Any] = {
        "ipAddress": ip,
        "maxAgeInDays": int(max_age_days),
    }
    if verbose:
        # AbuseIPDB supports 'verbose' flag; setting to empty string is common for query flags
        params["verbose"] = ""

    try:
        resp = requests.get(ABUSEIPDB_CHECK_URL, headers=headers, params=params, timeout=timeout_seconds)
    except requests.RequestException as e:
        raise AbuseIPDBError(f"AbuseIPDB request failed: {e}") from e

    if resp.status_code == 429:
        retry_after = resp.headers.get("Retry-After")
        msg = "AbuseIPDB rate limit exceeded (HTTP 429)."
        if retry_after:
            msg += f" Retry-After: {retry_after}s."
        raise AbuseIPDBError(msg)

    if resp.status_code >= 400:
        # Keep it readable; include body snippet
        body_snippet = resp.text[:300].replace("\n", " ")
        raise AbuseIPDBError(f"AbuseIPDB HTTP {resp.status_code}: {body_snippet}")

    try:
        payload = resp.json()
    except ValueError as e:
        raise AbuseIPDBError("AbuseIPDB returned non-JSON response.") from e

    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    # Normalized fields (stable contract for scoring)
    normalized = {
        "confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "last_reported_at": data.get("lastReportedAt"),
        # optional extra context you may want later:
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "hostnames": data.get("hostnames"),
    }

    return AbuseIPDBResult(normalized=normalized, raw=payload)

