from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _parse_iso(dt: str) -> datetime | None:
    try:
        # handles "Z" and "+00:00"
        if dt.endswith("Z"):
            dt = dt[:-1] + "+00:00"
        return datetime.fromisoformat(dt).astimezone(timezone.utc)
    except Exception:
        return None


def score_from_abuseipdb(abuse: dict[str, Any]) -> tuple[int, list[str]]:
    """
    abuse: normalized block like:
      {
        "confidence_score": int|None,
        "total_reports": int|None,
        "last_reported_at": str|None
      }
    """
    reasons: list[str] = []
    total = 0

    conf = abuse.get("confidence_score")
    if isinstance(conf, int):
        total += min(conf, 70)
        reasons.append(f"Abuse confidence score is {conf}")

    reports = abuse.get("total_reports")
    if isinstance(reports, int):
        if reports >= 50:
            total += 20
            reasons.append(f"{reports} abuse reports (>= 50)")
        elif reports >= 10:
            total += 10
            reasons.append(f"{reports} abuse reports (>= 10)")
        elif reports > 0:
            reasons.append(f"{reports} abuse reports")

    last = abuse.get("last_reported_at")
    if isinstance(last, str) and last:
        dt = _parse_iso(last)
        if dt:
            days = (datetime.now(timezone.utc) - dt).days
            if days <= 30:
                total += 10
                reasons.append("Recently reported (last 30 days)")

    total = max(0, min(total, 100))
    return total, reasons


def level_from_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"

