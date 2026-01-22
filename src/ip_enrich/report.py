from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .utils import utc_now_iso


@dataclass(frozen=True)
class Report:
    indicator: dict[str, str]
    timestamp: str
    version: str
    reverse_dns: str | None
    geo: dict[str, Any] | None
    asn: dict[str, Any] | None
    reputation: dict[str, Any]
    score: dict[str, Any]
    errors: list[str]
    raw: dict[str, Any] | None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "indicator": self.indicator,
            "timestamp": self.timestamp,
            "version": self.version,
            "reverse_dns": self.reverse_dns,
            "geo": self.geo,
            "asn": self.asn,
            "reputation": self.reputation,
            "score": self.score,
            "errors": self.errors,
        }
        if self.raw is not None:
            d["raw"] = self.raw
        return d


def new_base_report(ip: str, version: str) -> dict[str, Any]:
    return {
        "indicator": {"type": "ip", "ip": ip},
        "timestamp": utc_now_iso(),
        "version": version,
        "reverse_dns": None,
        "geo": None,
        "asn": None,
        "reputation": {},
        "score": {"total": 0, "level": "low", "reasons": []},
        "errors": [],
        "raw": {},
    }

