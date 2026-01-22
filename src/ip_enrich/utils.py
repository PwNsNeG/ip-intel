from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def read_ips_file(path: str | Path) -> list[str]:
    p = Path(path)
    lines = p.read_text(encoding="utf-8").splitlines()
    ips: list[str] = []
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        ips.append(s)
    return ips

