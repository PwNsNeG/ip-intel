from __future__ import annotations
from .config import load_settings
from .providers.abuseipdb import AbuseIPDBError, fetch_abuseipdb_check


import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .report import new_base_report
from .scoring import level_from_score, score_from_abuseipdb
from .utils import is_valid_ip, read_ips_file, utc_now_iso


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="ip-enrich", description="Enrich IPs with threat intel and output JSON.")
    p.add_argument("ip", nargs="?", help="Single IPv4/IPv6 address to enrich")
    p.add_argument("--file", "-f", help="Path to file with one IP per line")
    p.add_argument("--out", "-o", help="Write JSON output to a file (default: stdout)")
    p.add_argument("--no-raw", action="store_true", help="Do not include raw provider responses")
    return p.parse_args(argv)


def _write_output(out_path: str | None, payload: Any) -> None:
    text = json.dumps(payload, indent=2, sort_keys=False)
    if out_path:
        Path(out_path).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def enrich_one_ip(ip: str, include_raw: bool = True) -> dict[str, Any]:
    report = new_base_report(ip, __version__)

    settings = load_settings()

    try:
        abuse_res = fetch_abuseipdb_check(
            ip=ip,
            api_key=settings.abuseipdb_api_key,
            max_age_days=settings.abuseipdb_max_age_days,
            verbose=settings.abuseipdb_verbose,
            timeout_seconds=settings.request_timeout_seconds,
        )

        report["reputation"]["abuseipdb"] = {
            "confidence_score": abuse_res.normalized.get("confidence_score"),
            "total_reports": abuse_res.normalized.get("total_reports"),
            "last_reported_at": abuse_res.normalized.get("last_reported_at"),
            "categories": abuse_res.raw.get("data", {}).get("reports", None) if settings.abuseipdb_verbose else None,
        }

        # Score (explainable)
        total, reasons = score_from_abuseipdb(report["reputation"]["abuseipdb"])
        report["score"]["total"] = total
        report["score"]["level"] = level_from_score(total)
        report["score"]["reasons"] = reasons

        # Raw provider blob (optional)
        if report.get("raw") is not None:
            report["raw"]["abuseipdb"] = abuse_res.raw

    except AbuseIPDBError as e:
        report["errors"].append(str(e))

    if not include_raw:
        report.pop("raw", None)

    # If we had errors but no score, keep score low; reasons stay empty
    return report


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)

    if bool(args.ip) == bool(args.file):
        # either ip or file, but not both
        print("Error: Provide either a single IP or --file.", file=sys.stderr)
        return 1

    include_raw = not args.no_raw

    if args.ip:
        ip = args.ip.strip()
        if not is_valid_ip(ip):
            print(f"Error: Invalid IP: {ip}", file=sys.stderr)
            return 1
        payload = enrich_one_ip(ip, include_raw=include_raw)
        _write_output(args.out, payload)
        return 0

    # file mode
    ips = read_ips_file(args.file)
    results: list[dict[str, Any]] = []
    ok = 0
    failed = 0

    for raw in ips:
        ip = raw.strip()
        if not is_valid_ip(ip):
            failed += 1
            results.append(
                {
                    "indicator": {"type": "ip", "ip": ip},
                    "timestamp": utc_now_iso(),
                    "version": __version__,
                    "errors": [f"Invalid IP: {ip}"],
                }
            )
            continue

        try:
            r = enrich_one_ip(ip, include_raw=include_raw)
            results.append(r)
            ok += 1
        except Exception as e:
            failed += 1
            results.append(
                {
                    "indicator": {"type": "ip", "ip": ip},
                    "timestamp": utc_now_iso(),
                    "version": __version__,
                    "errors": [str(e)],
                }
            )

    payload = {
        "timestamp": utc_now_iso(),
        "version": __version__,
        "input": {"type": "file", "path": args.file, "count": len(ips)},
        "results": results,
        "stats": {"processed": len(ips), "ok": ok, "failed": failed},
    }
    _write_output(args.out, payload)
    return 0 if failed == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main())

