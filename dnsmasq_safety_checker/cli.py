"""CLI entrypoint."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from . import __version__
from .local_audit import audit_local
from .network_scan import scan_network
from .reporting import print_local_report, print_network_report, to_json


def add_common_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    parser.add_argument("--output", "-o", help="Save full JSON report to a file")


def save_report(report: Dict[str, Any], path: str | None) -> None:
    if not path:
        return
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dnsmasq-check",
        description="Safe dnsmasq CVE-2026 exposure and version triage scanner",
    )
    parser.add_argument("--version", action="version", version=f"dnsmasq-safety-checker {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    local = sub.add_parser("local", help="Audit the current Linux/router host")
    add_common_output_args(local)

    scan = sub.add_parser("scan", help="Safely scan an owned network or host for DNS exposure")
    scan.add_argument("target", help="CIDR, IP, hostname, or comma-separated targets, e.g. 192.168.1.0/24")
    scan.add_argument("--timeout", type=float, default=1.0, help="Socket timeout per probe, default: 1.0")
    scan.add_argument("--delay", type=float, default=0.02, help="Delay between hosts, default: 0.02")
    scan.add_argument("--poc", action="store_true", help="Benign proof-of-check mode: DNS reachability + version.bind query only")
    scan.add_argument("--allow-large", action="store_true", help="Allow scanning CIDRs larger than 256 hosts")
    add_common_output_args(scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "local":
            report = audit_local()
            save_report(report, args.output)
            if args.json:
                print(to_json(report))
            else:
                print_local_report(report)
            return 0

        if args.command == "scan":
            report = scan_network(
                args.target,
                timeout=args.timeout,
                delay=args.delay,
                poc=args.poc,
                allow_large=args.allow_large,
            )
            save_report(report, args.output)
            if args.json:
                print(to_json(report))
            else:
                print_network_report(report)
            return 0

        parser.print_help()
        return 2
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
