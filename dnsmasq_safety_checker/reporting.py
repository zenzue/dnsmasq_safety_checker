"""Console and JSON reporting helpers."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List


def to_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def _assessment_line(a: Dict[str, Any]) -> str:
    return f"{a.get('severity', 'UNKNOWN')} / {a.get('status', 'UNKNOWN')} - {a.get('reason', '')}"


def print_local_report(report: Dict[str, Any]) -> None:
    osr = report.get("platform", {}).get("os_release", {})
    print("dnsmasq Safety Checker - Local Audit")
    print("=" * 42)
    print(f"Host OS       : {osr.get('PRETTY_NAME') or report.get('platform', {}).get('system')}")
    print(f"Safe mode     : {report.get('safe_mode')}")
    print(f"Exposed local : {report.get('exposed_locally')}")
    print()

    d = report.get("dnsmasq", {})
    print(f"dnsmasq version: {d.get('version') or 'not detected'}")
    print("Assessment     : " + _assessment_line(report.get("assessment", {})))

    pihole = report.get("pihole_assessment")
    if pihole:
        print()
        print("Pi-hole FTL    : " + str(report.get("pihole_ftl", {}).get("version")))
        print("Assessment     : " + _assessment_line(pihole))

    print("\nFix suggestions:")
    for item in report.get("fix_suggestions", []):
        print(f"  - {item}")

    print("\nUseful raw checks:")
    for section in ["processes", "listening_ports"]:
        print(f"\n[{section}]")
        print(json.dumps(report.get(section, {}), indent=2)[:3000])


def print_network_report(report: Dict[str, Any]) -> None:
    print("dnsmasq Safety Checker - Network Scan")
    print("=" * 44)
    print(f"Target       : {report.get('target')}")
    print(f"Hosts scanned: {report.get('hosts_scanned')}")
    print(f"Safe mode    : {report.get('safe_mode')}")
    print()

    findings = report.get("findings", [])
    if not findings:
        print("No DNS service responded on the scanned targets.")
        return

    for f in findings:
        print(f"Host: {f.get('host')}")
        print(f"  TCP/53 open       : {f.get('tcp_53_open')}")
        print(f"  UDP/53 answered   : {f.get('udp_probe', {}).get('udp_53_answered')}")
        print(f"  version.bind text : {f.get('udp_probe', {}).get('version_text') or 'not exposed'}")
        print(f"  dnsmasq version   : {f.get('detected_dnsmasq_version') or 'unknown'}")
        print(f"  Assessment        : {_assessment_line(f.get('assessment', {}))}")
        print("  Suggested action  : " + f.get("assessment", {}).get("recommendation", "Review manually."))
        print()
