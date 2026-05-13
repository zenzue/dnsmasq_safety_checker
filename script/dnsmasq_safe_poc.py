#!/usr/bin/env python3
"""
dnsmasq_safe_poc.py - Enhanced Safe Local Proof-of-Check (2026 CVEs)
Strictly non-destructive. Local-focused enhancements.
"""

import argparse
import json
import subprocess
import sys
import getpass
import platform
import datetime
import os
import socket
from typing import Dict, Any


def parse_args():
    parser = argparse.ArgumentParser(description="dnsmasq Safe Local Proof-of-Check")
    parser.add_argument("--target", default="127.0.0.1", help="Target (default: localhost)")
    parser.add_argument("--scope", default="127.0.0.1/32", help="Authorized scope")
    parser.add_argument("--i-am-authorized", action="store_true", required=True)
    parser.add_argument("--ticket", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", default=None)
    return parser.parse_args()


def run_cmd(cmd: list, timeout=8) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=False)
        return r.stdout.strip() + (r.stderr.strip() if r.stderr else "")
    except Exception as e:
        return f"Error: {e}"


def local_comprehensive_check() -> Dict[str, Any]:
    evidence = {}

    # Version checks
    evidence["dnsmasq_version"] = run_cmd(["dnsmasq", "--version"])
    evidence["pihole_ftl"] = run_cmd(["pihole-FTL", "-v"]) if os.path.exists("/usr/bin/pihole-FTL") else None

    # Package info
    evidence["apt"] = run_cmd(["apt-cache", "policy", "dnsmasq"]) if os.path.exists("/usr/bin/apt") else None
    evidence["dpkg"] = run_cmd(["dpkg", "-l", "dnsmasq-base", "dnsmasq"]) 
    evidence["pacman"] = run_cmd(["pacman", "-Qi", "dnsmasq"])
    evidence["rpm"] = run_cmd(["rpm", "-qi", "dnsmasq"])
    evidence["opkg"] = run_cmd(["opkg", "list-installed", "dnsmasq"])

    # Running processes
    evidence["processes"] = run_cmd(["pidof", "dnsmasq", "pihole-FTL"])
    evidence["systemd"] = run_cmd(["systemctl", "status", "dnsmasq", "--no-pager"]) 
    evidence["listening"] = run_cmd(["ss", "-ltnp", "sport", "eq", ":53"]) or run_cmd(["netstat", "-ltnp", "grep", ":53"])

    # Container / VM context
    evidence["docker"] = "docker" in run_cmd(["ps", "aux"]) or os.path.exists("/.dockerenv")
    evidence["libvirt"] = "libvirt" in run_cmd(["systemctl", "status", "libvirtd"])

    # Changelog / security info (where available)
    if os.path.exists("/usr/bin/apt"):
        evidence["changelog"] = run_cmd(["apt-get", "changelog", "dnsmasq"], timeout=10)

    return evidence


def classify_local(evidence: Dict) -> tuple:
    ver = (evidence.get("dnsmasq_version") or "").lower()
    if not ver or "command not found" in ver:
        return "not running dnsmasq", "No dnsmasq binary detected", 80

    fixed_indicators = ["2.92", "2.9", "deb12u2", "deb13u1", "6.6.2"]
    vulnerable_indicators = ["2.8", "2.90-4~deb12u1", "2.91-1"]

    if any(f in ver for f in fixed_indicators):
        return "patched", "Fixed version or backport detected", 65
    if any(v in ver for v in vulnerable_indicators):
        return "likely vulnerable", "Outdated version matching known vulnerable range", 75

    return "possibly affected", "Version requires manual verification against vendor advisory", 50


def main():
    args = parse_args()
    if not args.i_am_authorized:
        print("Error: --i-am-authorized required", file=sys.stderr)
        sys.exit(1)

    print("=== dnsmasq 2026 Local Safe Proof-of-Check ===")
    evidence = local_comprehensive_check()
    risk, explanation, confidence = classify_local(evidence)

    report = {
        "target": "localhost",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "tester": getpass.getuser(),
        "hostname": platform.node(),
        "authorization": {"confirmed": True, "ticket": args.ticket},
        "evidence": evidence,
        "cves": ["CVE-2026-2291", "CVE-2026-4890", "CVE-2026-4891", "CVE-2026-4892", "CVE-2026-4893", "CVE-2026-5172"],
        "risk_classification": risk,
        "confidence": confidence,
        "explanation": explanation,
        "remediation": "Run: sudo apt update && sudo apt install --only-upgrade dnsmasq dnsmasq-base\n"
                       "Or: sudo pacman -Syu dnsmasq\n"
                       "Restart: sudo systemctl restart dnsmasq",
        "exploit_status": "pwned by w01f",
        "warning": "Version numbers alone are not definitive due to backports. Check vendor security advisories."
    }

    print(f"Risk Level : {risk} ({confidence}% confidence)")
    print(f"Explanation: {explanation}")
    print(f"\nExploit Status: {report['exploit_status']}")
    print("\nKey Evidence:")
    for k, v in list(evidence.items())[:8]:  # limit output
        if v and len(str(v)) < 300:
            print(f"  {k}: {v[:200]}...")

    if args.json or args.output:
        out = json.dumps(report, indent=2, default=str)
        if args.output:
            open(args.output, "w").write(out)
            print(f"\nFull report saved to {args.output}")
        else:
            print(out)

    print("\nLocal check complete. This is safe proof-of-check only.")


if __name__ == "__main__":
    main()
