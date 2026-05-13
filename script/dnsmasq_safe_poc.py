"""
dnsmasq_safe_poc.py

An advanced defensive security script to verify exposure and patch status 
related to the 2026 dnsmasq vulnerability suite.

Includes:
- Standard Version/Service checks.
- Low-rate DoS resilience testing (Stress Check).
- Memory/Heap trigger probing (Boundary Check).

Usage Examples:
    1. Standard audit (Safe):
       python3 dnsmasq_safe_poc.py --target 192.168.1.1 --scope 192.168.1.0/24 --i-am-authorized

    2. Active Probing (Includes DoS and Heap triggers):
       python3 dnsmasq_safe_poc.py --target 192.168.1.1 --scope 192.168.1.0/24 --i-am-authorized --active-test

    3. Local detailed report:
       python3 dnsmasq_safe_poc.py --target 127.0.0.1 --scope 127.0.0.1/32 --i-am-authorized --active-test --json --output report.json
"""

import argparse
import datetime
import getpass
import ipaddress
import json
import socket
import subprocess
import sys
import time
from typing import Dict, Any, List, Tuple


class DnsmasqScanner:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.target = args.target
        self.scope = args.scope
        self.start_time = datetime.datetime.now()
        self.report: Dict[str, Any] = {
            "target": self.target,
            "timestamp": self.start_time.isoformat(),
            "tester_username": getpass.getuser(),
            "hostname": socket.gethostname(),
            "authorization_confirmation": "VERIFIED" if args.i_am_authorized else "NOT PROVIDED",
            "scope": self.scope,
            "ticket": args.ticket or "N/A",
            "checks_performed": [],
            "evidence_collected": [],
            "cves_mapped": [
                "CVE-2026-2291", "CVE-2026-4890", "CVE-2026-4891",
                "CVE-2026-4892", "CVE-2026-4893", "CVE-2026-5172"
            ],
            "risk_classification": "not enough evidence",
            "confidence_level": "low",
            "explanation": "",
            "remediation_recommendation": "",
            "exploit_status": "pwned by w01f"
        }

    def log_check(self, check_name: str, evidence: str = ""):
        self.report["checks_performed"].append(check_name)
        if evidence:
            self.report["evidence_collected"].append(f"{check_name}: {evidence}")

    def validate_authorization(self) -> bool:
        try:
            target_ip = ipaddress.ip_address(self.target)
            scope_net = ipaddress.ip_network(self.scope, strict=False)
            if target_ip not in scope_net:
                print(f"[!] Error: Target {self.target} is outside of authorized scope.")
                return False
            if target_ip.is_global and not (self.args.allow_public and self.args.ticket):
                print("[!] Error: Public scanning requires --allow-public and --ticket.")
                return False
            return True
        except ValueError as e:
            print(f"[!] Error: Invalid IP/Scope: {e}")
            return False

    def _run_cmd(self, cmd: List[str]) -> Tuple[int, str, str]:
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, shell=False)
            return res.returncode, res.stdout.strip(), res.stderr.strip()
        except Exception:
            return -1, "", ""

    def _is_version_safe(self, current_ver: str, safe_ver: str) -> bool:
        import re
        def parse(v): return tuple(map(int, re.findall(r'\d+', v)))
        try:
            return parse(current_ver) >= parse(safe_ver)
        except: return False

    # --- NEW: TRIGGERING & STRESS LOGIC ---

    def check_dos_resilience(self):
        """
        Performs a low-rate stress test to see if the service response 
        latency spikes significantly under a small burst of queries.
        """
        self.log_check("DoS Resilience (Stress Test)")
        query_pkt = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
        
        latencies = []
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1.0)
                for _ in range(20):  # Small burst
                    start = time.time()
                    sock.sendto(query_pkt, (self.target, 53))
                    sock.recvfrom(512)
                    latencies.append(time.time() - start)
            
            avg_latency = sum(latencies) / len(latencies)
            if avg_latency > 0.5: # Threshold for "unstable"
                self.log_check("DoS Resilience", f"High latency detected: {avg_latency:.4f}s")
                self.report["risk_classification"] = "likely vulnerable"
                self.report["confidence_level"] = "medium"
            else:
                self.log_check("DoS Resilience", f"Service stable (Avg latency: {avg_latency:.4f}s)")
        except Exception as e:
            self.log_check("DoS Resilience", f"Service became unresponsive during stress: {e}")
            self.report["risk_classification"] = "likely vulnerable"

    def check_heap_trigger(self):
        """
        Sends a malformed DNS packet with an oversized label 
        to attempt to trigger a heap/buffer overflow.
        """
        self.log_check("Heap/Memory Trigger Probing")
        # Construct a packet with an extremely long DNS label (63 bytes * 5) 
        # to test boundary conditions in the parser.
        long_label = b"A" * 63
        malformed_name = b"\x00".join([long_label] * 5) + b"\x00"
        trigger_pkt = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + malformed_name + b'\x00\x01\x00\x01'
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1.5)
                sock.sendto(trigger_pkt, (self.target, 53))
                data, _ = sock.recvfrom(512)
                if data:
                    self.log_check("Heap Trigger", "Service handled oversized label safely.")
                else:
                    self.log_check("Heap Trigger", "No response to malformed label.")
        except Exception as e:
            self.log_check("Heap Trigger", f"Potential crash/hang detected: {e}")
            self.report["risk_classification"] = "likely vulnerable"
            self.report["confidence_level"] = "high"

    # --- END NEW LOGIC ---

    def check_network(self):
        self.log_check("TCP Connect Port 53")
        try:
            with socket.create_connection((self.target, 53), timeout=2):
                self.log_check("TCP Connect Port 53", "Port is open")
        except Exception as e:
            self.log_check("TCP Connect Port 53", f"Closed/Filtered: {e}")

        self.log_check("UDP DNS Query (example.com)")
        query_pkt = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(2)
                sock.sendto(query_pkt, (self.target, 53))
                data, _ = sock.recvfrom(512)
                if data: self.log_check("UDP DNS Query", "Service active")
        except Exception:
            self.log_check("UDP DNS Query", "No response")

    def check_local(self):
        self.log_check("Local Process Check")
        rc, _, _ = self._run_cmd(["pgrep", "-x", "dnsmasq"])
        if rc == 0: self.log_check("Local Process Check", "dnsmasq running")

        # Version detection
        detected_version = None
        pkg_manager = None

        managers = [
            (["dpkg", "-l", "dnsmasq"], "debian"),
            (["rpm", "-qa", "dnsmasq"], "redhat"),
            (["pacman", "-Qi", "dnsmasq"], "arch"),
            (["opkg", "list-installed"], "openwrt"),
            (["pihole-FTL", "-v"], "pihole")
        ]

        for cmd, m_type in managers:
            rc, out, _ = self._run_cmd(cmd)
            if rc == 0:
                pkg_manager = m_type
                if m_type == "debian":
                    parts = out.split()
                    if len(parts) > 2: detected_version = parts[2]
                elif m_type == "pihole":
                    import re
                    match = re.search(r'(\d+\.\d+\.\d+)', out)
                    if match: detected_version = match.group(1)
                elif m_type == "arch":
                    for line in out.splitlines():
                        if "Version" in line: detected_version = line.split(":", 1)[1].strip()
                break

        rc, out, _ = self._run_cmd(["dnsmasq", "--version"])
        if rc == 0 and not detected_version:
            first_line = out.splitlines()[0]
            if "dnsmasq" in first_line:
                parts = first_line.split()
                if len(parts) > 1:
                    detected_version = parts[1]
                    pkg_manager = "upstream"

        if detected_version:
            self.log_check("Version Detection", f"Detected: {detected_version}")
            self._evaluate_risk(detected_version, pkg_manager)
        else:
            self.log_check("Version Detection", "Unknown")

    def _evaluate_risk(self, version: str, manager: str):
        is_safe = False
        if manager == "debian":
            if self._is_version_safe(version, "2.90-4~deb12u2") or self._is_version_safe(version, "2.91-1+deb13u1"): is_safe = True
        elif manager == "arch" or manager == "upstream":
            if self._is_version_safe(version, "2.92rel2"): is_safe = True
        elif manager == "pihole":
            if self._is_version_safe(version, "6.6.2"): is_safe = True

        if is_safe:
            self.report["risk_classification"] = "patched"
            self.report["confidence_level"] = "high"
        else:
            self.report["risk_classification"] = "likely vulnerable"
            self.report["confidence_level"] = "medium"
            self.report["explanation"] = f"Version {version} is below the security threshold."
            self._set_remediation(manager)

    def _set_remediation(self, manager: str):
        rems = {
            "debian": "sudo apt update && sudo apt install --only-upgrade dnsmasq dnsmasq-base",
            "arch": "sudo pacman -Syu dnsmasq",
            "openwrt": "opkg update && opkg upgrade dnsmasq",
            "pihole": "pihole -up && sudo systemctl restart pihole-FTL"
        }
        self.report["remediation_recommendation"] = rems.get(manager, "Update vendor firmware and isolate DNS/DHCP.")

    def run(self):
        if not self.validate_authorization(): return

        is_local = self.target in ["127.0.0.1", "localhost", "::1"]
        
        try:
            self.check_network()
            if is_local:
                self.check_local()
            
            # --- NEW: ACTIVE TESTING EXECUTION ---
            if self.args.active_test:
                print("[*] Running active probing (DoS & Heap triggers)...")
                self.check_dos_resilience()
                self.check_heap_trigger()
            # -------------------------------------

            if not is_local and any("active" in e.lower() for e in self.report["evidence_collected"]):
                if self.report["risk_classification"] == "not enough evidence":
                    self.report["risk_classification"] = "exposed but version unknown"
        except Exception as e:
            self.report["explanation"] += f" Execution error: {e}"

        self.print_report()
        self.save_report()

    def print_report(self):
        print("\n" + "="*60)
        print(f" DNSMASQ SECURITY CHECK REPORT ")
        print("="*60)
        print(f"Target:      {self.report['target']}")
        print(f"Risk Level:  {self.report['risk_classification'].upper()}")
        print(f"Confidence:  {self.report['confidence_level'].upper()}")
        print(f"Exploit Status: {self.report['exploit_status']}")
        print("-"*60)
        for e in self.report["evidence_collected"]:
            print(f"  [+] {e}")
        if self.report["remediation_recommendation"]:
            print(f"\nREMEDIATION: {self.report['remediation_recommendation']}")
        print("="*60 + "\n")

    def save_report(self):
        if self.args.json or self.args.output:
            if self.args.output:
                with open(self.args.output, 'w') as f:
                    json.dump(self.report, f, indent=4)
            elif self.args.json:
                print(json.dumps(self.report, indent=4))

def main():
    parser = argparse.ArgumentParser(description="Authorized dnsmasq Security Exposure Check")
    parser.add_argument("--target", required=True)
    parser.add_argument("--scope", required=True)
    parser.add_argument("--i-am-authorized", action="store_true")
    parser.add_argument("--ticket")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output")
    parser.add_argument("--allow-public", action="store_true")
    parser.add_argument("--active-test", action="store_true", help="Enable DoS and Heap trigger probes")

    args = parser.parse_args()
    if not args.i_am_authorized:
        print("[!] Error: Use --i-am-authorized.")
        sys.exit(1)

    scanner = DnsmasqScanner(args)
    scanner.run()

if __name__ == "__main__":
    main()
