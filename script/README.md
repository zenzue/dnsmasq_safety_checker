# dnsmasq-safe-poc

**Author:** Aung Myat Thu  
**Version:** 1.1.0

A professional-grade, non-destructive security auditing tool designed to verify exposure and patch status regarding the **2026 dnsmasq vulnerability suite**.

## Philosophy: "Proof of Check"
In this project, **PoC** stands for **Proof of Check**. Unlike traditional exploit scripts that attempt to compromise a system, this tool is designed to be safe for production environments. It focuses on identifying the presence of vulnerabilities through observation and controlled, low-impact probing.

---

## Vulnerability Context
The script targets the following CVEs (2026 suite):
* `CVE-2026-2291`
* `CVE-2026-4890`
* `CVE-2026-4891`
* `CVE-2026-4892`
* `CVE-2026-4893`
* `CVE-2026-5172`

---

## Features

### 1. Dual-Mode Inspection
* **Network Mode (Remote):** Detects active DNS services via TCP/UDP handshakes and standard queries (`example.com` and `version.bind`).
* **Local Mode (On-Box):** If run locally, the script performs deep inspection via package managers (`dpkg`, `rpm`, `pacman`, `opkg`, `pihole-FTL`) to provide high-confidence patch status.

### 2. Active Probing (Optional)
When the `--active-test` flag is used, the script performs two specialized checks:
* **DoS Resilience Test:** Sends a low-rate burst of queries to monitor for latency spikes, indicating potential service instability.
* **Heap/Memory Trigger Probing:** Sends a single malformed packet with oversized DNS labels to check if the service's memory management handles boundary conditions safely.

### 3. Risk Classification
| Classification | Meaning |
| :--- | :--- |
| `patched` | Version meets or exceeds the security threshold. |
| `likely vulnerable` | Version is below the fixed threshold or service is unstable. |
| `exposed but version unknown` | Service is active, but version cannot be determined remotely. |
| `not running dnsmasq` | No dnsmasq service detected on target. |

---

## Usage

### Requirements
* Python 3.11+
* Standard library only (no `pip install` required).

### Examples

**1. Standard Passive Audit (Safest)**
Check a host within an authorized subnet without any stress testing.
```bash
python3 dnsmasq_safe_poc.py --target 192.168.1.1 --scope 192.168.1.0/24 --i-am-authorized
```

**2. Active Probing (Advanced)**
Perform DoS resilience and Heap trigger checks. Use this for higher confidence in vulnerability presence.
```bash
python3 dnsmasq_safe_poc.py --target 192.168.1.1 --scope 192.168.1.0/24 --i-am-authorized --active-test
```

**3. Compliance Reporting (JSON)**
Run locally on a target server to generate a machine-readable audit report.
```bash
python3 dnsmasq_safe_poc.py --target 127.0.0.1 --scope 127.0.0.1/32 --i-am-authorized --active-test --json --output report.json
```

---

## Remediation Quick-Reference

| Platform | Remediation Command |
| :--- | :--- |
| **Ubuntu/Debian** | `sudo apt update && sudo apt install --only-upgrade dnsmasq dnsmasq-base` |
| **Arch/Manjaro** | `sudo pacman -Syu dnsmasq` |
| **OpenWrt** | `opkg update && opkg upgrade dnsmasq` (or full firmware upgrade) |
| **Pi-hole** | `pihole -up && sudo systemctl restart pihole-FTL` |
| **IoT/Routers** | Update vendor firmware and isolate DNS/DHCP to trusted networks. |

> **⚠️ Professional Note:** Linux distributions often **backport** security fixes. A version number that appears "old" may actually be patched by your vendor. Always cross-reference findings with your specific distribution's security advisory.

---
## 📝 Disclaimer
*This tool is intended for authorized defensive auditing. Always ensure you have documented permission to scan the target network before execution.*
