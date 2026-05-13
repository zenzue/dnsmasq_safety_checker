"""Risk and remediation rules for dnsmasq CVE-2026 triage.

This module intentionally avoids exploit checks. It performs version and
exposure triage only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple

CVE_IDS = [
    "CVE-2026-2291",
    "CVE-2026-4890",
    "CVE-2026-4891",
    "CVE-2026-4892",
    "CVE-2026-4893",
    "CVE-2026-5172",
]

UPSTREAM_FIXED_VERSION = "2.92rel2"
PIHOLE_FTL_FIXED_VERSION = "6.6.2"

# Debian fixed versions from DSA-6264-1.
DEBIAN_FIXED = {
    "bookworm": "2.90-4~deb12u2",
    "trixie": "2.91-1+deb13u1",
}

SEVERITY_ORDER = {
    "LOW": 1,
    "INFO": 1,
    "MEDIUM": 2,
    "REVIEW": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


@dataclass
class Assessment:
    status: str
    severity: str
    reason: str
    recommendation: str


def _tuple_version(version: str) -> Tuple[int, int, int]:
    """Return a simple numeric tuple from strings such as 2.92rel2 or v6.6.2."""
    nums = re.findall(r"\d+", version or "")
    parts = [int(n) for n in nums[:3]]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)  # type: ignore[return-value]


def parse_dnsmasq_upstream_version(text: str) -> Optional[str]:
    """Extract upstream-ish dnsmasq version from command output or banners."""
    if not text:
        return None
    patterns = [
        r"Dnsmasq version\s+([0-9]+\.[0-9]+(?:rel[0-9]+)?)",
        r"dnsmasq[-_ ]?([0-9]+\.[0-9]+(?:rel[0-9]+)?)",
        r"\b([0-9]+\.[0-9]+(?:rel[0-9]+)?)\b",
    ]
    for pattern in patterns:
        m = re.search(pattern, text, flags=re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def parse_rel(version: str) -> Optional[int]:
    m = re.search(r"rel(\d+)", version or "", flags=re.IGNORECASE)
    if not m:
        return None
    return int(m.group(1))


def assess_upstream_dnsmasq(version: Optional[str], exposed: bool = False) -> Assessment:
    """Assess an upstream dnsmasq version string.

    Notes:
    - 2.92 is ambiguous because many binaries print only "2.92" even if the
      distribution package carries backported fixes or rel2 patches.
    - Distro package checks are preferred when available.
    """
    base_rec = (
        "Upgrade dnsmasq using your OS/vendor security updates. If building from "
        f"source, use upstream {UPSTREAM_FIXED_VERSION} or later. Restart dnsmasq, "
        "NetworkManager, libvirt/LXD networking, or the device firmware after updating."
    )
    if not version:
        if exposed:
            return Assessment(
                status="UNKNOWN_EXPOSED",
                severity="REVIEW",
                reason="DNS/DHCP service is reachable, but the dnsmasq version could not be confirmed remotely.",
                recommendation="Check the device firmware/package version directly. " + base_rec,
            )
        return Assessment(
            status="UNKNOWN",
            severity="REVIEW",
            reason="dnsmasq version could not be determined.",
            recommendation="Run local package checks or verify device firmware. " + base_rec,
        )

    major_minor = _tuple_version(version)[:2]
    rel = parse_rel(version)

    if major_minor < (2, 92):
        sev = "HIGH" if exposed else "REVIEW"
        return Assessment(
            status="LIKELY_VULNERABLE_OR_UNPATCHED_VENDOR_BUILD",
            severity=sev,
            reason=f"Detected dnsmasq {version}. Upstream fixes were released in {UPSTREAM_FIXED_VERSION}; older upstream versions need vendor backports or upgrade.",
            recommendation=base_rec,
        )

    if major_minor == (2, 92):
        if rel is not None and rel >= 2:
            return Assessment(
                status="LIKELY_FIXED_UPSTREAM",
                severity="LOW",
                reason=f"Detected dnsmasq {version}, which appears to be upstream rel2 or newer.",
                recommendation="Keep package/firmware updated and restrict DNS/DHCP exposure to trusted networks.",
            )
        return Assessment(
            status="AMBIGUOUS_2_92_BUILD",
            severity="REVIEW",
            reason="Detected dnsmasq 2.92 without rel/build metadata. It may or may not include the rel2 CVE patches.",
            recommendation="Check vendor package changelog/security advisory. Prefer distro package status over plain upstream version output. " + base_rec,
        )

    return Assessment(
        status="LIKELY_FIXED_NEWER_UPSTREAM",
        severity="LOW",
        reason=f"Detected dnsmasq {version}, which is newer than the first patched upstream release {UPSTREAM_FIXED_VERSION}.",
        recommendation="Keep package/firmware updated and restrict DNS/DHCP exposure to trusted networks.",
    )


def assess_pihole_ftl(version: Optional[str], exposed: bool = True) -> Assessment:
    if not version:
        return Assessment(
            status="UNKNOWN_PIHOLE_FTL",
            severity="REVIEW",
            reason="Pi-hole FTL version could not be determined.",
            recommendation="Run `pihole -up` and verify `pihole-FTL -v`. Fixed FTL version is 6.6.2 or later.",
        )
    if _tuple_version(version) >= _tuple_version(PIHOLE_FTL_FIXED_VERSION):
        return Assessment(
            status="LIKELY_FIXED_PIHOLE_FTL",
            severity="LOW",
            reason=f"Detected Pi-hole FTL {version}, which is at or above {PIHOLE_FTL_FIXED_VERSION}.",
            recommendation="Keep Pi-hole updated and restrict DNS service to trusted clients.",
        )
    return Assessment(
        status="LIKELY_VULNERABLE_PIHOLE_FTL",
        severity="HIGH" if exposed else "REVIEW",
        reason=f"Detected Pi-hole FTL {version}, below fixed version {PIHOLE_FTL_FIXED_VERSION}.",
        recommendation="Run `pihole -up`, update Docker image if containerized, then restart `pihole-FTL`.",
    )


def fix_suggestions(platform_hint: str = "generic") -> list[str]:
    hint = (platform_hint or "generic").lower()
    if any(x in hint for x in ["ubuntu", "debian", "apt", "linuxmint"]):
        return [
            "sudo apt update",
            "sudo apt install --only-upgrade dnsmasq dnsmasq-base",
            "sudo systemctl restart dnsmasq 2>/dev/null || true",
            "sudo systemctl restart NetworkManager 2>/dev/null || true",
            "sudo systemctl restart libvirtd 2>/dev/null || true",
            "sudo snap refresh lxd 2>/dev/null || true",
        ]
    if any(x in hint for x in ["arch", "manjaro", "pacman"]):
        return [
            "sudo pacman -Syu dnsmasq",
            "sudo systemctl restart dnsmasq 2>/dev/null || true",
            "sudo systemctl restart NetworkManager 2>/dev/null || true",
            "sudo systemctl restart libvirtd 2>/dev/null || true",
        ]
    if any(x in hint for x in ["openwrt", "opkg"]):
        return [
            "opkg update",
            "opkg list-upgradable | grep dnsmasq",
            "opkg upgrade dnsmasq dnsmasq-full 2>/dev/null || opkg upgrade dnsmasq",
            "/etc/init.d/dnsmasq restart",
            "Prefer full firmware upgrade when available.",
        ]
    if "pihole" in hint or "pi-hole" in hint:
        return [
            "pihole -up",
            "sudo systemctl restart pihole-FTL",
            "For Docker: docker compose pull && docker compose up -d",
        ]
    if any(x in hint for x in ["router", "iot", "firmware"]):
        return [
            "Check exact model and firmware version in the admin UI.",
            "Upgrade to the latest vendor firmware.",
            "Disable WAN-side DNS/admin access.",
            "Restrict DNS/DHCP to trusted LAN/VLAN only.",
            "Move unpatchable IoT devices to an isolated IoT VLAN.",
        ]
    return [
        "Upgrade dnsmasq through your OS/vendor security updates.",
        f"If building upstream source, use dnsmasq {UPSTREAM_FIXED_VERSION} or later.",
        "Restart services that embed or launch dnsmasq: dnsmasq, NetworkManager, libvirt, LXD, Pi-hole FTL, router firmware.",
        "Restrict UDP/TCP 53 and DHCP/DHCPv6 services to trusted networks only.",
    ]
