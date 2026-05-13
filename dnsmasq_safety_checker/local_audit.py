"""Local host audit helpers for dnsmasq exposure and version triage."""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from .rules import (
    assess_pihole_ftl,
    assess_upstream_dnsmasq,
    fix_suggestions,
    parse_dnsmasq_upstream_version,
)


def run_cmd(cmd: List[str], timeout: int = 5) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except FileNotFoundError:
        return {"cmd": cmd, "returncode": 127, "stdout": "", "stderr": "command not found"}
    except subprocess.TimeoutExpired:
        return {"cmd": cmd, "returncode": 124, "stdout": "", "stderr": "timeout"}


def command_exists(name: str) -> bool:
    return shutil.which(name) is not None


def detect_platform() -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }
    os_release = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.rstrip().split("=", 1)
                    os_release[k] = v.strip('"')
    except FileNotFoundError:
        pass
    info["os_release"] = os_release
    return info


def get_dnsmasq_version() -> Dict[str, Any]:
    result = run_cmd(["dnsmasq", "--version"])
    version = parse_dnsmasq_upstream_version(result.get("stdout", "") + "\n" + result.get("stderr", ""))
    return {"raw": result, "version": version}


def get_pihole_ftl_version() -> Dict[str, Any]:
    result = run_cmd(["pihole-FTL", "-v"])
    text = result.get("stdout", "") + "\n" + result.get("stderr", "")
    m = re.search(r"v?([0-9]+\.[0-9]+\.[0-9]+)", text)
    return {"raw": result, "version": m.group(1) if m else None}


def get_package_info() -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    if command_exists("dpkg-query"):
        info["dpkg"] = run_cmd([
            "dpkg-query",
            "-W",
            "-f=${Package} ${Version} ${Status}\n",
            "dnsmasq",
            "dnsmasq-base",
        ])
        info["apt_policy"] = run_cmd(["apt-cache", "policy", "dnsmasq", "dnsmasq-base"], timeout=8)
    if command_exists("pacman"):
        info["pacman"] = run_cmd(["pacman", "-Q", "dnsmasq"])
    if command_exists("rpm"):
        info["rpm"] = run_cmd(["rpm", "-q", "dnsmasq"])
    if command_exists("opkg"):
        info["opkg"] = run_cmd(["opkg", "list-installed", "dnsmasq*"])
    return info


def get_running_processes() -> Dict[str, Any]:
    if command_exists("pgrep"):
        return {"pgrep": run_cmd(["pgrep", "-a", "dnsmasq"])}
    return {"ps": run_cmd(["sh", "-c", "ps aux | grep '[d]nsmasq'"])}


def get_listening_ports() -> Dict[str, Any]:
    # Prefer ss. Fallbacks are included for smaller appliances.
    if command_exists("ss"):
        return {"ss": run_cmd(["sh", "-c", "ss -lntup 2>/dev/null | grep -E '(:53|:67|:547)' || true"])}
    if command_exists("netstat"):
        return {"netstat": run_cmd(["sh", "-c", "netstat -lntup 2>/dev/null | grep -E '(:53|:67|:547)' || true"])}
    return {}


def check_nm_libvirt_lxd() -> Dict[str, Any]:
    checks: Dict[str, Any] = {}
    checks["networkmanager_dnsmasq"] = run_cmd([
        "sh",
        "-c",
        "grep -R 'dns=dnsmasq' /etc/NetworkManager/ 2>/dev/null || true",
    ])
    if command_exists("virsh"):
        checks["libvirt_networks"] = run_cmd(["virsh", "net-list", "--all"])
    if command_exists("lxc"):
        checks["lxd_networks"] = run_cmd(["lxc", "network", "list"])
    return checks


def _collect_stdout(obj: Any) -> str:
    if isinstance(obj, dict):
        chunks = []
        for key, value in obj.items():
            if key == "stdout" and isinstance(value, str):
                chunks.append(value)
            else:
                chunks.append(_collect_stdout(value))
        return "\n".join(chunks)
    if isinstance(obj, list):
        return "\n".join(_collect_stdout(item) for item in obj)
    return ""


def is_exposed_locally(port_info: Dict[str, Any], proc_info: Dict[str, Any]) -> bool:
    # Look only at command output, not command strings, otherwise `pgrep dnsmasq`
    # would create a false positive even when dnsmasq is absent.
    text = _collect_stdout(port_info) + "\n" + _collect_stdout(proc_info)
    return any(token in text for token in [":53", ":67", ":547", "dnsmasq"])


def audit_local() -> Dict[str, Any]:
    platform_info = detect_platform()
    dnsmasq_version = get_dnsmasq_version()
    pihole_version = get_pihole_ftl_version() if command_exists("pihole-FTL") else {"version": None, "raw": None}
    package_info = get_package_info()
    processes = get_running_processes()
    ports = get_listening_ports()
    extra = check_nm_libvirt_lxd()

    exposed = is_exposed_locally(ports, processes)
    dnsmasq_raw = dnsmasq_version.get("raw") or {}
    process_stdout = _collect_stdout(processes)
    package_stdout = _collect_stdout(package_info)
    if (
        not dnsmasq_version.get("version")
        and dnsmasq_raw.get("returncode") == 127
        and not process_stdout.strip()
        and "dnsmasq" not in package_stdout.lower()
    ):
        from .rules import Assessment

        assessment = Assessment(
            status="NO_DNSMASQ_DETECTED",
            severity="LOW",
            reason="No dnsmasq binary, running process, or installed package was detected by local checks.",
            recommendation="No dnsmasq-specific patch action is required on this host. Still check routers, Pi-hole, LXD/libvirt hosts, and IoT devices separately.",
        )
    else:
        assessment = assess_upstream_dnsmasq(dnsmasq_version.get("version"), exposed=exposed)

    pihole_assessment = None
    if pihole_version.get("version"):
        pihole_assessment = assess_pihole_ftl(pihole_version.get("version"), exposed=exposed)

    os_id = platform_info.get("os_release", {}).get("ID", "generic")
    os_like = platform_info.get("os_release", {}).get("ID_LIKE", "")
    platform_hint = " ".join([os_id, os_like])

    return {
        "tool": "dnsmasq-safety-checker",
        "mode": "local",
        "safe_mode": True,
        "note": "This audit does not send malformed packets or exploit payloads.",
        "platform": platform_info,
        "dnsmasq": dnsmasq_version,
        "pihole_ftl": pihole_version,
        "packages": package_info,
        "processes": processes,
        "listening_ports": ports,
        "extra_checks": extra,
        "exposed_locally": exposed,
        "assessment": asdict(assessment),
        "pihole_assessment": asdict(pihole_assessment) if pihole_assessment else None,
        "fix_suggestions": fix_suggestions(platform_hint),
    }
