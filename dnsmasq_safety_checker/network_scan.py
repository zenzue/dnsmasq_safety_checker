"""Safe network scanning helpers.

The scanner uses benign DNS queries only. It does not send malformed packets,
cache poisoning attempts, DHCP lease requests, or DoS payloads.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import struct
import time
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .rules import assess_upstream_dnsmasq, fix_suggestions, parse_dnsmasq_upstream_version


def iter_targets(target: str, allow_large: bool = False) -> List[str]:
    target = target.strip()
    if not target:
        raise ValueError("target is required")
    results: List[str] = []
    for part in target.split(","):
        part = part.strip()
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 256 and not allow_large:
                raise ValueError(
                    f"Refusing to scan {len(hosts)} hosts without --allow-large. "
                    "Use smaller CIDR or explicit --allow-large for owned networks."
                )
            results.extend(str(ip) for ip in hosts)
        else:
            # Validate and normalize IP where possible; allow hostnames too.
            try:
                results.append(str(ipaddress.ip_address(part)))
            except ValueError:
                results.append(part)
    return sorted(set(results))


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _encode_qname(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")) + b"\x00"


def build_dns_query(qname: str, qtype: int = 1, qclass: int = 1) -> Tuple[int, bytes]:
    query_id = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)  # RD=1, one question
    question = _encode_qname(qname) + struct.pack("!HH", qtype, qclass)
    return query_id, header + question


def _skip_name(data: bytes, offset: int) -> int:
    jumped = False
    seen = set()
    while True:
        if offset >= len(data):
            raise ValueError("bad dns name offset")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("bad compression pointer")
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in seen:
                raise ValueError("compression loop")
            seen.add(ptr)
            offset += 2
            jumped = True
            # We only need the consumed length at the original offset, so return here.
            return offset
        if length == 0:
            return offset + 1
        offset += 1 + length
        if jumped:
            return offset


def parse_txt_answers(data: bytes, query_id: int) -> List[str]:
    if len(data) < 12:
        return []
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != query_id or not (flags & 0x8000):
        return []
    offset = 12
    for _ in range(qd):
        offset = _skip_name(data, offset) + 4
    answers: List[str] = []
    for _ in range(an):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlen]
        offset += rdlen
        if rtype == 16 and rdata:  # TXT
            pos = 0
            chunks = []
            while pos < len(rdata):
                ln = rdata[pos]
                pos += 1
                chunks.append(rdata[pos : pos + ln].decode("utf-8", errors="replace"))
                pos += ln
            answers.append("".join(chunks))
    return answers


def udp_dns_probe(host: str, timeout: float) -> Dict[str, Any]:
    """Send safe DNS probes: version.bind TXT CH, then example.com A if needed."""
    result: Dict[str, Any] = {
        "udp_53_answered": False,
        "version_bind_answered": False,
        "version_text": None,
        "normal_dns_answered": False,
        "error": None,
    }

    # Probe 1: version.bind TXT CHAOS. This is a benign version query.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        qid, payload = build_dns_query("version.bind", qtype=16, qclass=3)
        sock.sendto(payload, (host, 53))
        data, _ = sock.recvfrom(2048)
        result["udp_53_answered"] = True
        result["version_bind_answered"] = True
        txt = parse_txt_answers(data, qid)
        if txt:
            result["version_text"] = "; ".join(txt[:3])
        return result
    except socket.timeout:
        pass
    except OSError as exc:
        result["error"] = str(exc)
        return result
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # Probe 2: ordinary A query. This only confirms DNS is alive.
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        qid, payload = build_dns_query("example.com", qtype=1, qclass=1)
        sock.sendto(payload, (host, 53))
        data, _ = sock.recvfrom(2048)
        if len(data) >= 12 and data[:2] == struct.pack("!H", qid):
            result["udp_53_answered"] = True
            result["normal_dns_answered"] = True
    except socket.timeout:
        pass
    except OSError as exc:
        result["error"] = str(exc)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result


def scan_host(host: str, timeout: float = 1.0, poc: bool = False) -> Dict[str, Any]:
    tcp53 = tcp_connect(host, 53, timeout)
    udp = udp_dns_probe(host, timeout) if poc or tcp53 else udp_dns_probe(host, timeout)
    version = parse_dnsmasq_upstream_version(udp.get("version_text") or "")
    exposed = tcp53 or bool(udp.get("udp_53_answered"))
    assessment = assess_upstream_dnsmasq(version, exposed=exposed)

    return {
        "host": host,
        "safe_mode": True,
        "poc_mode": bool(poc),
        "poc_meaning": "Benign proof-of-check only: DNS reachability and optional version.bind response. No malformed/exploit packets.",
        "tcp_53_open": tcp53,
        "udp_probe": udp,
        "detected_dnsmasq_version": version,
        "exposed_dns": exposed,
        "assessment": asdict(assessment),
        "fix_suggestions": fix_suggestions("router firmware" if exposed and not version else "generic"),
    }


def scan_network(
    target: str,
    timeout: float = 1.0,
    delay: float = 0.02,
    poc: bool = False,
    allow_large: bool = False,
) -> Dict[str, Any]:
    hosts = iter_targets(target, allow_large=allow_large)
    findings: List[Dict[str, Any]] = []
    for host in hosts:
        finding = scan_host(host, timeout=timeout, poc=poc)
        if finding["exposed_dns"] or finding["tcp_53_open"]:
            findings.append(finding)
        if delay > 0:
            time.sleep(delay)
    return {
        "tool": "dnsmasq-safety-checker",
        "mode": "network",
        "target": target,
        "safe_mode": True,
        "note": "This scanner sends only benign DNS queries. It does not exploit, crash, poison cache, or request DHCP leases.",
        "hosts_scanned": len(hosts),
        "findings": findings,
    }
