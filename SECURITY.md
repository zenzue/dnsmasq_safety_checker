# Security Policy

## Supported use

This repository is for defensive security assessment only.

Allowed use cases:

- Checking your own Linux machine for dnsmasq package/version/process exposure.
- Checking your own router, OpenWrt, Pi-hole, LXD, or libvirt host.
- Scanning your own LAN for DNS exposure.
- Producing a report for patch planning.

Not supported:

- Exploit development.
- DoS testing.
- Cache poisoning testing.
- Malformed DNS/DHCP/DHCPv6 payload generation.
- Scanning third-party networks without authorization.

## Reporting issues

If you find a bug in this checker, open an issue with:

- OS and Python version.
- Command used.
- Sanitized output.
- Expected vs actual behavior.

Do not include secrets, public target IPs, or client data.
