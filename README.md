# dnsmasq Safety Checker

Safe, defensive Python scanner for checking dnsmasq exposure and CVE-2026 risk across Linux hosts, routers, Pi-hole, LXD/libvirt hosts, and IoT networks.

This project is intentionally **non-destructive**. It does **not** send malformed DNS packets, cache-poisoning payloads, DHCP lease requests, DHCPv6 payloads, memory-corruption probes, or denial-of-service traffic.

## What this checks

This tool helps you answer:

- Is `dnsmasq` installed locally?
- Is `dnsmasq` running?
- Is the machine listening on DNS/DHCP-related ports?
- Is Pi-hole FTL installed and below/above the known fixed release?
- Are DNS services exposed in my LAN?
- Can the scanner get a safe `version.bind` DNS response?
- What remediation commands should I run?

## CVEs covered for triage

The May 2026 dnsmasq disclosure includes:

- `CVE-2026-2291`
- `CVE-2026-4890`
- `CVE-2026-4891`
- `CVE-2026-4892`
- `CVE-2026-4893`
- `CVE-2026-5172`

Impacts reported publicly include DNS cache poisoning/redirection, denial of service, information disclosure, security-control bypass, and local privilege escalation in certain DHCPv6 conditions.

## Safety model

### Safe PoC meaning in this repo

In this repo, **PoC** means **Proof of Check**, not exploit proof-of-concept.

`--poc` mode only performs:

1. TCP connect check to port `53`.
2. UDP DNS query to `version.bind TXT CHAOS`.
3. Fallback ordinary DNS query for `example.com A`.
4. Version/risk mapping if a version is visible.

It does not prove memory corruption. It only proves that a DNS service is reachable and may need local/package verification.

### Why no exploit payload?

The relevant vulnerabilities include crash/DoS and cache poisoning classes. Sending malformed proof packets against routers, IoT devices, production resolvers, or client networks could break DNS service or alter trust. This tool stays in a defensive, non-disruptive boundary.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Or run directly:

```bash
python3 -m dnsmasq_safety_checker --help
```

## Usage

### 1. Local Linux/router audit

```bash
dnsmasq-check local
```

Save JSON report:

```bash
dnsmasq-check local --json --output reports/local-dnsmasq-report.json
```

### 2. Scan your own LAN safely

```bash
dnsmasq-check scan 192.168.1.0/24 --poc
```

Save report:

```bash
dnsmasq-check scan 192.168.1.0/24 --poc --json -o reports/lan-dnsmasq-report.json
```

Scan explicit devices:

```bash
dnsmasq-check scan 192.168.1.1,192.168.1.2,openwrt.lan --poc
```

Large networks require explicit permission:

```bash
dnsmasq-check scan 10.0.0.0/16 --poc --allow-large
```

Only scan networks you own or are authorized to test.

## Example output

```text
dnsmasq Safety Checker - Network Scan
============================================
Target       : 192.168.1.0/24
Hosts scanned: 254
Safe mode    : True

Host: 192.168.1.1
  TCP/53 open       : True
  UDP/53 answered   : True
  version.bind text : not exposed
  dnsmasq version   : unknown
  Assessment        : REVIEW / UNKNOWN_EXPOSED - DNS/DHCP service is reachable, but the dnsmasq version could not be confirmed remotely.
  Suggested action  : Check the device firmware/package version directly. Upgrade dnsmasq using your OS/vendor security updates...
```

## Fixed-version rules included

This repo includes conservative version hints:

- Upstream dnsmasq: `2.92rel2` or later.
- Debian Bookworm security package: `2.90-4~deb12u2`.
- Debian Trixie security package: `2.91-1+deb13u1`.
- Pi-hole FTL: `6.6.2` or later.

Important: many Linux distributions backport security patches while keeping older upstream version numbers. Prefer the OS security tracker/package changelog over plain `dnsmasq --version` output.

## Manual verification commands

### Ubuntu / Debian

```bash
dnsmasq --version 2>/dev/null || true
dpkg-query -W -f='${Package} ${Version} ${Status}\n' dnsmasq dnsmasq-base
apt-cache policy dnsmasq dnsmasq-base
ps aux | grep '[d]nsmasq'
ss -lntup | grep -E '(:53|:67|:547)'
```

Fix:

```bash
sudo apt update
sudo apt install --only-upgrade dnsmasq dnsmasq-base
sudo systemctl restart dnsmasq 2>/dev/null || true
sudo systemctl restart NetworkManager 2>/dev/null || true
sudo systemctl restart libvirtd 2>/dev/null || true
```

### Manjaro / Arch

```bash
dnsmasq --version 2>/dev/null || true
pacman -Qi dnsmasq
ps aux | grep '[d]nsmasq'
ss -lntup | grep -E '(:53|:67|:547)'
```

Fix:

```bash
sudo pacman -Syu dnsmasq
sudo systemctl restart dnsmasq 2>/dev/null || true
sudo systemctl restart NetworkManager 2>/dev/null || true
sudo systemctl restart libvirtd 2>/dev/null || true
```

### OpenWrt

```sh
dnsmasq --version
opkg list-installed | grep dnsmasq
ps | grep dnsmasq
netstat -lnup | grep -E '(:53|:67|:547)'
```

Fix:

```sh
opkg update
opkg list-upgradable | grep dnsmasq
opkg upgrade dnsmasq dnsmasq-full 2>/dev/null || opkg upgrade dnsmasq
/etc/init.d/dnsmasq restart
```

For many routers, a full firmware upgrade is safer than upgrading one package.

### Pi-hole

```bash
pihole -v
pihole-FTL -v
pihole status
```

Fix:

```bash
pihole -up
sudo systemctl restart pihole-FTL
```

Docker:

```bash
docker compose pull
docker compose up -d
```

### LXD / libvirt hosts

```bash
lxc network list
lxc network show lxdbr0
virsh net-list --all
ps aux | grep '[d]nsmasq'
ss -lntup | grep -E '(:53|:67|:547)'
```

Then update the host OS package and restart LXD/libvirt networking.

## IoT/router workflow

For devices without shell access:

1. Scan LAN with this tool to find devices answering DNS.
2. Login to admin panel.
3. Record model and firmware version.
4. Upgrade vendor firmware.
5. Disable DNS/admin access from WAN.
6. Keep IoT devices in a separate VLAN/guest network if they cannot be updated.

## Limitations

- Remote DNS scanning usually cannot confirm dnsmasq version.
- `version.bind` is commonly disabled or hidden.
- A device may run another DNS server, not dnsmasq.
- A distro may be patched even if upstream version output looks old.
- This tool does not test DHCPv6 memory corruption or DNSSEC crash paths.

## References

- CERT/CC VU#471747: https://www.kb.cert.org/vuls/id/471747
- Upstream dnsmasq CVE patch index: https://thekelleys.org.uk/dnsmasq/CVE/
- dnsmasq mailing list announcement: https://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2026q2/018471.html
- Debian DSA-6264-1: https://lists.debian.org/debian-security-announce/2026/msg00175.html
- Debian tracker DSA-6264-1: https://security-tracker.debian.org/tracker/DSA-6264-1
- Pi-hole FTL releases: https://github.com/pi-hole/FTL/releases

## Legal

Use only on systems and networks you own or have permission to assess.
