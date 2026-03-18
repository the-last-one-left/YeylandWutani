#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
scan-engine.py - 11-Phase Credentialed Network Vulnerability Scan Engine

Executes a full credentialed vulnerability scan against all discovered hosts
on the local network. Phases: Recon, Host Discovery, Port Scan, NSE CVE Scripts,
SSH Scan, WMI/WinRM Scan, SNMP Scan, CVE Correlation, Config Audit,
Risk Scoring, Delta Analysis.

Install target: /opt/risk-scanner/
Service user:   risk-scanner
"""

import json
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── lib path injection ─────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from network_utils import (
    get_subnets_from_interfaces,
    get_network_interfaces,
    resolve_credential_profile,
    reverse_dns,
    get_default_gateway,
    get_dns_servers,
    classify_device,
)
from credential_store import load_credentials
from ssh_scanner import scan_host_ssh
from wmi_scanner import scan_host_wmi
from snmp_scanner import scan_host_snmp
from vuln_db import lookup_cves, is_kev, get_kev_entry, get_cvss_score, get_db_stats
from risk_scorer import score_host, score_environment, classify_host_risk, get_risk_summary
from delta_tracker import load_previous_scan, compute_delta, get_trend_data

# ── Module logger ──────────────────────────────────────────────────────────
logger = logging.getLogger(__name__)

SCANNER_VERSION = "1.0.0"

# ── Phase label constants ──────────────────────────────────────────────────
_PHASE_LABELS = {
    1:  "Reconnaissance",
    2:  "Host Discovery",
    3:  "Port Scanning",
    4:  "NSE CVE Scripts",
    5:  "Credentialed SSH Scan",
    6:  "WMI/WinRM Scan",
    7:  "SNMP Scan",
    8:  "CVE Correlation",
    9:  "Configuration Audit",
    10: "Risk Scoring",
    11: "Delta Analysis",
}


# ══════════════════════════════════════════════════════════════════════════
# Helper utilities
# ══════════════════════════════════════════════════════════════════════════

def _phase_log(phase: int) -> None:
    """Emit the standardized phase-start log line."""
    label = _PHASE_LABELS.get(phase, "Unknown")
    logger.info(f"=== RISK SCANNER — Phase {phase}/11: {label} ===")


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _filter_excluded(hosts: list, excluded: list) -> list:
    """Remove any host whose IP appears in the excluded_hosts list."""
    if not excluded:
        return hosts
    excl_set = set(excluded)
    return [h for h in hosts if h.get("ip") not in excl_set]


def _get_scanner_own_ips() -> set:
    """Return the set of IP addresses assigned to this Pi's own interfaces.
    Used to prevent the scanner from reporting on itself.
    """
    own: set = set()
    try:
        for iface in get_network_interfaces():
            ip = iface.get("ip", "")
            if ip:
                own.add(ip)
    except Exception as exc:
        logger.warning(f"Could not enumerate own IPs for self-exclusion: {exc}")
    return own


def _blank_host(ip: str, mac: str = "", vendor: str = "") -> dict:
    """Return a freshly initialised per-host result dict."""
    return {
        "ip": ip,
        "hostname": "",
        "mac": mac,
        "vendor": vendor,
        "category": "Unknown Device",
        "os_guess": "",
        "open_ports": [],
        "services": [],
        "security_flags": [],
        "credential_type":      "none",
        "auth_ports":           [],     # [{port, label}] auth-capable ports detected
        "credential_attempted": False,  # Was a credential attempted against this host?
        "credential_error":     "",     # Failure reason if auth was attempted but failed
        "os_version": "",
        "kernel_version": "",
        "installed_packages": [],
        "running_services": [],
        "cve_matches": [],
        "patch_status": {},
        "user_accounts": [],
        "ssh_config_audit": {},
        "smb_shares": [],
        "windows_firewall": {},
        "antivirus": {},
        "snmp_data": {},
        "wmi_software": [],
        "risk_score": 0,
        "risk_level": "LOW",
        "top_risks": [],
    }


def _add_security_flag(host: dict, severity: str, description: str) -> None:
    """Append a security flag to the host, avoiding exact duplicates."""
    flag = {"severity": severity, "description": description}
    if flag not in host.setdefault("security_flags", []):
        host["security_flags"].append(flag)


def _extract_service_tuples(host: dict) -> list:
    """
    Extract (vendor, product, version) tuples from all credentialed and
    unauthenticated data sources on a single host for CVE correlation.

    Sources:
      - host["services"]               nmap service version detection
      - host["installed_packages"]     SSH-collected package list
      - host["wmi_software"]           WMI-collected installed software
      - host["snmp_data"]["firmware_info"]  SNMP firmware string(s)

    Returns a list of (vendor, product, version) 3-tuples.
    All values are stripped strings; empties are preserved as "" so that
    vuln_db.lookup_cves can still attempt a product-only match.
    """
    tuples = []

    # nmap service data
    for svc in host.get("services", []):
        if not isinstance(svc, dict):
            continue
        vendor = (svc.get("vendor") or "").strip()
        product = (svc.get("product") or "").strip()
        version = (svc.get("version") or "").strip()
        if product:
            tuples.append((vendor, product, version))

    # SSH-collected packages  {"name": "openssl", "version": "1.1.1f"}
    for pkg in host.get("installed_packages", []):
        if not isinstance(pkg, dict):
            continue
        name = (pkg.get("name") or "").strip()
        version = (pkg.get("version") or "").strip()
        if name:
            tuples.append(("", name, version))

    # WMI installed software  {"name": "...", "version": "...", "publisher": "..."}
    for sw in host.get("wmi_software", []):
        if not isinstance(sw, dict):
            continue
        vendor = (sw.get("publisher") or "").strip()
        name = (sw.get("name") or "").strip()
        version = (sw.get("version") or "").strip()
        if name:
            tuples.append((vendor, name, version))

    # SNMP firmware info  {"firmware_info": {"product": "...", "version": "...", "vendor": "..."}}
    fw = host.get("snmp_data", {}).get("firmware_info", {})
    if isinstance(fw, dict) and fw:
        vendor = (fw.get("vendor") or "").strip()
        product = (fw.get("product") or "").strip()
        version = (fw.get("version") or "").strip()
        if product:
            tuples.append((vendor, product, version))

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for t in tuples:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


# ══════════════════════════════════════════════════════════════════════════
# Phase 1 — Reconnaissance
# ══════════════════════════════════════════════════════════════════════════

def _run_recon(config: dict) -> dict:
    """
    Phase 1: Discover local subnets, default gateway, DNS servers, and
    public IP information.  Apply optional human-readable subnet labels
    from config["scan"]["subnet_labels"].

    Returns:
        {
            "subnets": ["10.0.1.0/24", ...],
            "default_gateway": "10.0.0.1",
            "dns_servers": ["8.8.8.8"],
            "public_ip_info": {"ip": "...", "org": "..."},
            "subnet_labels": {"10.0.1.0/24": "Servers"}
        }
    """
    # Local subnets from active interfaces
    subnets = get_subnets_from_interfaces()

    # Default gateway
    default_gateway = ""
    try:
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            match = re.search(r"default via (\S+)", result.stdout)
            if match:
                default_gateway = match.group(1)
        if not default_gateway:
            gw = get_default_gateway()
            if gw:
                default_gateway = gw
    except Exception as exc:
        logger.warning(f"Phase 1: gateway detection failed: {exc}")

    # DNS servers from /etc/resolv.conf
    dns_servers = get_dns_servers()

    # Public IP — ipify with graceful failure
    public_ip_info: dict = {}
    try:
        import urllib.request
        with urllib.request.urlopen(
            "https://api.ipify.org?format=json", timeout=10
        ) as resp:
            public_ip_info = json.loads(resp.read().decode())
    except Exception as exc:
        logger.info(f"Phase 1: public IP lookup failed (non-fatal): {exc}")

    # Apply subnet labels from config
    subnet_labels: dict = {}
    configured_labels = config.get("scan", {}).get("subnet_labels", {})
    for subnet in subnets:
        label = configured_labels.get(subnet)
        if label:
            subnet_labels[subnet] = label

    return {
        "subnets": subnets,
        "default_gateway": default_gateway,
        "dns_servers": dns_servers,
        "public_ip_info": public_ip_info,
        "subnet_labels": subnet_labels,
    }


# ══════════════════════════════════════════════════════════════════════════
# Phase 2 — Host Discovery
# ══════════════════════════════════════════════════════════════════════════

def _parse_arp_scan(output: str) -> dict:
    """Parse arp-scan output into {ip: {mac, vendor}} dict."""
    hosts: dict = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("Interface"):
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            ip, mac, vendor = parts[0].strip(), parts[1].strip(), "\t".join(parts[2:]).strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                hosts[ip] = {"mac": mac, "vendor": vendor}
    return hosts


def _parse_fping(output: str) -> list:
    """Parse fping -a output — one live IP per line."""
    ips = []
    for line in output.splitlines():
        line = line.strip()
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", line):
            ips.append(line)
    return ips


def _parse_nmap_ping_xml(xml_str: str) -> dict:
    """Parse nmap -sn XML output into {ip: {hostname}} dict."""
    hosts: dict = {}
    try:
        root = ET.fromstring(xml_str)
        for host_el in root.findall("host"):
            if host_el.find("status") is not None:
                status = host_el.find("status").get("state", "")
                if status != "up":
                    continue
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            hostname = ""
            hn_el = host_el.find(".//hostname")
            if hn_el is not None:
                hostname = hn_el.get("name", "")
            hosts[ip] = {"hostname": hostname}
    except ET.ParseError as exc:
        logger.debug(f"nmap ping XML parse error: {exc}")
    return hosts


def _run_host_discovery(subnets: list, config: dict) -> list:
    """
    Phase 2: Discover live hosts using ARP scan, fping, and nmap ping sweep.
    Results are merged and deduplicated by IP.  DNS reverse lookup applied
    to each discovered host.

    Each host dict is initialised via _blank_host().
    """
    discovered: dict = {}  # ip -> host dict

    # ARP scan — most reliable on LAN
    try:
        result = subprocess.run(
            ["arp-scan", "--localnet", "--ignoredups"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            for ip, info in _parse_arp_scan(result.stdout).items():
                if ip not in discovered:
                    discovered[ip] = _blank_host(ip, info.get("mac", ""), info.get("vendor", ""))
                else:
                    if not discovered[ip]["mac"]:
                        discovered[ip]["mac"] = info.get("mac", "")
                    if not discovered[ip]["vendor"]:
                        discovered[ip]["vendor"] = info.get("vendor", "")
            logger.info(f"Phase 2: ARP scan found {len(discovered)} hosts")
        else:
            logger.warning(f"Phase 2: arp-scan exited {result.returncode}: {result.stderr.strip()}")
    except FileNotFoundError:
        logger.warning("Phase 2: arp-scan not found — skipping ARP discovery")
    except subprocess.TimeoutExpired:
        logger.warning("Phase 2: arp-scan timed out")
    except Exception as exc:
        logger.warning(f"Phase 2: arp-scan failed: {exc}")

    # fping sweep — one subnet at a time
    for subnet in subnets:
        try:
            result = subprocess.run(
                ["fping", "-a", "-q", "-g", subnet],
                capture_output=True, text=True, timeout=60,
            )
            # fping returns 1 if any host is unreachable — that's fine
            for ip in _parse_fping(result.stdout):
                if ip not in discovered:
                    discovered[ip] = _blank_host(ip)
        except FileNotFoundError:
            logger.debug("Phase 2: fping not found — skipping fping sweep")
            break
        except subprocess.TimeoutExpired:
            logger.warning(f"Phase 2: fping timed out for {subnet}")
        except Exception as exc:
            logger.warning(f"Phase 2: fping failed for {subnet}: {exc}")

    # nmap ping sweep — most thorough
    for subnet in subnets:
        try:
            result = subprocess.run(
                ["nmap", "-sn", "-T4", subnet, "-oX", "-"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                for ip, info in _parse_nmap_ping_xml(result.stdout).items():
                    if ip not in discovered:
                        discovered[ip] = _blank_host(ip)
                    if info.get("hostname") and not discovered[ip]["hostname"]:
                        discovered[ip]["hostname"] = info["hostname"]
        except FileNotFoundError:
            logger.warning("Phase 2: nmap not found — skipping nmap ping sweep")
            break
        except subprocess.TimeoutExpired:
            logger.warning(f"Phase 2: nmap ping sweep timed out for {subnet}")
        except Exception as exc:
            logger.warning(f"Phase 2: nmap ping sweep failed for {subnet}: {exc}")

    # DNS reverse lookup for all discovered hosts
    logger.info(f"Phase 2: Performing reverse DNS on {len(discovered)} hosts")
    for ip, host in discovered.items():
        if not host.get("hostname"):
            try:
                hostname = reverse_dns(ip, timeout=2.0)
                if hostname:
                    host["hostname"] = hostname
            except Exception:
                pass

    hosts = list(discovered.values())
    logger.info(f"Phase 2: Discovery complete — {len(hosts)} unique hosts")
    return hosts


# ══════════════════════════════════════════════════════════════════════════
# Phase 3 — Port Scanning
# ══════════════════════════════════════════════════════════════════════════

def _parse_nmap_service_xml(xml_str: str, hosts_by_ip: dict) -> dict:
    """
    Parse nmap -sV XML output.
    Returns updated hosts_by_ip dict with open_ports, services, os_guess populated.
    """
    if not xml_str or not xml_str.strip():
        # Empty output is normal for UDP scans that find no open ports or when
        # nmap lacks raw-socket privileges for the scan type — not an error.
        return hosts_by_ip
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        logger.warning(f"Phase 3: nmap XML parse error: {exc}")
        return hosts_by_ip

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") != "up":
            continue

        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if ip not in hosts_by_ip:
            continue

        host = hosts_by_ip[ip]

        # MAC address from nmap (useful if arp-scan missed it)
        mac_el = host_el.find("address[@addrtype='mac']")
        if mac_el is not None:
            mac = mac_el.get("addr", "")
            vendor = mac_el.get("vendor", "")
            if mac and not host.get("mac"):
                host["mac"] = mac
            if vendor and not host.get("vendor"):
                host["vendor"] = vendor

        # Hostname from nmap
        hn_el = host_el.find(".//hostname[@type='PTR']")
        if hn_el is None:
            hn_el = host_el.find(".//hostname")
        if hn_el is not None and not host.get("hostname"):
            host["hostname"] = hn_el.get("name", "")

        # OS guess
        os_el = host_el.find(".//osmatch")
        if os_el is not None:
            host["os_guess"] = os_el.get("name", "")

        # Ports and services
        open_ports = []
        services = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portnum = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")
                svc_el = port_el.find("service")
                svc_name = ""
                product = ""
                version = ""
                extra = ""
                svc_vendor = ""
                if svc_el is not None:
                    svc_name = svc_el.get("name", "")
                    product = svc_el.get("product", "")
                    version = svc_el.get("version", "")
                    extra = svc_el.get("extrainfo", "")
                    svc_vendor = svc_el.get("devicetype", "")

                # Banner script output
                banner = ""
                for script_el in port_el.findall("script"):
                    if script_el.get("id") == "banner":
                        banner = script_el.get("output", "")

                open_ports.append(portnum)
                services.append({
                    "port": portnum,
                    "protocol": proto,
                    "name": svc_name,
                    "product": product,
                    "version": version,
                    "extra_info": extra,
                    "vendor": svc_vendor,
                    "state": "open",
                    "banner": banner,
                })

        # Merge with any ports already found by a previous scan pass so that
        # supplemental and UDP passes add to — rather than replace — the
        # results from the main TCP top-N scan.
        existing_ports = set(host.get("open_ports", []))
        existing_services = host.get("services", [])
        existing_port_keys = {(s["port"], s.get("protocol", "tcp")) for s in existing_services}
        for svc in services:
            key = (svc["port"], svc.get("protocol", "tcp"))
            if key not in existing_port_keys:
                existing_services.append(svc)
                existing_port_keys.add(key)
        host["open_ports"] = sorted(existing_ports | set(open_ports))
        host["services"] = existing_services

    return hosts_by_ip


def _classify_host_category(host: dict) -> str:
    """Assign device category using classify_device from network_utils."""
    ports = host.get("open_ports", [])
    mac = host.get("mac", "")
    hostname = host.get("hostname", "")
    snmp_info = host.get("snmp_data") or None
    # Build version_info dict from services for richer classification
    version_info = {}
    for svc in host.get("services", []):
        port = svc.get("port")
        if port:
            version_info[port] = {
                "version": f"{svc.get('product', '')} {svc.get('version', '')}".strip()
            }
    return classify_device(ports, mac, hostname, snmp_info, version_info)


# Supplemental TCP ports always scanned regardless of --top-ports setting.
# These cover vendor management interfaces and security-relevant services that
# fall outside nmap's frequency-ranked top-N list or are commonly filtered on
# internet scans but open on internal networks.
_SUPPLEMENTAL_TCP_PORTS = [
    # Alternate HTTP/HTTPS management
    8080, 8443, 8888, 8081, 8082, 8083, 8084, 8085,
    4443, 4444, 7443, 7080, 9090, 9443, 9080,
    # Firewall / UTM vendor management (WatchGuard, Palo Alto, Fortinet, SonicWall, Cisco)
    4117, 4118,       # WatchGuard management
    4440,             # WatchGuard / Rundeck
    843,              # Palo Alto GlobalProtect
    10443,            # Fortinet
    8888, 8080,       # SonicWall / generic
    # Network management
    10000,            # Webmin
    8834,             # Nessus
    9000, 9001, 9002, # Portainer, Minio, misc
    5000, 5001,       # Docker / misc
    3000,             # Grafana / Node dev
    6443,             # Kubernetes API
    # Databases (often missed behind firewalls)
    1521,             # Oracle
    1433,             # MSSQL (in top-1000 but ensure)
    5432,             # PostgreSQL
    27017, 27018,     # MongoDB
    6379,             # Redis
    9200, 9300,       # Elasticsearch
    8123,             # ClickHouse
    # Alternate SSH / remote access
    2222, 2200, 8022,
    4899,             # Radmin
    5900, 5901, 5902, # VNC
    # Industrial / OT
    102,              # Siemens S7
    502,              # Modbus
    44818,            # EtherNet/IP
    20000,            # DNP3
    # Misc security-relevant
    8161,             # ActiveMQ
    61616,            # ActiveMQ
    11211,            # Memcached
    2181,             # ZooKeeper
    9092,             # Kafka
]
# Deduplicate and sort for clean nmap argument
_SUPPLEMENTAL_TCP_PORTS = sorted(set(_SUPPLEMENTAL_TCP_PORTS))

# Key UDP ports — TCP-only scanning misses these entirely
_UDP_PORTS = [53, 67, 69, 123, 137, 161, 162, 500, 514, 1194, 4500, 5353]


def _run_port_scan(hosts: list, config: dict) -> list:
    """
    Phase 3: Service-version port scan with nmap.
    Runs two passes:
      1. TCP: --top-ports N (frequency-ranked) PLUS supplemental management/security ports
      2. UDP: key UDP ports (SNMP, DNS, NTP, NetBIOS, IKE, Syslog, VPN)
    Populates open_ports, services, os_guess, and category for each host.
    """
    if not hosts:
        return hosts

    scan_cfg = config.get("scan", {})
    top_ports = scan_cfg.get("port_scan_top_ports", 1000)
    full_scan  = scan_cfg.get("port_scan_full", False)
    enable_udp = scan_cfg.get("port_scan_udp", True)

    target_ips = [h["ip"] for h in hosts]
    hosts_by_ip = {h["ip"]: h for h in hosts}

    logger.info(
        f"Phase 3: Scanning {len(target_ips)} hosts — "
        f"TCP {'full -p-' if full_scan else f'top-{top_ports} + {len(_SUPPLEMENTAL_TCP_PORTS)} supplemental'}, "
        f"UDP {'enabled' if enable_udp else 'disabled'}"
    )

    # ── Pass 1: TCP scan ───────────────────────────────────────────────────
    if full_scan:
        tcp_port_arg = ["-p-"]
    else:
        # Combine nmap's top-N with supplemental ports in a single -p argument
        # so only one scan pass is needed. Format: "T:8080,8443,..." appended
        # to --top-ports causes nmap to scan both sets.
        # nmap doesn't support --top-ports + -p together, so we build an
        # explicit port string: comma-joined supplemental ports plus the top-N
        # via a separate invocation, results merged below.
        tcp_port_arg = ["--top-ports", str(top_ports)]

    tcp_cmd = ["nmap", "-sV", "--version-intensity", "5", "-T4"] + tcp_port_arg
    tcp_cmd += ["--script=banner", "-oX", "-"] + target_ips

    try:
        tcp_result = subprocess.run(tcp_cmd, capture_output=True, text=True, timeout=1800)
        if tcp_result.returncode not in (0, 1):
            logger.warning(f"Phase 3: TCP nmap exited {tcp_result.returncode}: {tcp_result.stderr[:200]}")
        _parse_nmap_service_xml(tcp_result.stdout, hosts_by_ip)
    except subprocess.TimeoutExpired:
        logger.warning("Phase 3: TCP nmap scan timed out")
    except FileNotFoundError:
        logger.error("Phase 3: nmap not found — port scan skipped")
        return hosts
    except Exception as exc:
        logger.error(f"Phase 3: TCP nmap failed: {exc}")

    # ── Pass 1b: Supplemental TCP ports (management/vendor ports) ──────────
    if not full_scan:
        supp_str = ",".join(str(p) for p in _SUPPLEMENTAL_TCP_PORTS)
        supp_cmd = ["nmap", "-sV", "--version-intensity", "3", "-T4",
                    "-p", supp_str, "--script=banner", "-oX", "-"] + target_ips
        try:
            supp_result = subprocess.run(supp_cmd, capture_output=True, text=True, timeout=600)
            if supp_result.returncode not in (0, 1):
                logger.warning(f"Phase 3: supplemental nmap exited {supp_result.returncode}")
            _parse_nmap_service_xml(supp_result.stdout, hosts_by_ip)
            logger.info("Phase 3: Supplemental TCP port scan complete")
        except subprocess.TimeoutExpired:
            logger.warning("Phase 3: Supplemental TCP scan timed out")
        except Exception as exc:
            logger.warning(f"Phase 3: Supplemental TCP scan failed: {exc}")

    # ── Pass 2: UDP scan for key ports ─────────────────────────────────────
    if enable_udp:
        udp_str = ",".join(str(p) for p in _UDP_PORTS)
        udp_cmd = ["nmap", "-sU", "-sV", "--version-intensity", "3", "-T4",
                   "-p", udp_str, "--open", "-oX", "-"] + target_ips
        try:
            udp_result = subprocess.run(udp_cmd, capture_output=True, text=True, timeout=600)
            if udp_result.returncode not in (0, 1):
                logger.warning(f"Phase 3: UDP nmap exited {udp_result.returncode}: {udp_result.stderr[:200]}")
            _parse_nmap_service_xml(udp_result.stdout, hosts_by_ip)
            logger.info("Phase 3: UDP port scan complete")
        except subprocess.TimeoutExpired:
            logger.warning("Phase 3: UDP scan timed out")
        except Exception as exc:
            logger.warning(f"Phase 3: UDP scan failed: {exc}")

    # ── Post-scan: categorise, annotate auth ports, flag filtered hosts ────
    _AUTH_PORT_LABELS = {
        22:   "SSH",
        445:  "SMB/WMI",
        135:  "WMI-DCOM",
        5985: "WinRM",
        5986: "WinRM-SSL",
        161:  "SNMP",
    }
    zero_port_hosts = 0
    for host in hosts:
        host["category"] = _classify_host_category(host)
        host["auth_ports"] = [
            {"port": p, "label": _AUTH_PORT_LABELS[p]}
            for p in host.get("open_ports", [])
            if p in _AUTH_PORT_LABELS
        ]
        # Flag hosts that responded to discovery but show zero open ports —
        # this usually means a host-based firewall or appliance is filtering
        # the scan rather than genuinely having no services.
        if not host.get("open_ports"):
            zero_port_hosts += 1
            host.setdefault("security_flags", []).append({
                "severity": "INFO",
                "description": (
                    "No open ports detected — host may be filtering port scans "
                    "(host-based firewall or network appliance). "
                    "Consider whitelisting the scanner IP for accurate assessment."
                ),
            })

    open_count = sum(1 for h in hosts if h["open_ports"])
    logger.info(
        f"Phase 3: Port scan complete — {open_count} hosts with open ports, "
        f"{zero_port_hosts} hosts appear filtered"
    )
    return hosts


# ══════════════════════════════════════════════════════════════════════════
# Phase 4 — NSE CVE Scripts
# ══════════════════════════════════════════════════════════════════════════

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _parse_nse_vulners_xml(xml_str: str, hosts_by_ip: dict) -> dict:
    """
    Parse nmap --script=vulners XML output.
    Seeds host["cve_matches"] with CVE IDs extracted from NSE script output.
    Also builds (vendor, product, version) tuples per host for Phase 8.
    """
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        logger.debug(f"Phase 4: NSE XML parse error: {exc}")
        return hosts_by_ip

    for host_el in root.findall("host"):
        addr_el = host_el.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if ip not in hosts_by_ip:
            continue
        host = hosts_by_ip[ip]

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            for script_el in port_el.findall("script"):
                if script_el.get("id") != "vulners":
                    continue
                output = script_el.get("output", "")
                cve_ids = set(_CVE_RE.findall(output))
                existing_ids = {c["cve_id"] for c in host.get("cve_matches", [])}
                for cve_id in cve_ids:
                    if cve_id.upper() not in existing_ids:
                        host["cve_matches"].append({
                            "cve_id": cve_id.upper(),
                            "cvss_v3_score": 0.0,
                            "severity": "UNKNOWN",
                            "kev": False,
                            "product": "",
                            "description": "(from NSE vulners script)",
                            "fix_available": False,
                            "source": "nse",
                        })
                        existing_ids.add(cve_id.upper())

    return hosts_by_ip


def _run_nse_scripts(hosts: list, config: dict) -> list:
    """
    Phase 4: Run nmap --script=vulners on hosts with open ports.
    Seeds initial CVE matches and extracts service tuples.
    """
    if not config.get("scan", {}).get("enable_nse_vulners", True):
        logger.info("Phase 4: NSE vulners disabled in config — skipping")
        return hosts

    # Only scan hosts that actually have open ports
    scan_targets = [h["ip"] for h in hosts if h.get("open_ports")]
    if not scan_targets:
        logger.info("Phase 4: No hosts with open ports — skipping NSE scripts")
        return hosts

    cmd = [
        "nmap", "-sV", "--version-intensity", "3", "-T4",
        "--script=vulners", "-oX", "-",
    ] + scan_targets

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except subprocess.TimeoutExpired:
        logger.warning("Phase 4: NSE vulners scan timed out")
        return hosts
    except FileNotFoundError:
        logger.warning("Phase 4: nmap not found — NSE scripts skipped")
        return hosts
    except Exception as exc:
        logger.warning(f"Phase 4: NSE vulners failed: {exc}")
        return hosts

    hosts_by_ip = {h["ip"]: h for h in hosts}
    _parse_nse_vulners_xml(result.stdout, hosts_by_ip)

    seeded = sum(1 for h in hosts if h.get("cve_matches"))
    logger.info(f"Phase 4: NSE vulners complete — {seeded} hosts with seeded CVEs")
    return hosts


# ══════════════════════════════════════════════════════════════════════════
# Phase 5 — Credentialed SSH Scan
# ══════════════════════════════════════════════════════════════════════════

def _run_ssh_scans(
    hosts: list,
    credentials: list,
    config: dict,
    coverage: dict,
) -> list:
    """
    Phase 5: Attempt SSH-credentialed scan on hosts with port 22 open
    or where a credential profile explicitly targets the host.
    Uses a thread pool for parallel execution.
    """
    if not config.get("scan", {}).get("enable_ssh_scan", True):
        logger.info("Phase 5: SSH scan disabled in config — skipping")
        return hosts

    ssh_creds = [c for c in credentials if c.get("type") == "ssh"]
    # Determine candidate hosts: port 22 open, OR a host-scoped SSH profile targets it
    host_scoped_ips = {
        ip
        for cred in ssh_creds
        if cred.get("scope") == "host"
        for ip in cred.get("targets", [])
    }

    candidates = [
        h for h in hosts
        if 22 in h.get("open_ports", []) or h["ip"] in host_scoped_ips
    ]

    if not candidates:
        logger.info("Phase 5: No SSH candidates — skipping")
        return hosts

    max_workers = min(config.get("scan", {}).get("max_threads", 10), 10)
    hosts_by_ip = {h["ip"]: h for h in hosts}

    def _scan_one_ssh(host: dict):
        ip = host["ip"]
        profile = resolve_credential_profile(ip, ssh_creds)
        if not profile:
            if ip not in coverage["no_credential"]:
                coverage["no_credential"].append(ip)
            return
        try:
            hosts_by_ip[ip]["credential_attempted"] = True
            result = scan_host_ssh(ip, profile)
            _merge_dict(hosts_by_ip[ip], result)
            if result.get("ssh_success"):
                hosts_by_ip[ip]["credential_type"] = "ssh"
                coverage["ssh_success"].append(ip)
            else:
                err = result.get("error") or "Authentication failed"
                hosts_by_ip[ip]["credential_error"] = err
                coverage["ssh_failed"].append(ip)
        except Exception as exc:
            logger.warning(f"Phase 5: SSH scan failed for {ip}: {exc}")
            hosts_by_ip[ip]["credential_attempted"] = True
            hosts_by_ip[ip]["credential_error"] = str(exc)
            coverage["ssh_failed"].append(ip)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_one_ssh, h): h["ip"] for h in candidates}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                future.result()
            except Exception as exc:
                logger.warning(f"Phase 5: thread exception for {ip}: {exc}")

    success_count = len(coverage["ssh_success"])
    fail_count = len(coverage["ssh_failed"])
    logger.info(f"Phase 5: SSH scan complete — success:{success_count} failed:{fail_count}")
    return list(hosts_by_ip.values())


# ══════════════════════════════════════════════════════════════════════════
# Phase 6 — WMI / WinRM Scan
# ══════════════════════════════════════════════════════════════════════════

_WMI_PORTS = {135, 445, 3389, 5985, 5986}
_WMI_CATEGORIES = {"Windows Workstation", "Windows Server", "Windows Device",
                   "Domain Controller"}


def _run_wmi_scans(
    hosts: list,
    credentials: list,
    config: dict,
    coverage: dict,
) -> list:
    """
    Phase 6: WMI/WinRM credentialed scan on Windows hosts.
    """
    if not config.get("scan", {}).get("enable_wmi_scan", True):
        logger.info("Phase 6: WMI scan disabled in config — skipping")
        return hosts

    wmi_creds = [c for c in credentials if c.get("type") == "wmi"]
    candidates = [
        h for h in hosts
        if bool(set(h.get("open_ports", [])) & _WMI_PORTS)
        # If the port scan found ports but none are WMI ports, skip — don't
        # waste a 30-second timeout on a host that is definitely not running
        # WinRM/WMI.  Only fall back to category-based selection when the
        # port scan found *nothing* (host may be filtering scans).
        or (h.get("category") in _WMI_CATEGORIES and not h.get("open_ports"))
    ]

    if not candidates:
        logger.info("Phase 6: No WMI candidates — skipping")
        return hosts

    max_workers = min(config.get("scan", {}).get("max_threads", 10), 10)
    hosts_by_ip = {h["ip"]: h for h in hosts}

    def _scan_one_wmi(host: dict):
        ip = host["ip"]
        profile = resolve_credential_profile(ip, wmi_creds)
        if not profile:
            # Do not double-count as no_credential if SSH already recorded it
            return
        try:
            hosts_by_ip[ip]["credential_attempted"] = True
            result = scan_host_wmi(ip, profile)
            _merge_dict(hosts_by_ip[ip], result)
            if result.get("wmi_success"):
                if hosts_by_ip[ip].get("credential_type") == "none":
                    hosts_by_ip[ip]["credential_type"] = "wmi"
                coverage["wmi_success"].append(ip)
            else:
                if not hosts_by_ip[ip].get("credential_error"):
                    err = result.get("error") or "WMI/WinRM authentication failed"
                    hosts_by_ip[ip]["credential_error"] = err
                coverage["wmi_failed"].append(ip)
        except Exception as exc:
            logger.warning(f"Phase 6: WMI scan failed for {ip}: {exc}")
            hosts_by_ip[ip]["credential_attempted"] = True
            if not hosts_by_ip[ip].get("credential_error"):
                hosts_by_ip[ip]["credential_error"] = str(exc)
            coverage["wmi_failed"].append(ip)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_one_wmi, h): h["ip"] for h in candidates}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                future.result()
            except Exception as exc:
                logger.warning(f"Phase 6: thread exception for {ip}: {exc}")

    success_count = len(coverage["wmi_success"])
    fail_count = len(coverage["wmi_failed"])
    logger.info(f"Phase 6: WMI scan complete — success:{success_count} failed:{fail_count}")
    return list(hosts_by_ip.values())


# ══════════════════════════════════════════════════════════════════════════
# Phase 7 — SNMP Scan
# ══════════════════════════════════════════════════════════════════════════

_SNMP_CATEGORIES = {"Network Switch", "Network Infrastructure", "Firewall",
                    "Wireless Access Point", "Printer", "UPS / Power Device",
                    "IP Camera / NVR"}


def _run_snmp_scans(
    hosts: list,
    credentials: list,
    config: dict,
    coverage: dict,
) -> list:
    """
    Phase 7: SNMP scan on network devices and any host with port 161 open.
    profile=None is acceptable — snmp_scanner falls back to default community.
    """
    if not config.get("scan", {}).get("enable_snmp_scan", True):
        logger.info("Phase 7: SNMP scan disabled in config — skipping")
        return hosts

    snmp_creds = [c for c in credentials if c.get("type") in ("snmp_v2c", "snmp_v3")]
    candidates = [
        h for h in hosts
        if 161 in h.get("open_ports", []) or h.get("category") in _SNMP_CATEGORIES
    ]

    if not candidates:
        logger.info("Phase 7: No SNMP candidates — skipping")
        return hosts

    max_workers = min(config.get("scan", {}).get("max_threads", 10), 10)
    hosts_by_ip = {h["ip"]: h for h in hosts}

    def _scan_one_snmp(host: dict):
        ip = host["ip"]
        profile = resolve_credential_profile(ip, snmp_creds) or None
        try:
            result = scan_host_snmp(ip, profile)
            if result and result.get("snmp_success"):
                _merge_dict(hosts_by_ip[ip], result)
                if hosts_by_ip[ip].get("credential_type") == "none":
                    hosts_by_ip[ip]["credential_type"] = "snmp"
                coverage["snmp_success"].append(ip)
                # Re-classify now that we have richer SNMP data
                hosts_by_ip[ip]["category"] = _classify_host_category(hosts_by_ip[ip])
            else:
                coverage["snmp_failed"].append(ip)
        except Exception as exc:
            logger.warning(f"Phase 7: SNMP scan failed for {ip}: {exc}")
            coverage["snmp_failed"].append(ip)

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_scan_one_snmp, h): h["ip"] for h in candidates}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                future.result()
            except Exception as exc:
                logger.warning(f"Phase 7: thread exception for {ip}: {exc}")

    success_count = len(coverage["snmp_success"])
    fail_count = len(coverage["snmp_failed"])
    logger.info(f"Phase 7: SNMP scan complete — success:{success_count} failed:{fail_count}")
    return list(hosts_by_ip.values())


# ══════════════════════════════════════════════════════════════════════════
# Phase 8 — CVE Correlation
# ══════════════════════════════════════════════════════════════════════════

def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFORMATIONAL"


def _run_cve_correlation(hosts: list, config: dict) -> list:
    """
    Phase 8: Correlate service/package/software/firmware data against the
    local NVD/CVE database for every host.  Merges with any NSE-seeded CVEs,
    deduplicates, enriches with KEV data, sorts and caps per host.
    """
    if not config.get("scan", {}).get("enable_cve_correlation", True):
        logger.info("Phase 8: CVE correlation disabled in config — skipping")
        return hosts

    max_cves = config.get("vulnerability", {}).get("max_cves_per_host", 50)
    total_new = 0

    for host in hosts:
        tuples = _extract_service_tuples(host)
        if not tuples:
            continue

        existing_ids = {c["cve_id"] for c in host.get("cve_matches", [])}
        new_cves: list = []

        for vendor, product, version in tuples:
            if not product:
                continue
            try:
                cves = lookup_cves(vendor, product, version)
            except Exception as exc:
                logger.debug(f"Phase 8: lookup_cves failed ({vendor},{product},{version}): {exc}")
                continue

            for cve in cves:
                cve_id = (cve.get("cve_id") or "").upper()
                if not cve_id or cve_id in existing_ids:
                    continue
                existing_ids.add(cve_id)

                score = float(cve.get("cvss_v3_score") or get_cvss_score(cve_id) or 0.0)
                kev_flag = bool(cve.get("kev") or is_kev(cve_id))
                kev_entry = {}
                if kev_flag:
                    try:
                        kev_entry = get_kev_entry(cve_id) or {}
                    except Exception:
                        pass

                entry = {
                    "cve_id": cve_id,
                    "cvss_v3_score": score,
                    "severity": _severity_from_score(score),
                    "kev": kev_flag,
                    "product": f"{product} {version}".strip(),
                    "description": cve.get("description", ""),
                    "fix_available": bool(cve.get("fix_available", False)),
                    "source": "vuln_db",
                }
                if kev_entry:
                    entry["kev_due_date"] = kev_entry.get("due_date", "")
                    entry["kev_ransomware"] = kev_entry.get("known_ransomware_campaign_use", "")
                new_cves.append(entry)
                total_new += 1

        # Merge new CVEs with any NSE-seeded stubs (enrich stubs in-place)
        nse_stubs = {c["cve_id"]: c for c in host.get("cve_matches", []) if c.get("source") == "nse"}
        for entry in new_cves:
            if entry["cve_id"] in nse_stubs:
                # Enrich the NSE stub with real data
                nse_stubs[entry["cve_id"]].update(entry)
            else:
                host["cve_matches"].append(entry)

        # Enrich any remaining un-enriched NSE stubs with score lookup
        for cve_id, stub in nse_stubs.items():
            if stub.get("cvss_v3_score", 0.0) == 0.0:
                try:
                    score = float(get_cvss_score(cve_id) or 0.0)
                    stub["cvss_v3_score"] = score
                    stub["severity"] = _severity_from_score(score)
                    stub["kev"] = is_kev(cve_id)
                except Exception:
                    pass

        # Sort: KEV first, then by cvss_v3_score descending
        host["cve_matches"].sort(
            key=lambda c: (0 if c.get("kev") else 1, -float(c.get("cvss_v3_score") or 0))
        )

        # Cap
        if len(host["cve_matches"]) > max_cves:
            host["cve_matches"] = host["cve_matches"][:max_cves]

    logger.info(f"Phase 8: CVE correlation complete — {total_new} new CVE matches added")
    return hosts


# ══════════════════════════════════════════════════════════════════════════
# Phase 9 — Configuration Audit
# ══════════════════════════════════════════════════════════════════════════

_SSL_PORTS = {443, 8443, 465, 993, 995}
_WEB_PORTS_HTTP = {80, 8080}


def _check_ssl_cert(ip: str, port: int) -> list:
    """
    Attempt TLS connection and return a list of security flags based on:
    expired cert, soon-to-expire cert (<30 days), self-signed cert,
    and deprecated TLS version (1.0/1.1).
    """
    flags = []
    try:
        # Build a permissive context so we can inspect even bad certs
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL

        conn = ctx.wrap_socket(
            socket.create_connection((ip, port), timeout=5),
            server_hostname=ip,
        )
        try:
            cert = conn.getpeercert()
            tls_version = conn.version()

            # TLS version check
            if tls_version in ("TLSv1", "TLSv1.1"):
                flags.append({
                    "severity": "MEDIUM",
                    "description": f"Port {port}: Deprecated TLS version {tls_version} in use",
                })

            if cert:
                import datetime
                # Certificate expiry
                not_after_str = cert.get("notAfter", "")
                if not_after_str:
                    not_after = datetime.datetime.strptime(
                        not_after_str, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=timezone.utc)
                    now = datetime.datetime.now(timezone.utc)
                    days_remaining = (not_after - now).days
                    if days_remaining < 0:
                        flags.append({
                            "severity": "CRITICAL",
                            "description": (
                                f"Port {port}: TLS certificate EXPIRED "
                                f"{abs(days_remaining)} days ago"
                            ),
                        })
                    elif days_remaining <= 30:
                        flags.append({
                            "severity": "HIGH",
                            "description": (
                                f"Port {port}: TLS certificate expiring in "
                                f"{days_remaining} days"
                            ),
                        })

                # Self-signed check: issuer == subject
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                if issuer and issuer == subject:
                    flags.append({
                        "severity": "MEDIUM",
                        "description": f"Port {port}: Self-signed TLS certificate",
                    })
        finally:
            conn.close()

    except ssl.SSLError as exc:
        flags.append({
            "severity": "MEDIUM",
            "description": f"Port {port}: SSL/TLS error — {exc.reason or str(exc)}",
        })
    except (ConnectionRefusedError, OSError, socket.timeout):
        pass  # Port not open or timed out — not a finding
    except Exception as exc:
        logger.debug(f"SSL audit {ip}:{port}: {exc}")

    return flags


def _check_smb(ip: str) -> list:
    """Run nmap SMB security scripts and return security flags."""
    flags = []
    try:
        result = subprocess.run(
            [
                "nmap", "-p", "445", "--script",
                "smb-security-mode,smb-vuln-ms17-010,smb2-security-mode",
                "-oX", "-", ip,
            ],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode not in (0, 1):
            return flags

        output_lower = result.stdout.lower()

        if "ms17-010" in output_lower and "vulnerable" in output_lower:
            flags.append({
                "severity": "CRITICAL",
                "description": "EternalBlue (MS17-010) vulnerability detected — patch immediately",
            })

        if "message signing enabled but not required" in output_lower:
            flags.append({
                "severity": "MEDIUM",
                "description": "SMB signing not required — susceptible to relay attacks",
            })

        if "authentication level: user" not in output_lower and "smb-security-mode" in output_lower:
            if "guest" in output_lower or "share" in output_lower:
                flags.append({
                    "severity": "HIGH",
                    "description": "SMB share-level or guest authentication enabled",
                })

    except subprocess.TimeoutExpired:
        logger.debug(f"SMB audit timed out for {ip}")
    except FileNotFoundError:
        logger.debug("nmap not found for SMB audit")
    except Exception as exc:
        logger.debug(f"SMB audit {ip}: {exc}")
    return flags


def _check_web_admin(ip: str, port: int) -> list:
    """HTTP GET to detect unauthenticated web admin interface."""
    flags = []
    try:
        import urllib.request
        url = f"http://{ip}:{port}/"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                flags.append({
                    "severity": "MEDIUM",
                    "description": (
                        f"Port {port}: Unauthenticated web interface accessible "
                        f"(HTTP 200 without credentials)"
                    ),
                })
    except Exception:
        pass
    return flags


def _check_ftp_anon(ip: str) -> list:
    """Attempt FTP anonymous login via raw socket."""
    flags = []
    try:
        s = socket.create_connection((ip, 21), timeout=5)
        banner = s.recv(1024).decode(errors="replace")
        s.sendall(b"USER anonymous\r\n")
        resp = s.recv(1024).decode(errors="replace")
        s.sendall(b"PASS scanner@yeyland.com\r\n")
        resp2 = s.recv(1024).decode(errors="replace")
        s.close()
        if resp2.startswith("230"):
            flags.append({
                "severity": "HIGH",
                "description": "FTP anonymous login accepted — unauthenticated file access possible",
            })
    except Exception:
        pass
    return flags


def _run_config_audit(hosts: list, config: dict) -> list:
    """
    Phase 9: SSL/TLS certificate audit, SMB security mode, web admin
    detection, Telnet flagging, and FTP anonymous login check.
    """
    scan_cfg = config.get("scan", {})
    enable_ssl = scan_cfg.get("enable_ssl_audit", True)
    enable_smb = scan_cfg.get("enable_smb_audit", True)

    for host in hosts:
        ports_set = set(host.get("open_ports", []))
        ip = host["ip"]

        # SSL/TLS audit
        if enable_ssl:
            for port in _SSL_PORTS:
                if port in ports_set:
                    flags = _check_ssl_cert(ip, port)
                    for flag in flags:
                        _add_security_flag(host, flag["severity"], flag["description"])

        # SMB security audit
        if enable_smb and 445 in ports_set:
            for flag in _check_smb(ip):
                _add_security_flag(host, flag["severity"], flag["description"])

        # Web admin detection
        for port in _WEB_PORTS_HTTP:
            if port in ports_set:
                for flag in _check_web_admin(ip, port):
                    _add_security_flag(host, flag["severity"], flag["description"])

        # Telnet
        if 23 in ports_set:
            _add_security_flag(
                host, "HIGH",
                "Port 23 (Telnet) open — cleartext remote access protocol in use"
            )

        # FTP anonymous login
        if 21 in ports_set:
            for flag in _check_ftp_anon(ip):
                _add_security_flag(host, flag["severity"], flag["description"])

    logger.info("Phase 9: Configuration audit complete")
    return hosts


# ══════════════════════════════════════════════════════════════════════════
# Phase 10 — Risk Scoring
# ══════════════════════════════════════════════════════════════════════════

def _run_risk_scoring(hosts: list) -> tuple:
    """
    Phase 10: Score each host, classify risk level, compute environment score.
    Returns (sorted_hosts, risk_dict).
    """
    for host in hosts:
        try:
            host["risk_score"] = score_host(host)
            host["risk_level"] = classify_host_risk(host["risk_score"])
            host["top_risks"] = get_risk_summary([host])
        except Exception as exc:
            logger.warning(f"Phase 10: risk scoring failed for {host['ip']}: {exc}")
            host["risk_score"] = 0
            host["risk_level"] = "UNKNOWN"
            host["top_risks"] = []

    # Sort hosts by descending risk score
    hosts.sort(key=lambda h: h.get("risk_score", 0), reverse=True)

    # Environment-level score
    env_score = 0
    env_level = "LOW"
    try:
        env_score = score_environment(hosts)
        env_level = classify_host_risk(env_score)
    except Exception as exc:
        logger.warning(f"Phase 10: environment scoring failed: {exc}")

    risk = {
        "score": env_score,
        "level": env_level,
        "breakdown": {
            "critical_hosts": sum(1 for h in hosts if h.get("risk_level") == "CRITICAL"),
            "high_hosts": sum(1 for h in hosts if h.get("risk_level") == "HIGH"),
            "medium_hosts": sum(1 for h in hosts if h.get("risk_level") == "MEDIUM"),
            "low_hosts": sum(1 for h in hosts if h.get("risk_level") == "LOW"),
        },
    }

    logger.info(
        f"Phase 10: Risk scoring complete — "
        f"env score: {env_score} ({env_level}), "
        f"CRITICAL hosts: {risk['breakdown']['critical_hosts']}"
    )
    return hosts, risk


# ══════════════════════════════════════════════════════════════════════════
# Phase 11 — Delta Analysis
# ══════════════════════════════════════════════════════════════════════════

def _run_delta(scan_results: dict, data_dir: str) -> dict:
    """
    Phase 11: Load previous scan and compute delta (new/resolved hosts,
    new/resolved CVEs, risk trend).  Returns empty dict if no prior scan.
    """
    try:
        prev = load_previous_scan(data_dir)
    except Exception as exc:
        logger.warning(f"Phase 11: load_previous_scan failed: {exc}")
        return {}

    if not prev:
        logger.info("Phase 11: No previous scan found — delta skipped")
        return {}

    delta: dict = {}
    try:
        delta = compute_delta(scan_results, prev)
    except Exception as exc:
        logger.warning(f"Phase 11: compute_delta failed: {exc}")

    try:
        trend = get_trend_data(data_dir, weeks=12)
        delta["trend_data"] = trend
    except Exception as exc:
        logger.warning(f"Phase 11: get_trend_data failed: {exc}")

    logger.info("Phase 11: Delta analysis complete")
    return delta


# ══════════════════════════════════════════════════════════════════════════
# Merge helper
# ══════════════════════════════════════════════════════════════════════════

def _merge_dict(base: dict, update: dict) -> None:
    """
    Merge update into base in-place.  List fields are extended rather than
    replaced to preserve data from earlier phases.  None values in update
    do not overwrite existing data.
    """
    _LIST_FIELDS = {
        "open_ports", "services", "security_flags", "cve_matches",
        "installed_packages", "running_services", "user_accounts",
        "smb_shares", "wmi_software",
    }
    for key, value in update.items():
        if value is None:
            continue
        if key in _LIST_FIELDS and isinstance(value, list):
            existing = base.setdefault(key, [])
            # Deduplicate simple primitives; for dicts just extend
            if value and isinstance(value[0], dict):
                existing.extend(value)
            else:
                for item in value:
                    if item not in existing:
                        existing.append(item)
        elif key == "snmp_data" and isinstance(value, dict):
            base.setdefault("snmp_data", {}).update(value)
        else:
            if value != "" or not base.get(key):
                base[key] = value


# ══════════════════════════════════════════════════════════════════════════
# Summary builder
# ══════════════════════════════════════════════════════════════════════════

def _build_summary(hosts: list, recon: dict) -> dict:
    """Build the top-level scan summary dict from final host list."""
    total_hosts = len(hosts)
    credentialed = sum(1 for h in hosts if h.get("credential_type") != "none")
    total_cves = sum(len(h.get("cve_matches", [])) for h in hosts)
    kev_matches = sum(
        sum(1 for c in h.get("cve_matches", []) if c.get("kev"))
        for h in hosts
    )
    total_ports = sum(len(h.get("open_ports", [])) for h in hosts)

    category_breakdown: dict = {}
    for host in hosts:
        cat = host.get("category", "Unknown Device")
        category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

    return {
        "total_hosts": total_hosts,
        "credentialed_hosts": credentialed,
        "uncredentialed_hosts": total_hosts - credentialed,
        "total_cves": total_cves,
        "kev_matches": kev_matches,
        "total_open_ports": total_ports,
        "subnets_scanned": recon.get("subnets", []),
        "category_breakdown": category_breakdown,
        "phases_completed": 0,   # updated by run_scan
        "phases_skipped": 0,     # updated by run_scan
    }


# ══════════════════════════════════════════════════════════════════════════
# Public entry point
# ══════════════════════════════════════════════════════════════════════════

def run_scan(config: dict, data_dir: str = "/opt/risk-scanner/data") -> dict:
    """
    Execute the full 11-phase credentialed vulnerability scan.

    Args:
        config:   Parsed config.json dict.
        data_dir: Path to persistent data directory (delta tracking, etc.)

    Returns:
        scan_results dict conforming to the documented schema.
    """
    scan_start = _now_iso()
    start_ts = time.monotonic()

    client_name = config.get("reporting", {}).get("client_name", "Unknown Client")
    logger.info(f"Authorized credentialed scan — client: {client_name}")
    logger.info(f"Scanner version {SCANNER_VERSION} — scan started {scan_start}")

    excluded_hosts: list = config.get("scan", {}).get("excluded_hosts", [])

    # ── Initialise scan_results skeleton ──────────────────────────────────
    scan_results: dict = {
        "scan_start": scan_start,
        "scan_end": "",
        "scanner_version": SCANNER_VERSION,
        "hosts": [],
        "summary": {},
        "reconnaissance": {},
        "delta": {},
        "risk": {"score": 0, "level": "LOW", "breakdown": {}},
        "credential_coverage": {
            "ssh_success": [],
            "ssh_failed": [],
            "wmi_success": [],
            "wmi_failed": [],
            "snmp_success": [],
            "snmp_failed": [],
            "no_credential": [],
        },
        "vuln_db_stats": {},
        "ai_insights": None,
    }

    phases_completed = 0
    phases_skipped = 0
    coverage = scan_results["credential_coverage"]

    # ── Load credentials once ─────────────────────────────────────────────
    credentials: list = []
    try:
        credentials = load_credentials()
        logger.info(f"Loaded {len(credentials)} credential profile(s)")
    except Exception as exc:
        logger.error(f"Failed to load credentials: {exc} — proceeding uncredentialed")

    # ── Load vuln DB stats ────────────────────────────────────────────────
    try:
        scan_results["vuln_db_stats"] = get_db_stats()
    except Exception as exc:
        logger.warning(f"Could not retrieve vuln DB stats: {exc}")

    # ── Phase 1: Reconnaissance ───────────────────────────────────────────
    _phase_log(1)
    recon: dict = {}
    try:
        recon = _run_recon(config)
        scan_results["reconnaissance"] = recon
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 1 failed: {exc}")
        phases_skipped += 1
        recon = {"subnets": get_subnets_from_interfaces(), "default_gateway": "",
                 "dns_servers": [], "public_ip_info": {}, "subnet_labels": {}}
        scan_results["reconnaissance"] = recon

    subnets = recon.get("subnets", [])
    if not subnets:
        logger.warning("No subnets detected — scan scope may be empty")

    # ── Phase 2: Host Discovery ───────────────────────────────────────────
    _phase_log(2)
    hosts: list = []
    own_ips: set = _get_scanner_own_ips()
    try:
        hosts = _run_host_discovery(subnets, config)
        hosts = _filter_excluded(hosts, excluded_hosts)
        # Always exclude the scanner's own IP(s) — arp-scan picks up the Pi
        # itself because it responds to ARP on the local subnet.
        before = len(hosts)
        hosts = [h for h in hosts if h.get("ip") not in own_ips]
        removed = before - len(hosts)
        if removed:
            logger.info(
                f"Phase 2: excluded {removed} self-IP(s) from results "
                f"({', '.join(sorted(own_ips))})"
            )
        scan_results["hosts"] = hosts
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 2 failed: {exc}")
        phases_skipped += 1

    if not hosts:
        logger.warning("Phase 2: No hosts discovered — subsequent phases will be empty")

    # ── Phase 3: Port Scanning ────────────────────────────────────────────
    _phase_log(3)
    try:
        hosts = _run_port_scan(hosts, config)
        hosts = _filter_excluded(hosts, excluded_hosts)
        scan_results["hosts"] = hosts
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 3 failed: {exc}")
        phases_skipped += 1

    # ── Phase 4: NSE CVE Scripts ──────────────────────────────────────────
    _phase_log(4)
    try:
        hosts = _run_nse_scripts(hosts, config)
        scan_results["hosts"] = hosts
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 4 failed: {exc}")
        phases_skipped += 1

    # ── Phase 5: Credentialed SSH Scan ────────────────────────────────────
    _phase_log(5)
    try:
        hosts = _run_ssh_scans(hosts, credentials, config, coverage)
        hosts = _filter_excluded(hosts, excluded_hosts)
        scan_results["hosts"] = hosts
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 5 failed: {exc}")
        phases_skipped += 1

    # ── Phase 6: WMI/WinRM Scan ───────────────────────────────────────────
    _phase_log(6)
    try:
        hosts = _run_wmi_scans(hosts, credentials, config, coverage)
        scan_results["hosts"] = hosts
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 6 failed: {exc}")
        phases_skipped += 1

    # ── Phase 7: SNMP Scan ────────────────────────────────────────────────
    _phase_log(7)
    try:
        hosts = _run_snmp_scans(hosts, credentials, config, coverage)
        scan_results["hosts"] = hosts
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 7 failed: {exc}")
        phases_skipped += 1

    # ── Phase 8: CVE Correlation ──────────────────────────────────────────
    _phase_log(8)
    try:
        hosts = _run_cve_correlation(hosts, config)
        scan_results["hosts"] = hosts
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 8 failed: {exc}")
        phases_skipped += 1

    # ── Phase 9: Configuration Audit ──────────────────────────────────────
    _phase_log(9)
    try:
        hosts = _run_config_audit(hosts, config)
        scan_results["hosts"] = hosts
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 9 failed: {exc}")
        phases_skipped += 1

    # ── Phase 10: Risk Scoring ────────────────────────────────────────────
    _phase_log(10)
    try:
        hosts, risk = _run_risk_scoring(hosts)
        scan_results["hosts"] = hosts
        scan_results["risk"] = risk
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 10 failed: {exc}")
        phases_skipped += 1

    # ── Phase 11: Delta Analysis ──────────────────────────────────────────
    _phase_log(11)
    try:
        if config.get("scan", {}).get("enable_delta_tracking", True):
            delta = _run_delta(scan_results, data_dir)
            scan_results["delta"] = delta
        else:
            logger.info("Phase 11: delta tracking disabled in config — skipping")
            phases_skipped += 1
        phases_completed += 1
    except Exception as exc:
        logger.error(f"Phase 11 failed: {exc}")
        phases_skipped += 1

    # ── Finalise ──────────────────────────────────────────────────────────
    scan_end = _now_iso()
    scan_results["scan_end"] = scan_end

    summary = _build_summary(hosts, recon)
    summary["phases_completed"] = phases_completed
    summary["phases_skipped"] = phases_skipped
    scan_results["summary"] = summary

    elapsed = time.monotonic() - start_ts
    logger.info(
        f"=== RISK SCANNER COMPLETE === "
        f"duration: {elapsed:.1f}s | hosts: {summary['total_hosts']} | "
        f"CVEs: {summary['total_cves']} | KEV: {summary['kev_matches']} | "
        f"phases: {phases_completed}/11 completed, {phases_skipped} skipped"
    )

    return scan_results
