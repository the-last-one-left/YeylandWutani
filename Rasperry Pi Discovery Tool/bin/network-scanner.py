#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
network-scanner.py - Comprehensive Network Discovery Engine

Seventeen-phase discovery:
  Phase 1:   Network Reconnaissance
  Phase 1b:  Alternate Subnet Detection (probe common gateways)
  Phase 2:   Host Discovery (ARP + ping sweep, including additional subnets)
  Phase 3:   Port Scanning (nmap top-100 with -sV and --osscan-guess)
  Phase 4:   Service Enumeration (HTTP, SMB, SNMP enhanced, banners, NSE scripts)
  Phase 5:   Network Topology (traceroute)
  Phase 6:   Security Observations
  Phase 7:   WiFi Network Enumeration + Channel Analysis
  Phase 8:   mDNS / Bonjour Service Discovery
  Phase 9:   UPnP / SSDP Device Discovery
  Phase 10:  DHCP Scope Analysis (rogue server detection)
  Phase 11:  NTP Server Detection
  Phase 12:  802.1X / NAC Detection
  Phase 13:  OSINT / External Reconnaissance
  Phase 14:  SSL/TLS Certificate Health Audit
  Phase 15:  Backup & DR Posture Inference
  Phase 16:  End-of-Life / End-of-Support Detection
"""

import concurrent.futures
import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from network_utils import (
    classify_device,
    freq_to_band,
    freq_to_channel,
    get_default_gateway,
    get_dns_servers,
    get_hostname,
    get_mac_vendor,
    get_network_interfaces,
    get_wifi_interfaces,
    normalize_mac,
    port_to_service,
    reverse_dns,
    signal_quality,
)

logger = logging.getLogger(__name__)

CONFIG_PATH = Path("/opt/network-discovery/config/config.json")
DATA_DIR = Path("/opt/network-discovery/data")


# ── Configuration defaults ────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "scan_timeout": 600,
    "max_threads": 50,
    "port_scan_top_ports": 100,
    "enable_dns_enumeration": True,
    "enable_dhcp_detection": True,
    "enable_arp_scan": True,
    "enable_traceroute": True,
    # Enhanced scanning
    "enable_service_versions": True,
    "enable_os_detection": True,
    "enable_nse_scripts": True,
    "nse_script_timeout": "15s",
    # Enhanced SNMP
    "enable_snmp_enhanced": True,
    "snmp_community_strings": ["public", "private", "community", "admin", "cisco", "snmp"],
    "snmp_timeout": 2,
    "snmp_retries": 1,
    # Banner grabbing
    "enable_banner_grab": True,
    "banner_grab_timeout": 3,
    "banner_grab_bytes": 256,
    # Multi-subnet detection
    "enable_multi_subnet": True,
    "multi_subnet_candidates": [
        "192.168.0.1", "192.168.1.1", "192.168.2.1",
        "10.0.0.1", "10.0.0.254", "10.0.1.1", "10.1.0.1",
        "172.16.0.1", "172.16.1.1",
    ],
    # MSP enrichment
    "enable_public_ip_lookup": True,
    "enable_gateway_fingerprint": True,
    # Active Directory probing
    "enable_ad_probing": True,
    "ad_probe_timeout": 10,
    # Subnet / VLAN labels (CIDR -> human-readable label)
    "subnet_labels": {},
    # ── Extended discovery phases ─────────────────────────────────────────
    # WiFi enumeration (passive scan, no association)
    "enable_wifi_scan": True,
    "wifi_interface": "auto",
    "wifi_scan_timeout": 30,
    # mDNS / Bonjour service discovery
    "enable_mdns_discovery": True,
    "mdns_timeout": 10,
    # UPnP / SSDP device discovery
    "enable_ssdp_discovery": True,
    "ssdp_timeout": 5,
    # DHCP scope analysis (rogue server detection)
    "enable_dhcp_analysis": True,
    "dhcp_timeout": 10,
    # NTP server detection
    "enable_ntp_detection": True,
    "ntp_timeout": 3,
    # 802.1X / NAC detection
    "enable_nac_detection": True,
    # ── OSINT / External Reconnaissance ───────────────────────────────────
    "enable_osint": True,
    "osint_timeout": 8,          # per-query HTTP timeout
    "enable_shodan_internetdb": True,  # free, no API key
    "enable_crtsh_lookup": True,       # certificate transparency
    "enable_dns_security": True,       # MX, SPF, DKIM, DMARC analysis
    "enable_whois_lookup": True,       # WHOIS via RDAP / whois CLI
    # ── SSL/TLS Certificate Health Audit ──────────────────────────────────
    "enable_ssl_audit": True,
    "ssl_audit_timeout": 5,
    "ssl_cert_warning_days": 30,
    "ssl_cert_critical_days": 7,
    # ── Backup & DR Posture Inference ─────────────────────────────────────
    "enable_backup_posture": True,
    # ── End-of-Life / End-of-Support Detection ────────────────────────────
    "enable_eol_detection": True,
    "eol_warning_months": 12,
}


def load_scan_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            config = json.load(f)
        return {**DEFAULT_CONFIG, **config.get("network_discovery", {})}
    except Exception:
        return DEFAULT_CONFIG


# ── Subnet label lookup ──────────────────────────────────────────────────

def _build_subnet_label_index(subnet_labels: dict) -> list:
    """Pre-compile subnet label CIDRs into (IPv4Network, label) tuples for O(1) lookups."""
    index = []
    for cidr, label in subnet_labels.items():
        try:
            index.append((ipaddress.IPv4Network(cidr, strict=False), label))
        except ValueError:
            pass
    return index


def _resolve_subnet_label(ip: str, label_index: list) -> str:
    """Return the human-readable label for the subnet an IP belongs to.

    label_index is a pre-compiled list of (IPv4Network, label) tuples
    built by _build_subnet_label_index().  Returns empty string if no match.
    """
    if not label_index:
        return ""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return ""
    for net, label in label_index:
        if addr in net:
            return label
    return ""


# ── MSP Enrichment Helpers ────────────────────────────────────────────────

def _get_public_ip_info() -> dict:
    """
    Query ipinfo.io to get the Pi's public IP, ISP/ASN, and reverse PTR.
    Returns empty dict on any failure (e.g. no internet, timeout).
    """
    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"User-Agent": "YeylandWutani-NetworkDiscovery/1.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        return {
            "public_ip": data.get("ip", ""),
            "isp":       data.get("org", ""),      # e.g. "AS7922 Comcast Cable"
            "city":      data.get("city", ""),
            "region":    data.get("region", ""),
            "country":   data.get("country", ""),
            "hostname":  data.get("hostname", ""), # reverse PTR if set
            "timezone":  data.get("timezone", ""),
        }
    except Exception as exc:
        logger.debug(f"Public IP lookup failed: {exc}")
        return {}


# Firewall/router sysDescr fingerprint patterns: (regex, vendor, product)
_GW_SNMP_PATTERNS = [
    (r"FortiGate[- ]?(\S+)",       "Fortinet",           "FortiGate"),
    (r"SonicOS",                    "SonicWall",          "SonicWall"),
    (r"SonicWALL",                  "SonicWall",          "SonicWall"),
    (r"Cisco Adaptive Security",    "Cisco",              "ASA Firewall"),
    (r"Cisco IOS XE",               "Cisco",              "IOS XE"),
    (r"Cisco IOS",                  "Cisco",              "IOS"),
    (r"Cisco NX-OS",                "Cisco",              "NX-OS Switch"),
    (r"JunOS|Juniper",              "Juniper",            "JunOS"),
    (r"pfSense",                    "Netgate",            "pfSense"),
    (r"OPNsense",                   "OPNsense",           "OPNsense"),
    (r"MikroTik RouterOS[^\d]*(\S+)", "MikroTik",         "RouterOS"),
    (r"EdgeOS",                     "Ubiquiti",           "EdgeRouter"),
    (r"UniFi",                      "Ubiquiti",           "UniFi"),
    (r"Meraki",                     "Cisco Meraki",       "Meraki"),
    (r"WatchGuard",                 "WatchGuard",         "Firebox"),
    (r"Sophos",                     "Sophos",             "XG Firewall"),
    (r"Palo Alto",                  "Palo Alto Networks", "PAN-OS"),
    (r"DrayTek",                    "DrayTek",            "Vigor"),
    (r"Fortinet",                   "Fortinet",           "FortiGate"),
]

_GW_HTTP_PATTERNS = [
    ("fortigate",        "Fortinet",           "FortiGate"),
    ("sonicwall",        "SonicWall",          "SonicWall"),
    ("pfsense",          "Netgate",            "pfSense"),
    ("opnsense",         "OPNsense",           "OPNsense"),
    ("meraki",           "Cisco Meraki",       "Meraki"),
    ("cisco",            "Cisco",              "Cisco"),
    ("ubiquiti",         "Ubiquiti",           "UniFi/EdgeOS"),
    ("watchguard",       "WatchGuard",         "Firebox"),
    ("sophos",           "Sophos",             "XG Firewall"),
    ("mikrotik",         "MikroTik",           "RouterOS"),
    ("routeros",         "MikroTik",           "RouterOS"),
    ("draytek",          "DrayTek",            "Vigor"),
    ("fortinet",         "Fortinet",           "FortiGate"),
]

_GW_OUI_MAP = {
    "fortinet":          ("Fortinet",           "FortiGate"),
    "sonicwall":         ("SonicWall",          "SonicWall"),
    "sonic wall":        ("SonicWall",          "SonicWall"),
    "palo alto":         ("Palo Alto Networks", "PAN-OS"),
    "watchguard":        ("WatchGuard",         "Firebox"),
    "ubiquiti":          ("Ubiquiti",           "UniFi/EdgeOS"),
    "cisco meraki":      ("Cisco Meraki",       "Meraki"),
    "aruba":             ("Aruba Networks",     "Switch/Controller"),
    "juniper":           ("Juniper",            "JunOS"),
    "mikrotik":          ("MikroTik",           "RouterOS"),
}


def _fingerprint_gateway(host: dict) -> dict:
    """
    Attempt to identify the gateway device vendor/model using all available
    data already collected (SNMP, HTTP titles, banners, port versions, OUI).
    Returns a gateway_info dict. Does NOT make new network calls.
    """
    services = host.get("services", {})
    vendor_raw = host.get("vendor", "").lower()

    # 1. SNMP sysDescr — highest confidence
    snmp = services.get("snmp", {}) or {}
    sys_descr = (snmp.get("sysDescr") or snmp.get("snmp_sysdescr") or "").strip()
    if sys_descr:
        for pattern, vendor, product in _GW_SNMP_PATTERNS:
            m = re.search(pattern, sys_descr, re.IGNORECASE)
            if m:
                model = ""
                firmware = ""
                # Try to extract model from parenthetical group
                if m.lastindex and m.lastindex >= 1:
                    model = m.group(1).strip()[:30]
                # Try to extract version from sysDescr: common patterns
                ver_m = re.search(
                    r"[Vv]ersion[:\s]+(\d+[\d.]+)|v(\d+[\d.]+)",
                    sys_descr
                )
                if ver_m:
                    firmware = (ver_m.group(1) or ver_m.group(2) or "").strip()[:20]
                return {
                    "vendor": vendor, "product": product,
                    "model": model, "firmware": firmware,
                    "confidence": "high", "detection_source": "snmp",
                }

    # 2. HTTP/HTTPS title — medium confidence
    for port in (80, 443, 8080, 8443):
        svc = services.get(port, {})
        if isinstance(svc, dict):
            title = (svc.get("title") or svc.get("nse_title") or "").lower()
            server = (svc.get("server") or "").lower()
            for keyword, vendor, product in _GW_HTTP_PATTERNS:
                if keyword in title or keyword in server:
                    return {
                        "vendor": vendor, "product": product,
                        "model": "", "firmware": "",
                        "confidence": "medium", "detection_source": "http_title",
                    }

    # 3. SSH / port 22 banner
    svc_22 = services.get(22, {})
    if isinstance(svc_22, dict):
        banner = (svc_22.get("banner") or svc_22.get("nse_banner") or "").lower()
        if banner:
            for keyword, vendor, product in _GW_HTTP_PATTERNS:
                if keyword in banner:
                    return {
                        "vendor": vendor, "product": product,
                        "model": "", "firmware": "",
                        "confidence": "medium", "detection_source": "ssh_banner",
                    }

    # 4. Port-specific version strings
    for port in (8291, 4444):  # MikroTik Winbox, Ubiquiti UNMS
        svc = services.get(port, {})
        if isinstance(svc, dict) and svc.get("version"):
            ver = svc["version"].lower()
            if "mikrotik" in ver or port == 8291:
                return {
                    "vendor": "MikroTik", "product": "RouterOS",
                    "model": "", "firmware": "",
                    "confidence": "medium", "detection_source": "port_version",
                }
            if "ubiquiti" in ver or port == 4444:
                return {
                    "vendor": "Ubiquiti", "product": "UNMS/UISP",
                    "model": "", "firmware": "",
                    "confidence": "medium", "detection_source": "port_version",
                }

    # 5. MAC OUI fallback — low confidence
    for oui_kw, (vendor, product) in _GW_OUI_MAP.items():
        if oui_kw in vendor_raw:
            return {
                "vendor": vendor, "product": product,
                "model": "", "firmware": "",
                "confidence": "low", "detection_source": "oui",
            }

    return {}


def _aggregate_security_gaps(hosts: list) -> list:
    """
    Roll up per-host security flags into aggregated issue counts.
    Returns a list of dicts sorted by severity then count, most impactful first.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    issue_map: dict = {}

    for host in hosts:
        ip = host.get("ip", "")
        for flag in host.get("security_flags", []):
            issue = flag.get("flag", "")
            sev = flag.get("severity", "LOW")
            if not issue:
                continue
            if issue not in issue_map:
                issue_map[issue] = {"issue": issue, "severity": sev, "count": 0, "ips": []}
            issue_map[issue]["count"] += 1
            if ip and ip not in issue_map[issue]["ips"]:
                issue_map[issue]["ips"].append(ip)

    gaps = sorted(
        issue_map.values(),
        key=lambda x: (severity_order.get(x["severity"], 9), -x["count"]),
    )
    return gaps


# ── Phase 1: Network Reconnaissance ───────────────────────────────────────

def phase1_reconnaissance(config: dict = None) -> dict:
    """Identify active interfaces, subnets, gateway, DNS, and public IP."""
    logger.info("[Phase 1] Network Reconnaissance...")
    result = {
        "phase": "reconnaissance",
        "interfaces": [],
        "subnets": [],
        "additional_subnets": [],
        "default_gateway": None,
        "dns_servers": [],
        "our_ips": [],
        "public_ip_info": {},
    }

    interfaces = get_network_interfaces()
    result["interfaces"] = interfaces
    result["our_ips"] = [iface["ip"] for iface in interfaces if iface.get("ip")]

    subnets = list({iface["cidr"] for iface in interfaces if iface.get("cidr")})
    result["subnets"] = subnets

    result["default_gateway"] = get_default_gateway()
    result["dns_servers"] = get_dns_servers()

    # Public IP / ISP lookup (best-effort, requires internet)
    if (config or {}).get("enable_public_ip_lookup", True):
        logger.info("  Fetching public IP info...")
        result["public_ip_info"] = _get_public_ip_info()
        pub = result["public_ip_info"]
        if pub.get("public_ip"):
            logger.info(f"  Public IP: {pub['public_ip']}  ISP: {pub.get('isp', 'N/A')}")

    logger.info(f"  Interfaces: {[i['name'] for i in interfaces]}")
    logger.info(f"  Subnets: {subnets}")
    logger.info(f"  Gateway: {result['default_gateway']}")
    logger.info(f"  DNS: {result['dns_servers']}")

    return result


# ── Phase 1b: Alternate Subnet Detection ──────────────────────────────────

def _probe_ip_alive(ip: str, timeout_ms: int = 500) -> bool:
    """Ping a single IP once. Returns True if it responds."""
    try:
        ret = subprocess.call(
            ["fping", "-c", "1", "-t", str(timeout_ms), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return ret == 0
    except FileNotFoundError:
        # fping not available - fall back to TCP connect on port 80
        try:
            with socket.create_connection((ip, 80), timeout=1):
                return True
        except Exception:
            pass
        try:
            with socket.create_connection((ip, 443), timeout=1):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


def phase1b_alternate_subnet_detection(recon: dict, config: dict) -> dict:
    """
    Probe candidate gateway IPs to discover adjacent/routable subnets.
    Responds to IPs not already within known subnets are treated as
    new /24 networks and added to recon for Phase 2 scanning.
    """
    if not config.get("enable_multi_subnet", True):
        return recon

    logger.info("[Phase 1b] Alternate Subnet Detection...")

    # Build set of already-known networks
    known_nets = []
    for cidr in recon.get("subnets", []):
        try:
            known_nets.append(ipaddress.IPv4Network(cidr, strict=False))
        except ValueError:
            pass

    def is_in_known_net(ip: str) -> bool:
        try:
            addr = ipaddress.IPv4Address(ip)
            return any(addr in net for net in known_nets)
        except ValueError:
            return True  # skip invalid

    # Build candidate list: config list + .1 and .254 of each known subnet
    # Use network_address/broadcast_address to avoid materializing host list (#14)
    candidates = list(config.get("multi_subnet_candidates", []))
    for net in known_nets:
        if net.num_addresses > 2:
            candidates.append(str(net.network_address + 1))    # .1 equivalent
            candidates.append(str(net.broadcast_address - 1))  # .254 equivalent

    # Determine the Pi's own prefix length to use when inferring new subnets (#16)
    # Fall back to /24 if no known nets exist.
    pi_prefixlen = 24
    if known_nets:
        pi_prefixlen = known_nets[0].prefixlen

    # Deduplicate, skip IPs already in known subnets and our own IPs
    our_ips = set(recon.get("our_ips", []))
    seen = set()
    probe_targets = []
    for ip in candidates:
        if ip in seen or ip in our_ips:
            continue
        seen.add(ip)
        if not is_in_known_net(ip):
            probe_targets.append(ip)

    logger.info(f"  Probing {len(probe_targets)} candidate gateway IPs (parallel)...")

    # Probe in parallel to avoid blocking sequentially on each timeout (#4)
    def _probe_and_infer(ip: str):
        if not _probe_ip_alive(ip):
            return None
        try:
            inferred_net = ipaddress.IPv4Network(f"{ip}/{pi_prefixlen}", strict=False)
            return (ip, inferred_net)
        except ValueError:
            return None

    probe_workers = min(len(probe_targets), 20)
    found = 0
    if probe_targets:
        with concurrent.futures.ThreadPoolExecutor(max_workers=probe_workers) as ex:
            for result in ex.map(_probe_and_infer, probe_targets):
                if result is None:
                    continue
                ip, inferred_net = result
                cidr = str(inferred_net)
                if not any(inferred_net.overlaps(kn) for kn in known_nets):
                    recon["additional_subnets"].append({
                        "cidr": cidr,
                        "discovered_via": ip,
                    })
                    recon["subnets"].append(cidr)
                    known_nets.append(inferred_net)
                    logger.info(f"  Found additional subnet: {cidr} (via {ip})")
                    found += 1

    logger.info(f"  Alternate subnet detection complete. {found} additional subnet(s) found.")
    return recon


# ── Phase 2: Host Discovery ────────────────────────────────────────────────

def _run_arp_scan(subnet: str, iface: str = None) -> list:
    """Run arp-scan on a subnet. Returns list of {ip, mac, vendor}."""
    hosts = []
    cmd = ["arp-scan", "--localnet", "--retry=2"]
    if iface:
        cmd += ["--interface", iface]
    try:
        output = subprocess.check_output(cmd, text=True, timeout=60, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                ip = parts[0].strip()
                mac = parts[1].strip()
                vendor = parts[2].strip() if len(parts) > 2 else ""
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                    hosts.append({"ip": ip, "mac": normalize_mac(mac), "vendor_arp": vendor})
    except subprocess.TimeoutExpired:
        logger.warning("arp-scan timed out")
    except FileNotFoundError:
        logger.warning("arp-scan not found - skipping ARP phase")
    except Exception as e:
        logger.warning(f"arp-scan error: {e}")
    return hosts


def _run_fping(subnet: str) -> list:
    """Run fping to discover live hosts. Returns list of live IPs."""
    live = []
    try:
        output = subprocess.check_output(
            ["fping", "-a", "-g", subnet, "-t", "500", "-r", "1"],
            text=True, timeout=120, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            ip = line.strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                live.append(ip)
    except subprocess.TimeoutExpired:
        logger.warning("fping timed out")
    except FileNotFoundError:
        logger.warning("fping not found - using nmap ping scan fallback")
        live = _nmap_ping_scan(subnet)
    except Exception as e:
        logger.warning(f"fping error: {e}")
    return live


def _nmap_ping_scan(subnet: str) -> list:
    """Nmap ping-only scan as fallback for fping."""
    live = []
    try:
        output = subprocess.check_output(
            ["nmap", "-n", "-sn", "--min-parallelism", "100", subnet],
            text=True, timeout=120, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            match = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                live.append(match.group(1))
    except Exception as e:
        logger.warning(f"nmap ping scan error: {e}")
    return live


def _make_empty_host(ip: str, subnet_source: str = "direct") -> dict:
    return {
        "ip": ip,
        "mac": "",
        "vendor": "Unknown",
        "hostname": None,
        "open_ports": [],
        "services": {},
        "category": "Unknown",
        "security_flags": [],
        "subnet_source": subnet_source,
        "subnet_label": "",
    }


def phase2_host_discovery(recon: dict, config: dict) -> list:
    """
    Discover all live hosts via ARP + ping sweep on direct and additional subnets.
    Returns list of host dicts with ip, mac, vendor, hostname.
    """
    logger.info("[Phase 2] Host Discovery...")
    all_hosts: dict = {}  # ip -> host_dict
    our_ips = set(recon.get("our_ips", []))

    # ── Direct interfaces (ARP + fping) ───────────────────────────────────
    for iface in recon.get("interfaces", []):
        subnet = iface.get("cidr")
        if not subnet:
            continue

        if config.get("enable_arp_scan", True):
            logger.info(f"  ARP scan: {subnet} on {iface['name']}")
            arp_hosts = _run_arp_scan(subnet, iface=iface.get("name"))
            for h in arp_hosts:
                ip = h["ip"]
                if ip not in our_ips:
                    all_hosts[ip] = {
                        **_make_empty_host(ip, "direct"),
                        "mac": h.get("mac", ""),
                        "vendor": get_mac_vendor(h.get("mac", "")) or h.get("vendor_arp", "Unknown"),
                    }

        logger.info(f"  Ping sweep: {subnet}")
        live_ips = _run_fping(subnet)
        for ip in live_ips:
            if ip not in our_ips and ip not in all_hosts:
                all_hosts[ip] = _make_empty_host(ip, "direct")

    # ── Additional subnets found by phase1b (fping only - ARP won't cross router) ──
    for extra in recon.get("additional_subnets", []):
        cidr = extra["cidr"]
        logger.info(f"  Scanning additional subnet: {cidr} (discovered via {extra['discovered_via']})")
        live_ips = _run_fping(cidr)
        for ip in live_ips:
            if ip not in our_ips and ip not in all_hosts:
                all_hosts[ip] = _make_empty_host(ip, "additional")

    # ── DNS lookups (parallel) ────────────────────────────────────────────
    if config.get("enable_dns_enumeration", True):
        logger.info(f"  Reverse DNS for {len(all_hosts)} hosts (parallel)...")
        dns_threads = min(config.get("max_threads", 50), len(all_hosts), 50)
        with concurrent.futures.ThreadPoolExecutor(max_workers=dns_threads) as ex:
            ip_list = list(all_hosts.keys())
            results_iter = ex.map(reverse_dns, ip_list)
            for ip, hostname in zip(ip_list, results_iter):
                all_hosts[ip]["hostname"] = hostname or "N/A"

    # ── Ensure gateway is present ─────────────────────────────────────────
    gw = recon.get("default_gateway")
    if gw and gw not in our_ips and gw not in all_hosts:
        all_hosts[gw] = {
            **_make_empty_host(gw, "direct"),
            "hostname": reverse_dns(gw) or "N/A",
            "category": "Network Infrastructure",
            "is_gateway": True,
        }

    # Apply subnet labels from config (e.g. "192.168.1.0/24" -> "Corporate LAN")
    subnet_labels = config.get("subnet_labels", {})
    if subnet_labels:
        label_index = _build_subnet_label_index(subnet_labels)
        for host in all_hosts.values():
            host["subnet_label"] = _resolve_subnet_label(host["ip"], label_index)

    hosts = sorted(all_hosts.values(), key=lambda h: socket.inet_aton(h["ip"]))
    logger.info(f"  Discovered {len(hosts)} live hosts.")
    return hosts


# ── Phase 3: Port Scanning ─────────────────────────────────────────────────

def _nmap_port_scan(
    ip: str,
    top_ports: int = 100,
    service_versions: bool = True,
    os_detection: bool = True,
) -> dict:
    """
    Run nmap TCP SYN scan on top N ports for a single host.

    Returns:
        {
            "open_ports": list[int],
            "version_info": {port: {"version": str}, ...},
            "os_guess": str,
        }
    """
    result = {"open_ports": [], "version_info": {}, "os_guess": ""}
    cmd = ["nmap", "-n", "-sS", "--open"]

    if service_versions:
        cmd += ["-sV", "--version-intensity", "4"]
    if os_detection:
        cmd += ["--osscan-guess"]

    cmd += [
        "--top-ports", str(top_ports),
        "--host-timeout", "60s",
        "--min-parallelism", "20",
        "-T4",
        ip,
    ]

    try:
        output = subprocess.check_output(
            cmd, text=True, timeout=90, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            # Open port with optional version string
            m = re.match(r"^(\d+)/tcp\s+open\s+\S+\s*(.*)", line)
            if m:
                port = int(m.group(1))
                result["open_ports"].append(port)
                version_str = m.group(2).strip()
                if version_str:
                    result["version_info"][port] = {"version": version_str[:120]}

            # OS guess line (first match wins)
            if not result["os_guess"]:
                og = re.search(r"OS guess(?:es)?: (.+)", line, re.IGNORECASE)
                if og:
                    result["os_guess"] = og.group(1).strip()[:100]

    except subprocess.TimeoutExpired:
        logger.warning(f"Port scan timeout (>90s): {ip}")
    except FileNotFoundError:
        logger.error("nmap not found — is it installed?")
    except Exception as e:
        logger.warning(f"Port scan error for {ip}: {e}")

    return result


def phase3_port_scan(hosts: list, config: dict) -> list:
    """Parallel port scanning of all discovered hosts."""
    logger.info(f"[Phase 3] Port Scanning {len(hosts)} hosts...")
    top_ports = config.get("port_scan_top_ports", 100)
    max_threads = min(config.get("max_threads", 50), 50)
    svc_versions = config.get("enable_service_versions", True)
    os_det = config.get("enable_os_detection", True)

    def scan_host(host: dict) -> dict:
        scan_result = _nmap_port_scan(
            host["ip"],
            top_ports=top_ports,
            service_versions=svc_versions,
            os_detection=os_det,
        )
        host["open_ports"] = scan_result["open_ports"]

        # Seed services with version info from this scan pass
        if scan_result["version_info"]:
            if "services" not in host:
                host["services"] = {}
            for port, vinfo in scan_result["version_info"].items():
                if port not in host["services"]:
                    host["services"][port] = {"name": port_to_service(port)}
                host["services"][port]["version"] = vinfo["version"]

        if scan_result["os_guess"]:
            host["os_guess"] = scan_result["os_guess"]

        if host["open_ports"]:
            logger.debug(f"  {host['ip']}: {host['open_ports']}")
        return host

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = list(executor.map(scan_host, hosts))

    total_ports = sum(len(h["open_ports"]) for h in results)
    logger.info(f"  Port scan complete. {total_ports} open ports found across {len(hosts)} hosts.")
    return results


# ── Phase 4: Service Enumeration ──────────────────────────────────────────

def _get_http_info(ip: str, port: int) -> dict:
    """Grab HTTP title and Server header via urllib."""
    import urllib.request
    protocol = "https" if port in (443, 8443) else "http"
    url = f"{protocol}://{ip}:{port}/"
    info = {"title": "", "server": "", "url": url}
    try:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "NetworkDiscovery/1.0"})
        with urllib.request.urlopen(req, timeout=5, context=ctx if protocol == "https" else None) as resp:
            info["server"] = resp.headers.get("Server", "")
            body = resp.read(4096).decode("utf-8", errors="ignore")
            match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
            if match:
                info["title"] = match.group(1).strip()[:120]
    except Exception:
        pass
    return info


def _check_smb(ip: str) -> dict:
    """SMB OS discovery via nmap script."""
    info = {}
    try:
        output = subprocess.check_output(
            ["nmap", "-n", "-p", "445", "--script", "smb-os-discovery",
             "--host-timeout", "10s", ip],
            text=True, timeout=15, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            if "Computer name:" in line:
                info["smb_computer"] = line.split(":", 1)[1].strip()
            elif "Domain name:" in line or "Workgroup:" in line:
                info["smb_domain"] = line.split(":", 1)[1].strip()
            elif "OS:" in line and "Windows" in line:
                info["smb_os"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return info


# ── Enhanced SNMP ──────────────────────────────────────────────────────────

def _parse_snmp_value(line: str) -> str:
    """Extract the value portion from a snmpget/snmpwalk output line."""
    for marker in ("STRING:", "INTEGER:", "OID:", "Timeticks:", "Counter32:",
                   "Gauge32:", "IpAddress:", "Hex-STRING:"):
        if marker in line:
            return line.split(marker, 1)[1].strip().strip('"')[:200]
    return ""


def _check_snmp(ip: str) -> dict:
    """Basic SNMP check (public community only) - kept as fallback."""
    info = {}
    try:
        output = subprocess.check_output(
            ["snmpget", "-v", "1", "-c", "public", "-t", "2", "-r", "1",
             ip, "sysDescr.0"],
            text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        if "STRING:" in output:
            desc = output.split("STRING:", 1)[1].strip()[:200]
            info["snmp_sysdescr"] = desc
    except Exception:
        pass
    return info


def _check_snmp_enhanced(ip: str, config: dict) -> dict:
    """
    Enhanced SNMP scan: probe multiple community strings (v2c then v1),
    walk key scalar OIDs and interface descriptions once a working community
    is found.
    """
    communities = config.get("snmp_community_strings",
                             ["public", "private", "community", "admin", "cisco", "snmp"])
    timeout = config.get("snmp_timeout", 2)
    retries = config.get("snmp_retries", 1)

    working_community = None
    working_version = None

    # Probe: find first community + version that responds
    for community in communities:
        for version in ("2c", "1"):
            try:
                ret = subprocess.call(
                    ["snmpget", f"-v{version}", "-c", community,
                     f"-t{timeout}", f"-r{retries}", ip, "sysDescr.0"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=timeout + 2,
                )
                if ret == 0:
                    working_community = community
                    working_version = version
                    break
            except FileNotFoundError:
                logger.debug("snmpget not found - skipping SNMP enhanced scan")
                return {}
            except Exception:
                pass
        if working_community:
            break

    if not working_community:
        return {}

    logger.debug(f"  SNMP {ip}: community='***' version=v{working_version}")

    info = {
        "working_community": working_community,
        "snmp_version": f"v{working_version}",
        "snmp_sysdescr": "",  # backward compat key
        "sysDescr": "", "sysName": "", "sysLocation": "",
        "sysContact": "", "sysUpTime": "", "sysObjectID": "",
        "ifDescr": [],
    }

    # Fetch all scalar OIDs in one call
    scalar_oids = [
        "sysDescr.0", "sysName.0", "sysLocation.0",
        "sysContact.0", "sysUpTime.0", "sysObjectID.0",
    ]
    oid_keys = ["sysDescr", "sysName", "sysLocation", "sysContact", "sysUpTime", "sysObjectID"]

    try:
        output = subprocess.check_output(
            ["snmpget", f"-v{working_version}", "-c", working_community,
             f"-t{timeout}", f"-r{retries}", ip] + scalar_oids,
            text=True, timeout=timeout * 3 + 5, stderr=subprocess.DEVNULL
        )
        lines = [l.strip() for l in output.splitlines() if l.strip()]
        for i, line in enumerate(lines[:len(oid_keys)]):
            val = _parse_snmp_value(line)
            if val:
                info[oid_keys[i]] = val
        # Set backward compat key
        info["snmp_sysdescr"] = info["sysDescr"]
    except Exception as e:
        logger.debug(f"SNMP scalar fetch error for {ip}: {e}")

    # Interface descriptions - try snmpwalk, fall back to individual snmpgets
    try:
        output = subprocess.check_output(
            ["snmpwalk", f"-v{working_version}", "-c", working_community,
             f"-t{timeout}", f"-r{retries}", ip, "ifDescr"],
            text=True, timeout=timeout * 4 + 5, stderr=subprocess.DEVNULL
        )
        ifaces = []
        for line in output.splitlines():
            val = _parse_snmp_value(line)
            if val:
                ifaces.append(val)
        info["ifDescr"] = ifaces[:16]
    except FileNotFoundError:
        # snmpwalk not installed - fetch ifDescr.1 through ifDescr.8 individually
        ifaces = []
        try:
            oids = [f"ifDescr.{i}" for i in range(1, 9)]
            output = subprocess.check_output(
                ["snmpget", f"-v{working_version}", "-c", working_community,
                 f"-t{timeout}", f"-r1", ip] + oids,
                text=True, timeout=timeout * 2 + 5, stderr=subprocess.DEVNULL
            )
            for line in output.splitlines():
                val = _parse_snmp_value(line)
                if val and val not in ("No Such Instance", "No Such Object"):
                    ifaces.append(val)
        except Exception:
            pass
        info["ifDescr"] = ifaces
    except Exception as e:
        logger.debug(f"SNMP ifDescr walk error for {ip}: {e}")

    return info


# ── Banner grabbing ────────────────────────────────────────────────────────

BANNER_PORTS = {21, 22, 23, 25}


def _grab_banner(ip: str, port: int, timeout: float = 3.0, max_bytes: int = 256) -> str:
    """
    Connect to ip:port and read the initial banner (welcome message).
    Returns printable ASCII string, or "" on any failure.
    Failures are expected and intentionally not logged.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            raw = sock.recv(max_bytes)
        banner = raw.decode("utf-8", errors="replace").strip()
        # Keep only printable ASCII + whitespace
        banner = re.sub(r"[^\x20-\x7E\n\r\t]", "", banner)
        return banner[:max_bytes]
    except Exception:
        return ""


# ── NSE Scripts ───────────────────────────────────────────────────────────

def _nse_timeout_secs(config: dict) -> int:
    """Convert nse_script_timeout string (e.g. '15s') to int seconds + buffer."""
    raw = config.get("nse_script_timeout", "15s")
    try:
        return int(re.sub(r"[^\d]", "", raw)) + 5
    except Exception:
        return 20


def _run_nse_scripts(ip: str, open_ports: list, config: dict) -> dict:
    """
    Run targeted nmap NSE scripts based on which ports are open.
    All script invocations are non-intrusive (no auth attempts except anonymous SMB).

    Returns a dict of results to be merged into the host's services dict.
    """
    results = {}
    ports_set = set(open_ports)
    timeout_flag = config.get("nse_script_timeout", "15s")
    proc_timeout = _nse_timeout_secs(config)

    def _run(cmd: list) -> str:
        try:
            return subprocess.check_output(
                cmd, text=True, timeout=proc_timeout, stderr=subprocess.DEVNULL
            )
        except Exception:
            return ""

    # SMB share enumeration (anonymous)
    if 445 in ports_set:
        out = _run([
            "nmap", "-n", "-p", "445",
            "--script", "smb-enum-shares",
            "--script-args", "smbusername=,smbpassword=",
            "--host-timeout", timeout_flag, ip,
        ])
        shares = []
        for line in out.splitlines():
            m = re.search(r"(\\\\[^\s]+)", line)
            if m:
                shares.append(m.group(1))
        if shares:
            results["smb_shares"] = shares

    # SSL certificate info
    ssl_ports = [p for p in (443, 8443) if p in ports_set]
    if ssl_ports:
        out = _run([
            "nmap", "-n", "-p", ",".join(str(p) for p in ssl_ports),
            "--script", "ssl-cert",
            "--host-timeout", timeout_flag, ip,
        ])
        cert = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Subject:"):
                cert["subject"] = line.split(":", 1)[1].strip()[:120]
            elif line.startswith("Issuer:"):
                cert["issuer"] = line.split(":", 1)[1].strip()[:120]
            elif "Not valid after" in line or "notAfter" in line:
                cert["expires"] = line.split(":", 1)[1].strip()[:40] if ":" in line else ""
            elif "Not valid before" in line or "notBefore" in line:
                cert["issued"] = line.split(":", 1)[1].strip()[:40] if ":" in line else ""
        if cert:
            results["ssl_cert"] = cert

    # Banner grab via NSE for FTP/SSH/Telnet/SMTP (supplement raw socket banners)
    banner_ports = sorted(BANNER_PORTS & ports_set)
    if banner_ports:
        out = _run([
            "nmap", "-n", "-p", ",".join(str(p) for p in banner_ports),
            "--script", "banner",
            "--host-timeout", timeout_flag, ip,
        ])
        for line in out.splitlines():
            m = re.match(r"^(\d+)/tcp.*banner: (.+)", line, re.IGNORECASE)
            if not m:
                m = re.search(r"\|_?banner: (.+)", line, re.IGNORECASE)
                if m:
                    # Try to infer port from context - skip if ambiguous
                    pass
            if m and len(m.groups()) == 2:
                port = int(m.group(1))
                if port not in results:
                    results[port] = {}
                results[port]["nse_banner"] = m.group(2).strip()[:200]

    # HTTP title via NSE (backup to urllib - won't overwrite existing title)
    web_ports = sorted({p for p in open_ports
                        if p in (80, 443, 8080, 8443, 8000, 8888, 3000)})
    if web_ports:
        out = _run([
            "nmap", "-n", "-p", ",".join(str(p) for p in web_ports),
            "--script", "http-title",
            "--host-timeout", timeout_flag, ip,
        ])
        for line in out.splitlines():
            # nmap outputs: "80/tcp  open  http  Title: ..."  or "|  http-title: ..."
            m = re.search(r"http-title: (.+)", line, re.IGNORECASE)
            if m:
                title = m.group(1).strip()[:120]
                # Try to find which port this applies to from surrounding context
                pm = re.match(r"^(\d+)/tcp", line)
                if pm:
                    port = int(pm.group(1))
                    if port not in results:
                        results[port] = {}
                    if "nse_title" not in results.get(port, {}):
                        results[port]["nse_title"] = title

    return results


def _merge_nse_results(services: dict, nse_results: dict) -> None:
    """
    Merge NSE script results into the services dict in-place.
    Does not overwrite keys already set by urllib or _check_smb.
    """
    for key, value in nse_results.items():
        if isinstance(key, int):  # port-keyed results
            if key not in services:
                services[key] = {"name": port_to_service(key)}
            for subkey, subval in value.items():
                if subkey not in services[key]:
                    services[key][subkey] = subval
        else:
            # String keys: smb_shares, ssl_cert, etc. - always add
            services[key] = value


def phase4_service_enumeration(hosts: list, config: dict) -> list:
    """Enumerate HTTP, SMB, SNMP, banners, and NSE scripts on discovered hosts."""
    logger.info("[Phase 4] Service Enumeration...")
    banner_timeout = float(config.get("banner_grab_timeout", 3))
    banner_bytes = int(config.get("banner_grab_bytes", 256))
    snmp_enhanced = config.get("enable_snmp_enhanced", True)
    do_banners = config.get("enable_banner_grab", True)
    do_nse = config.get("enable_nse_scripts", True)

    def enumerate_host(host: dict) -> dict:
        ports = set(host.get("open_ports", []))
        # Start from any services dict already seeded by phase3 (version info)
        services = host.get("services", {})

        # Ensure all open ports have at least a name entry
        for port in ports:
            if port not in services:
                services[port] = {"name": port_to_service(port)}

        # HTTP/HTTPS
        for port in ports:
            if port in (80, 443, 8080, 8443, 8000, 8888, 3000):
                http_info = _get_http_info(host["ip"], port)
                services[port].update(http_info)

        # SMB OS discovery
        if 445 in ports or 139 in ports:
            smb_info = _check_smb(host["ip"])
            services["smb"] = smb_info

        # SNMP
        if 161 in ports:
            if snmp_enhanced:
                snmp_info = _check_snmp_enhanced(host["ip"], config)
            else:
                snmp_info = _check_snmp(host["ip"])
            services["snmp"] = snmp_info

        # Raw socket banner grabbing (FTP, SSH, Telnet, SMTP)
        if do_banners:
            for port in BANNER_PORTS:
                if port in ports:
                    banner = _grab_banner(host["ip"], port, banner_timeout, banner_bytes)
                    if banner:
                        services[port]["banner"] = banner

        # NSE scripts (smb-enum-shares, ssl-cert, banner, http-title)
        if do_nse and ports:
            nse_results = _run_nse_scripts(host["ip"], list(ports), config)
            _merge_nse_results(services, nse_results)

        host["services"] = services

        # Gateway deep-fingerprint (uses data already collected above)
        if host.get("is_gateway") and config.get("enable_gateway_fingerprint", True):
            gw_info = _fingerprint_gateway(host)
            if gw_info:
                host["gateway_info"] = gw_info
                # Override category to Firewall if confidence is high/medium
                if gw_info.get("confidence") in ("high", "medium"):
                    host["category"] = "Firewall"

        # Active Directory / LDAP probing (if DC ports detected)
        if config.get("enable_ad_probing", True):
            open_set = set(host.get("open_ports", []))
            if 88 in open_set and 389 in open_set:
                ad_timeout = int(config.get("ad_probe_timeout", 10))
                logger.info(f"  DC detected at {host['ip']} — running LDAP probe...")
                ad_info = _probe_ad_ldap(host["ip"], timeout=ad_timeout)
                host["ad_info"] = ad_info
                host["is_domain_controller"] = True
                if ad_info.get("enumerated"):
                    host["category"] = "Domain Controller"
                    logger.info(
                        f"  AD probe success: domain={ad_info.get('domain_name', '?')}, "
                        f"users={ad_info.get('user_count')}, "
                        f"computers={ad_info.get('computer_count')}"
                    )

        return host

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(enumerate_host, hosts))

    logger.info("  Service enumeration complete.")
    return results


# ── Phase 5: Network Topology ──────────────────────────────────────────────

def _run_traceroute(target_ip: str) -> list:
    """Run traceroute, return list of hop IPs."""
    hops = []
    try:
        output = subprocess.check_output(
            ["traceroute", "-n", "-w", "1", "-m", "15", target_ip],
            text=True, timeout=30, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                ip_candidate = parts[1]
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip_candidate):
                    hops.append(ip_candidate)
    except Exception:
        pass
    return hops


def phase5_topology(recon: dict, config: dict) -> dict:
    """Map network topology via traceroute to gateway and key hosts."""
    if not config.get("enable_traceroute", True):
        return {}

    logger.info("[Phase 5] Network Topology...")
    topology = {}

    gw = recon.get("default_gateway")
    if gw:
        hops = _run_traceroute(gw)
        topology["gateway"] = {"target": gw, "hops": hops}
        logger.info(f"  Traceroute to gateway {gw}: {len(hops)} hop(s)")

    logger.info("  Topology mapping complete.")
    return topology


# ── Phase 6: Security Observations ────────────────────────────────────────

SECURITY_RULES = [
    {"ports": {21},      "flag": "FTP enabled (unencrypted)",                    "severity": "MEDIUM"},
    {"ports": {23},      "flag": "Telnet enabled (insecure)",                    "severity": "HIGH"},
    {"ports": {161},     "flag": "SNMP enabled (check community strings)",       "severity": "MEDIUM"},
    {"ports": {137, 139},"flag": "NetBIOS exposed",                              "severity": "LOW"},
    {"ports": {3389},    "flag": "RDP exposed",                                  "severity": "MEDIUM"},
    {"ports": {5900},    "flag": "VNC exposed",                                  "severity": "HIGH"},
    {"ports": {1433},    "flag": "MSSQL exposed",                                "severity": "HIGH"},
    {"ports": {3306},    "flag": "MySQL exposed",                                "severity": "HIGH"},
    {"ports": {5432},    "flag": "PostgreSQL exposed",                           "severity": "HIGH"},
    {"ports": {27017},   "flag": "MongoDB exposed (often unauthenticated)",      "severity": "CRITICAL"},
    {"ports": {6379},    "flag": "Redis exposed (often unauthenticated)",        "severity": "CRITICAL"},
    # LDAP anonymous bind rule — only fires if AD probe actually succeeded (checked in phase6)
    {"ports": {389},     "flag": "LDAP anonymous bind enabled (AD enumerable without credentials)", "severity": "MEDIUM"},
]


# ── Active Directory / LDAP Probing ──────────────────────────────────────────

def _probe_ad_ldap(ip: str, timeout: int = 10) -> dict:
    """
    Passively enumerate a Domain Controller using anonymous LDAP bind.
    Uses ldapsearch (from ldap-utils package) — read-only, no credential guessing.
    Anonymous LDAP bind is a standard capability exposed by all AD domain controllers
    by default; this is equivalent to what any LAN user can run with ldapsearch -x.

    Returns a dict with AD environment details, or empty dict with enumerated=False
    if the host is unreachable or anonymous bind is not permitted.
    """
    result = {
        "domain_name": "",
        "netbios_name": "",
        "base_dn": "",
        "domain_functional_level": "",
        "user_count": None,
        "computer_count": None,
        "dc_count": None,
        "domain_admins": [],
        "os_versions": {},
        "enumerated": False,
        "anonymous_bind_allowed": False,
        "error": "",
    }

    # Check ldapsearch is available
    if not Path("/usr/bin/ldapsearch").exists():
        logger.debug(f"  LDAP probe {ip}: ldapsearch not installed, skipping")
        result["error"] = "ldapsearch not found — install ldap-utils"
        return result

    logger.debug(f"  LDAP probe {ip}: starting anonymous bind enumeration")

    _AD_FUNC_LEVELS = {
        "0": "Windows Server 2000",
        "1": "Windows Server 2003 Interim",
        "2": "Windows Server 2003",
        "3": "Windows Server 2008",
        "4": "Windows Server 2008 R2",
        "5": "Windows Server 2012",
        "6": "Windows Server 2012 R2",
        "7": "Windows Server 2016",
        "9": "Windows Server 2019",
        "10": "Windows Server 2025",
    }

    # ── Step 1: rootDSE (always anonymous on AD, never blocked) ──────────
    try:
        proc = subprocess.run(
            ["ldapsearch", "-x", "-H", f"ldap://{ip}", "-b", "", "-s", "base",
             "defaultNamingContext", "dnsHostName", "ldapServiceName",
             "forestFunctionality", "domainFunctionality"],
            capture_output=True, text=True, timeout=timeout
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("defaultNamingContext:"):
                result["base_dn"] = line.split(":", 1)[1].strip()
            elif line.startswith("dnsHostName:"):
                hostname = line.split(":", 1)[1].strip()
                # Extract domain from dc01.corp.local -> corp.local
                parts = hostname.split(".")
                if len(parts) > 1:
                    result["domain_name"] = ".".join(parts[1:])
            elif line.startswith("ldapServiceName:"):
                # Format: "corp.local:dc01$@CORP.LOCAL"
                svc = line.split(":", 1)[1].strip()
                if "@" in svc:
                    result["netbios_name"] = svc.split("@")[-1].strip()
            elif line.startswith("domainFunctionality:"):
                lvl = line.split(":", 1)[1].strip()
                result["domain_functional_level"] = _AD_FUNC_LEVELS.get(lvl, f"Level {lvl}")
    except subprocess.TimeoutExpired:
        logger.warning(f"  LDAP probe {ip}: rootDSE query timed out ({timeout}s)")
        result["error"] = f"rootDSE query timed out ({timeout}s)"
        return result
    except Exception as e:
        logger.warning(f"  LDAP probe {ip}: rootDSE query failed: {e}")
        result["error"] = f"rootDSE query failed: {e}"
        return result

    if not result["base_dn"]:
        logger.debug(f"  LDAP probe {ip}: no base DN in rootDSE — not an AD DC")
        result["error"] = "Could not determine base DN from rootDSE"
        return result

    base_dn = result["base_dn"]
    result["enumerated"] = True   # rootDSE succeeded
    logger.info(
        f"  LDAP probe {ip}: AD domain={result['domain_name'] or '?'}, "
        f"base_dn={base_dn}, level={result['domain_functional_level'] or '?'}"
    )

    # ── Step 2: User count (anonymous bind, may be restricted) ───────────
    try:
        proc = subprocess.run(
            ["ldapsearch", "-x", "-H", f"ldap://{ip}", "-b", base_dn,
             "-s", "sub", "(&(objectClass=user)(objectCategory=person))",
             "dn", "-z", "1000"],
            capture_output=True, text=True, timeout=timeout
        )
        if "result: 0 Success" in proc.stdout or "dn: CN=" in proc.stdout:
            result["user_count"] = proc.stdout.count("dn: CN=")
            result["anonymous_bind_allowed"] = True
            logger.info(f"  LDAP probe {ip}: anonymous bind OK — {result['user_count']} user(s)")
        else:
            logger.debug(f"  LDAP probe {ip}: user query denied (anonymous bind restricted)")
    except subprocess.TimeoutExpired:
        logger.debug(f"  LDAP probe {ip}: user query timed out")
    except Exception as e:
        logger.debug(f"  LDAP probe {ip}: user query error: {e}")

    # ── Step 3: Computer count + OS breakdown ────────────────────────────
    try:
        proc = subprocess.run(
            ["ldapsearch", "-x", "-H", f"ldap://{ip}", "-b", base_dn,
             "-s", "sub", "(objectClass=computer)",
             "dn", "operatingSystem", "-z", "1000"],
            capture_output=True, text=True, timeout=timeout
        )
        if "dn: CN=" in proc.stdout:
            result["computer_count"] = proc.stdout.count("dn: CN=")
            result["anonymous_bind_allowed"] = True
            os_versions: dict = {}
            for line in proc.stdout.splitlines():
                line = line.strip()
                if line.startswith("operatingSystem:"):
                    os_name = line.split(":", 1)[1].strip()
                    os_versions[os_name] = os_versions.get(os_name, 0) + 1
            result["os_versions"] = os_versions
            logger.info(
                f"  LDAP probe {ip}: {result['computer_count']} computer(s), "
                f"{len(os_versions)} OS variant(s)"
            )
    except subprocess.TimeoutExpired:
        logger.debug(f"  LDAP probe {ip}: computer query timed out")
    except Exception as e:
        logger.debug(f"  LDAP probe {ip}: computer query error: {e}")

    # ── Step 4: Domain Admins group members ──────────────────────────────
    try:
        proc = subprocess.run(
            ["ldapsearch", "-x", "-H", f"ldap://{ip}", "-b", base_dn,
             "-s", "sub", "(&(objectClass=group)(cn=Domain Admins))",
             "member", "-z", "100"],
            capture_output=True, text=True, timeout=timeout
        )
        admins = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("member: CN="):
                cn = line.split("CN=")[1].split(",")[0]
                admins.append(cn)
        if admins:
            result["domain_admins"] = admins[:15]
            result["anonymous_bind_allowed"] = True
            logger.info(f"  LDAP probe {ip}: {len(admins)} Domain Admin(s) found")
    except subprocess.TimeoutExpired:
        logger.debug(f"  LDAP probe {ip}: Domain Admins query timed out")
    except Exception as e:
        logger.debug(f"  LDAP probe {ip}: Domain Admins query error: {e}")

    # ── Step 5: DC count ──────────────────────────────────────────────────
    try:
        proc = subprocess.run(
            ["ldapsearch", "-x", "-H", f"ldap://{ip}", "-b", base_dn,
             "-s", "sub",
             "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
             "dn", "-z", "50"],
            capture_output=True, text=True, timeout=timeout
        )
        count = proc.stdout.count("dn: CN=")
        result["dc_count"] = max(count, 1)  # At minimum, we're talking to this DC
        logger.debug(f"  LDAP probe {ip}: {result['dc_count']} DC(s) found")
    except Exception as e:
        logger.debug(f"  LDAP probe {ip}: DC count query error: {e}")
        result["dc_count"] = 1

    logger.info(
        f"  LDAP probe {ip}: enumeration complete — "
        f"anon_bind={'yes' if result['anonymous_bind_allowed'] else 'no'}, "
        f"users={result['user_count']}, computers={result['computer_count']}, "
        f"DCs={result['dc_count']}"
    )
    return result



def _check_ssh_version_outdated(banner: str) -> bool:
    """Return True if SSH banner indicates OpenSSH < 8.0."""
    m = re.search(r"OpenSSH[_ ](\d+)\.(\d+)", banner, re.IGNORECASE)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        return (major, minor) < (8, 0)
    return False


def _check_ssl_expiry(ssl_cert: dict) -> Optional[int]:
    """
    Parse SSL cert expiry and return days remaining, or None if unparseable.
    Handles nmap output formats like '2025-03-15T12:00:00' and '2025-03-15'.
    """
    expires = (ssl_cert or {}).get("expires", "")
    if not expires:
        return None
    # Try a few date patterns
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d", "%b %d %H:%M:%S %Y %Z"):
        try:
            from datetime import datetime as _dt
            exp_dt = _dt.strptime(expires.strip(), fmt)
            return (exp_dt - _dt.now()).days
        except ValueError:
            pass
    return None


def phase6_security(hosts: list) -> list:
    """Apply security observation rules to each host."""
    logger.info("[Phase 6] Security Observations...")
    total_flags = 0

    for host in hosts:
        ports_set = set(host.get("open_ports", []))
        services = host.get("services", {})
        flags = []

        # Port-based rules (with Telnet banner augmentation)
        for rule in SECURITY_RULES:
            if rule["ports"] & ports_set:
                flag_text = rule["flag"]
                # Augment Telnet flag with banner snippet
                if 23 in rule["ports"]:
                    telnet_banner = (services.get(23) or {}).get("banner", "")
                    if telnet_banner:
                        flag_text += f" | Banner: {telnet_banner[:60]}"
                flags.append({"flag": flag_text, "severity": rule["severity"]})

        # Many open ports = likely no host-based firewall
        if len(ports_set) > 20:
            flags.append({
                "flag": f"High port exposure ({len(ports_set)} open ports)",
                "severity": "MEDIUM",
            })

        # SNMP: non-public community responded
        snmp = services.get("snmp", {}) or {}
        working_community = snmp.get("working_community", "")
        if working_community and working_community.lower() not in ("public", ""):
            flags.append({
                "flag": f"SNMP non-default community accepted: '{working_community}'",
                "severity": "MEDIUM",
            })

        # SSL cert expiring soon (within 30 days)
        ssl_cert = services.get("ssl_cert", {})
        days_left = _check_ssl_expiry(ssl_cert)
        if days_left is not None and days_left <= 30:
            flags.append({
                "flag": f"SSL certificate expiring in {days_left} day(s)",
                "severity": "HIGH" if days_left <= 7 else "MEDIUM",
            })

        # Outdated SSH version
        ssh_banner = (services.get(22) or {}).get("banner", "")
        if ssh_banner and _check_ssh_version_outdated(ssh_banner):
            flags.append({
                "flag": f"Outdated SSH version detected: {ssh_banner[:60]}",
                "severity": "MEDIUM",
            })

        # LDAP anonymous bind — only flag if AD probe actually confirmed it succeeded
        ad_info = host.get("ad_info", {}) or {}
        if ad_info.get("anonymous_bind_allowed"):
            flags.append({
                "flag": "LDAP anonymous bind enabled — AD structure enumerable without credentials",
                "severity": "MEDIUM",
            })

        # Rogue/unidentified device with active services
        vendor = host.get("vendor", "Unknown")
        if (vendor in ("", "Unknown") and len(ports_set) >= 3
                and not host.get("is_domain_controller")):
            flags.append({
                "flag": f"Unidentified device (unknown OUI) with {len(ports_set)} open services",
                "severity": "LOW",
            })

        host["security_flags"] = flags
        total_flags += len(flags)

        # Classify device with enriched data
        # Note: if phase4 already set a category (e.g. Firewall, Domain Controller),
        # preserve it; classify_device is used as the primary classifier but DC/Firewall
        # overrides from phase4 take precedence.
        phase4_category = host.get("category", "")
        new_category = classify_device(
            open_ports=list(ports_set),
            mac=host.get("mac", ""),
            hostname=host.get("hostname", "") or "",
            snmp_info=snmp or None,
            version_info=services or None,
        )
        # Keep phase4 override for Firewall and Domain Controller (high-confidence)
        if phase4_category in ("Firewall", "Domain Controller"):
            host["category"] = phase4_category
        else:
            host["category"] = new_category

        # Fallback: use OS guess if still unknown
        if host["category"] == "Unknown Device" and host.get("os_guess"):
            os_g = host["os_guess"].lower()
            if "windows" in os_g:
                host["category"] = "Windows Device"
            elif "linux" in os_g:
                host["category"] = "Linux/Unix Device"
            elif "cisco" in os_g or "ios" in os_g:
                host["category"] = "Network Infrastructure"

    logger.info(f"  Security analysis complete. {total_flags} observations across {len(hosts)} hosts.")
    return hosts


# ══════════════════════════════════════════════════════════════════════════
# Extended Discovery Phases (7–12)
# ══════════════════════════════════════════════════════════════════════════


# ── Phase 7: WiFi Network Enumeration ─────────────────────────────────────

def _parse_iw_scan(output: str) -> list:
    """Parse 'iw dev <iface> scan' output into a list of network dicts."""
    networks = []
    current = None

    for line in output.splitlines():
        line = line.strip()
        if line.startswith("BSS "):
            if current:
                networks.append(current)
            bssid_match = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
            current = {
                "ssid": "",
                "bssid": bssid_match.group(1).upper() if bssid_match else "",
                "channel": 0,
                "frequency": "",
                "signal_dbm": -100,
                "signal_quality": "Weak",
                "encryption": "Open",
                "hidden": False,
                "band": "Unknown",
            }
        elif current is None:
            continue
        elif line.startswith("SSID:"):
            ssid = line[5:].strip()
            if not ssid:
                current["hidden"] = True
                current["ssid"] = "(Hidden)"
            else:
                current["ssid"] = ssid
        elif line.startswith("freq:"):
            try:
                freq = int(line.split(":")[1].strip())
                current["frequency"] = f"{freq} MHz"
                current["channel"] = freq_to_channel(freq)
                current["band"] = freq_to_band(freq)
            except (ValueError, IndexError):
                pass
        elif line.startswith("signal:"):
            try:
                dbm = float(line.split(":")[1].strip().split()[0])
                current["signal_dbm"] = int(dbm)
                current["signal_quality"] = signal_quality(int(dbm))
            except (ValueError, IndexError):
                pass
        elif "WPA" in line or "RSN" in line or "WEP" in line:
            if "WPA2" in line or "RSN" in line:
                current["encryption"] = "WPA2"
            elif "WPA" in line:
                current["encryption"] = "WPA"
            elif "WEP" in line:
                current["encryption"] = "WEP"
        elif "SAE" in line:
            current["encryption"] = "WPA3"

    if current:
        networks.append(current)

    # Refine encryption — if we saw both RSN and SAE entries for same BSS,
    # mark as WPA3.  For now the simple heuristic above is good enough.
    return networks


def _parse_iwlist_scan(output: str) -> list:
    """Fallback parser for 'iwlist <iface> scan' output."""
    networks = []
    current = None

    for line in output.splitlines():
        line = line.strip()
        if "Cell " in line and "Address:" in line:
            if current:
                networks.append(current)
            bssid_match = re.search(r"Address:\s*([0-9A-Fa-f:]{17})", line)
            current = {
                "ssid": "",
                "bssid": bssid_match.group(1).upper() if bssid_match else "",
                "channel": 0,
                "frequency": "",
                "signal_dbm": -100,
                "signal_quality": "Weak",
                "encryption": "Open",
                "hidden": False,
                "band": "Unknown",
            }
        elif current is None:
            continue
        elif "ESSID:" in line:
            match = re.search(r'ESSID:"(.*)"', line)
            ssid = match.group(1) if match else ""
            if not ssid:
                current["hidden"] = True
                current["ssid"] = "(Hidden)"
            else:
                current["ssid"] = ssid
        elif "Frequency:" in line:
            match = re.search(r"Frequency:(\d+\.?\d*)\s*GHz.*Channel\s+(\d+)", line)
            if match:
                freq_ghz = float(match.group(1))
                ch = int(match.group(2))
                current["frequency"] = f"{int(freq_ghz * 1000)} MHz"
                current["channel"] = ch
                current["band"] = freq_to_band(int(freq_ghz * 1000))
        elif "Signal level=" in line:
            match = re.search(r"Signal level=(-?\d+)\s*dBm", line)
            if match:
                dbm = int(match.group(1))
                current["signal_dbm"] = dbm
                current["signal_quality"] = signal_quality(dbm)
        elif "Encryption key:on" in line:
            if current["encryption"] == "Open":
                current["encryption"] = "WEP"
        elif "WPA2" in line or "RSN" in line:
            current["encryption"] = "WPA2"
        elif "WPA " in line:
            if current["encryption"] not in ("WPA2", "WPA3"):
                current["encryption"] = "WPA"

    if current:
        networks.append(current)
    return networks


def _build_channel_analysis(networks: list) -> dict:
    """Aggregate WiFi networks into channel congestion maps."""
    ch_24 = {}
    ch_5 = {}

    for net in networks:
        ch = net.get("channel", 0)
        dbm = net.get("signal_dbm", -100)
        band = net.get("band", "Unknown")

        if band == "2.4GHz" and 1 <= ch <= 14:
            if ch not in ch_24:
                ch_24[ch] = {"count": 0, "strongest_dbm": -100}
            ch_24[ch]["count"] += 1
            ch_24[ch]["strongest_dbm"] = max(ch_24[ch]["strongest_dbm"], dbm)
        elif band == "5GHz" and ch > 0:
            if ch not in ch_5:
                ch_5[ch] = {"count": 0, "strongest_dbm": -100}
            ch_5[ch]["count"] += 1
            ch_5[ch]["strongest_dbm"] = max(ch_5[ch]["strongest_dbm"], dbm)

    # Ensure common 2.4 GHz channels are present even if zero
    for ch in (1, 6, 11):
        if ch not in ch_24:
            ch_24[ch] = {"count": 0, "strongest_dbm": -100}

    most_cong_24 = max(ch_24.items(), key=lambda x: x[1]["count"], default=(0, {"count": 0}))
    least_cong_24 = min(
        ((c, d) for c, d in ch_24.items() if c in (1, 6, 11)),
        key=lambda x: x[1]["count"], default=(0, {"count": 0}),
    )
    most_cong_5 = max(ch_5.items(), key=lambda x: x[1]["count"], default=(0, {"count": 0}))
    least_cong_5 = min(ch_5.items(), key=lambda x: x[1]["count"], default=(0, {"count": 0}))

    # Build recommendation
    rec_parts = []
    if ch_24:
        rec_parts.append(
            f"2.4 GHz: Use channel {least_cong_24[0]} "
            f"({least_cong_24[1]['count']} networks)"
        )
    if ch_5:
        rec_parts.append(
            f"5 GHz: Use channel {least_cong_5[0]} "
            f"({least_cong_5[1]['count']} networks)"
        )

    return {
        "2.4ghz": {str(k): v for k, v in sorted(ch_24.items())},
        "5ghz": {str(k): v for k, v in sorted(ch_5.items())},
        "most_congested_24": {"channel": most_cong_24[0], "count": most_cong_24[1]["count"]},
        "least_congested_24": {"channel": least_cong_24[0], "count": least_cong_24[1]["count"]},
        "most_congested_5": {"channel": most_cong_5[0], "count": most_cong_5[1]["count"]},
        "least_congested_5": {"channel": least_cong_5[0], "count": least_cong_5[1]["count"]},
        "recommendation": " | ".join(rec_parts) if rec_parts else "No WiFi networks detected.",
    }


def phase7_wifi_scan(config: dict) -> dict:
    """Phase 7: Passive WiFi network enumeration and channel analysis."""
    logger.info("[Phase 7] WiFi Network Enumeration...")

    wifi_iface = config.get("wifi_interface", "auto")
    timeout = config.get("wifi_scan_timeout", 30)

    # Auto-detect WiFi interface
    if wifi_iface == "auto":
        ifaces = get_wifi_interfaces()
        if not ifaces:
            logger.info("  No WiFi interfaces detected. Skipping WiFi scan.")
            return {"wifi_interface": None, "scan_success": False, "networks": [],
                    "channel_analysis": {}, "summary": {"total_networks": 0}}
        wifi_iface = ifaces[0]
        logger.info(f"  Auto-detected WiFi interface: {wifi_iface}")

    # Try 'iw dev <iface> scan' first (preferred)
    networks = []
    try:
        result = subprocess.run(
            ["iw", "dev", wifi_iface, "scan"],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            networks = _parse_iw_scan(result.stdout)
            logger.info(f"  iw scan found {len(networks)} networks.")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug(f"  iw scan failed: {e}")

    # Fallback to iwlist
    if not networks:
        try:
            result = subprocess.run(
                ["iwlist", wifi_iface, "scan"],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                networks = _parse_iwlist_scan(result.stdout)
                logger.info(f"  iwlist scan found {len(networks)} networks.")
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.warning(f"  WiFi scan failed (both iw and iwlist): {e}")

    # Deduplicate by BSSID
    seen_bssids = set()
    unique_networks = []
    for net in networks:
        bssid = net.get("bssid", "")
        if bssid and bssid not in seen_bssids:
            seen_bssids.add(bssid)
            unique_networks.append(net)
    networks = unique_networks

    # Sort by signal strength (strongest first)
    networks.sort(key=lambda n: n.get("signal_dbm", -100), reverse=True)

    # Channel analysis
    channel_analysis = _build_channel_analysis(networks)

    # Summary
    summary = {
        "total_networks": len(networks),
        "hidden_networks": sum(1 for n in networks if n.get("hidden")),
        "open_networks": sum(1 for n in networks if n.get("encryption") == "Open"),
        "wep_networks": sum(1 for n in networks if n.get("encryption") == "WEP"),
        "wpa2_networks": sum(1 for n in networks if n.get("encryption") == "WPA2"),
        "wpa3_networks": sum(1 for n in networks if n.get("encryption") == "WPA3"),
    }

    logger.info(
        f"  WiFi scan complete: {summary['total_networks']} networks, "
        f"{summary['open_networks']} open, {summary['hidden_networks']} hidden."
    )
    return {
        "wifi_interface": wifi_iface,
        "scan_success": True,
        "networks": networks,
        "channel_analysis": channel_analysis,
        "summary": summary,
    }


# ── Phase 8: mDNS / Bonjour Service Discovery ─────────────────────────────

def phase8_mdns_discovery(config: dict) -> dict:
    """Phase 8: Discover mDNS/Bonjour services on the local network."""
    logger.info("[Phase 8] mDNS / Bonjour Service Discovery...")
    timeout = config.get("mdns_timeout", 10)

    services = []

    # Primary: avahi-browse (most reliable on Linux)
    try:
        result = subprocess.run(
            ["avahi-browse", "-apt", "--resolve", "--no-db-lookup"],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.splitlines():
                if not line.startswith("="):
                    continue
                parts = line.split(";")
                if len(parts) < 10:
                    continue
                # =;iface;protocol;name;type;domain;hostname;address;port;txt
                try:
                    svc = {
                        "service_type": parts[4].strip(),
                        "name": parts[3].strip(),
                        "hostname": parts[6].strip(),
                        "ip": parts[7].strip(),
                        "port": int(parts[8].strip()) if parts[8].strip().isdigit() else 0,
                        "txt_records": parts[9].strip() if len(parts) > 9 else "",
                    }
                    # Skip IPv6 link-local
                    if ":" in svc["ip"]:
                        continue
                    services.append(svc)
                except (IndexError, ValueError):
                    continue
            logger.info(f"  avahi-browse found {len(services)} services.")
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        logger.debug(f"  avahi-browse not available or timed out: {e}")

    # Fallback: avahi-browse without --resolve (faster, less data)
    if not services:
        try:
            result = subprocess.run(
                ["avahi-browse", "-apt"],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.splitlines():
                    if not line.startswith("+"):
                        continue
                    parts = line.split(";")
                    if len(parts) >= 5:
                        services.append({
                            "service_type": parts[4].strip(),
                            "name": parts[3].strip(),
                            "hostname": "",
                            "ip": "",
                            "port": 0,
                            "txt_records": "",
                        })
                logger.info(f"  avahi-browse (unresolved) found {len(services)} services.")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("  avahi-utils not available. mDNS discovery skipped.")

    # Deduplicate by (name, service_type, ip)
    seen = set()
    unique = []
    for s in services:
        key = (s["name"], s["service_type"], s["ip"])
        if key not in seen:
            seen.add(key)
            unique.append(s)
    services = unique

    # Summary
    service_types = list(set(s["service_type"] for s in services))
    unique_hosts = len(set(s["ip"] for s in services if s["ip"]))

    logger.info(f"  mDNS discovery complete: {len(services)} services from {unique_hosts} hosts.")
    return {
        "mdns_available": len(services) > 0,
        "services": services,
        "summary": {
            "total_services": len(services),
            "service_types_found": sorted(service_types),
            "unique_hosts": unique_hosts,
        },
    }


# ── Phase 9: UPnP / SSDP Discovery ───────────────────────────────────────

def _fetch_ssdp_description(location_url: str, timeout: float = 3.0) -> dict:
    """Fetch and parse a UPnP device description XML."""
    info = {"friendly_name": "", "manufacturer": "", "model_name": "", "device_type": ""}
    try:
        req = urllib.request.Request(location_url, headers={"User-Agent": "YW-Discovery/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            xml_data = resp.read(32768)  # Cap at 32 KB
        root = ET.fromstring(xml_data)
        ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}
        device = root.find(".//upnp:device", ns)
        if device is None:
            # Try without namespace
            device = root.find(".//{urn:schemas-upnp-org:device-1-0}device")
        if device is not None:
            for tag, key in [
                ("friendlyName", "friendly_name"),
                ("manufacturer", "manufacturer"),
                ("modelName", "model_name"),
                ("deviceType", "device_type"),
            ]:
                el = device.find(f"upnp:{tag}", ns) or device.find(
                    f"{{urn:schemas-upnp-org:device-1-0}}{tag}"
                )
                if el is not None and el.text:
                    info[key] = el.text.strip()
    except Exception:
        pass
    return info


def phase9_ssdp_discovery(config: dict) -> dict:
    """Phase 9: UPnP / SSDP device discovery via M-SEARCH multicast."""
    logger.info("[Phase 9] UPnP / SSDP Discovery...")
    timeout = config.get("ssdp_timeout", 5)

    ssdp_addr = ("239.255.255.250", 1900)
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    responses = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(msearch.encode(), ssdp_addr)

        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(4096)
                responses.append((data.decode("utf-8", errors="replace"), addr[0]))
            except socket.timeout:
                break
    except Exception as e:
        logger.warning(f"  SSDP M-SEARCH failed: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # Parse SSDP responses
    devices = []
    seen_usns = set()
    for resp_text, resp_ip in responses:
        headers = {}
        for line in resp_text.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().upper()] = val.strip()

        usn = headers.get("USN", "")
        if not usn or usn in seen_usns:
            continue
        seen_usns.add(usn)

        location = headers.get("LOCATION", "")
        device = {
            "usn": usn,
            "service_type": headers.get("ST", ""),
            "location": location,
            "ip": resp_ip,
            "friendly_name": "",
            "manufacturer": "",
            "model_name": "",
            "device_type": "",
        }
        devices.append(device)

    # Fetch device descriptions (limit to 20 to keep scan fast)
    locations_fetched = set()
    for dev in devices[:20]:
        loc = dev.get("location", "")
        if loc and loc not in locations_fetched:
            locations_fetched.add(loc)
            desc = _fetch_ssdp_description(loc)
            dev.update(desc)
            # Also update other devices with same location
            for other in devices:
                if other.get("location") == loc and other is not dev:
                    for k in ("friendly_name", "manufacturer", "model_name", "device_type"):
                        if not other.get(k):
                            other[k] = desc.get(k, "")

    # Deduplicate by IP + friendly_name
    unique_devices = []
    seen = set()
    for d in devices:
        key = (d["ip"], d.get("friendly_name", "") or d.get("usn", ""))
        if key not in seen:
            seen.add(key)
            unique_devices.append(d)
    devices = unique_devices

    device_types = list(set(d.get("device_type", "") for d in devices if d.get("device_type")))
    logger.info(f"  SSDP discovery complete: {len(devices)} devices found.")
    return {
        "ssdp_available": len(devices) > 0,
        "devices": devices,
        "summary": {
            "total_devices": len(devices),
            "device_types": sorted(device_types),
        },
    }


# ── Phase 10: DHCP Scope Analysis ──────────────────────────────────────────

def phase10_dhcp_analysis(recon: dict, config: dict) -> dict:
    """Phase 10: Detect DHCP servers and analyze scope configuration.

    Uses scapy to send DHCP DISCOVER and collect OFFER responses.
    Falls back to parsing current lease info from dhclient if scapy fails.
    """
    logger.info("[Phase 10] DHCP Scope Analysis...")
    timeout = config.get("dhcp_timeout", 10)
    expected_gateway = recon.get("default_gateway", "")

    dhcp_servers = []

    # Method 1: scapy DHCP DISCOVER
    try:
        from scapy.all import (
            BOOTP, DHCP, IP, UDP, Ether, conf, get_if_hwaddr, sendp, sniff,
        )

        # Get the active interface MAC
        iface = conf.iface
        try:
            hw = get_if_hwaddr(iface)
        except Exception:
            hw = "de:ad:be:ef:ca:fe"

        mac_bytes = bytes.fromhex(hw.replace(":", ""))

        pkt = (
            Ether(dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=mac_bytes, xid=0x12345678)
            / DHCP(options=[("message-type", "discover"), "end"])
        )

        # Send and collect offers
        logger.debug("  Sending DHCP DISCOVER...")
        sendp(pkt, verbose=0, count=1)

        def _is_dhcp_offer(p):
            return (
                p.haslayer(DHCP)
                and any(
                    opt[0] == "message-type" and opt[1] == 2  # OFFER
                    for opt in p[DHCP].options
                    if isinstance(opt, tuple) and len(opt) >= 2
                )
            )

        offers = sniff(filter="udp and port 68", timeout=timeout, lfilter=_is_dhcp_offer)

        for offer in offers:
            dhcp_opts = {
                opt[0]: opt[1]
                for opt in offer[DHCP].options
                if isinstance(opt, tuple) and len(opt) >= 2
            }
            server_ip = dhcp_opts.get("server_id", offer[IP].src if offer.haslayer(IP) else "")
            srv = {
                "server_ip": str(server_ip),
                "offered_ip": offer[BOOTP].yiaddr if offer.haslayer(BOOTP) else "",
                "subnet_mask": str(dhcp_opts.get("subnet_mask", "")),
                "gateway": str(dhcp_opts.get("router", "")),
                "dns_servers": [],
                "lease_time": int(dhcp_opts.get("lease_time", 0)),
                "domain_name": str(dhcp_opts.get("domain", "")),
            }
            # DNS servers may come as a list or single IP
            name_server = dhcp_opts.get("name_server", "")
            if name_server:
                if isinstance(name_server, (list, tuple)):
                    srv["dns_servers"] = [str(ns) for ns in name_server]
                else:
                    srv["dns_servers"] = [str(name_server)]
            dhcp_servers.append(srv)

        logger.info(f"  DHCP DISCOVER received {len(dhcp_servers)} OFFER(s).")

    except ImportError:
        logger.info("  scapy not available. Trying lease file fallback.")
    except Exception as e:
        logger.warning(f"  DHCP DISCOVER failed: {e}")

    # Method 2: Fallback — parse current DHCP lease
    if not dhcp_servers:
        lease_files = [
            "/var/lib/dhcp/dhclient.leases",
            "/var/lib/dhcpcd5/dhcpcd-eth0.lease",
            "/var/lib/dhcpcd/dhcpcd-eth0.lease",
        ]
        for lf in lease_files:
            try:
                with open(lf) as f:
                    content = f.read()
                # Simple parse for the last lease block
                blocks = content.split("lease {")
                if len(blocks) > 1:
                    last = blocks[-1]
                    srv = {"server_ip": "", "offered_ip": "", "subnet_mask": "",
                           "gateway": "", "dns_servers": [], "lease_time": 0,
                           "domain_name": ""}
                    for line in last.splitlines():
                        line = line.strip().rstrip(";")
                        if "dhcp-server-identifier" in line:
                            srv["server_ip"] = line.split()[-1]
                        elif "fixed-address" in line:
                            srv["offered_ip"] = line.split()[-1]
                        elif "subnet-mask" in line:
                            srv["subnet_mask"] = line.split()[-1]
                        elif line.startswith("option routers"):
                            srv["gateway"] = line.split()[-1]
                        elif "domain-name-servers" in line:
                            servers_str = line.split("domain-name-servers")[-1].strip()
                            srv["dns_servers"] = [s.strip() for s in servers_str.split(",")]
                        elif "dhcp-lease-time" in line:
                            try:
                                srv["lease_time"] = int(line.split()[-1])
                            except ValueError:
                                pass
                        elif line.startswith("option domain-name "):
                            srv["domain_name"] = line.split('"')[1] if '"' in line else ""
                    if srv["server_ip"]:
                        dhcp_servers.append(srv)
                        logger.info(f"  Found DHCP lease info from {lf}")
                        break
            except (FileNotFoundError, PermissionError):
                continue

    # Rogue detection
    rogue_warning = False
    if len(dhcp_servers) > 1:
        unique_servers = set(s["server_ip"] for s in dhcp_servers)
        if len(unique_servers) > 1:
            rogue_warning = True
            logger.warning(
                f"  ROGUE DHCP WARNING: {len(unique_servers)} different DHCP servers detected: "
                f"{unique_servers}"
            )
    elif len(dhcp_servers) == 1 and expected_gateway:
        # Flag if DHCP server isn't the gateway (could be rogue)
        if dhcp_servers[0]["server_ip"] != expected_gateway:
            logger.info(
                f"  Note: DHCP server ({dhcp_servers[0]['server_ip']}) "
                f"differs from gateway ({expected_gateway})."
            )

    logger.info(f"  DHCP analysis complete: {len(dhcp_servers)} server(s) detected.")
    return {
        "dhcp_servers": dhcp_servers,
        "rogue_server_warning": rogue_warning,
        "summary": {
            "server_count": len(dhcp_servers),
            "is_rogue_detected": rogue_warning,
        },
    }


# ── Phase 11: NTP Server Detection ───────────────────────────────────────

def _query_ntp_server(ip: str, timeout: float = 3.0) -> Optional[dict]:
    """Send an NTP client query and parse the response."""
    NTP_PORT = 123
    # NTP v3 client mode packet: LI=0, VN=3, Mode=3 → byte 0 = 0b00_011_011 = 0x1B
    ntp_packet = b"\x1b" + b"\x00" * 47

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(ntp_packet, (ip, NTP_PORT))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) < 48:
            return None

        stratum = data[1]
        ref_id_bytes = data[12:16]

        # Stratum 0 = kiss-of-death, 1 = primary reference (GPS, atomic, etc.)
        if stratum == 0:
            return None

        if stratum == 1:
            ref_str = ref_id_bytes.decode("ascii", errors="replace").strip("\x00")
        else:
            ref_str = ".".join(str(b) for b in ref_id_bytes)

        return {
            "ip": ip,
            "stratum": stratum,
            "reference": ref_str,
        }
    except Exception:
        return None


def phase11_ntp_detection(hosts: list, recon: dict, config: dict) -> dict:
    """Phase 11: Detect NTP servers on the network."""
    logger.info("[Phase 11] NTP Server Detection...")
    timeout = config.get("ntp_timeout", 3)

    ntp_servers = []

    # Check Pi's own NTP status
    system_ntp = {"configured_servers": [], "synchronized": False}
    try:
        result = subprocess.run(
            ["timedatectl", "show", "--property=NTPSynchronized,NTP"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "NTPSynchronized=yes" in line:
                    system_ntp["synchronized"] = True
                elif "NTP=yes" in line:
                    system_ntp["synchronized"] = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try chronyc sources for configured servers
    try:
        result = subprocess.run(
            ["chronyc", "sources", "-n"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("^*", "^+", "^-", "^?"):
                    system_ntp["configured_servers"].append(parts[1])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Probe candidate IPs: gateway, DNS servers, and any hosts with port 123
    candidates = set()
    gw = recon.get("default_gateway")
    if gw:
        candidates.add(gw)
    for dns in recon.get("dns_servers", []):
        candidates.add(dns)
    for host in hosts:
        if 123 in host.get("open_ports", []):
            candidates.add(host["ip"])

    logger.info(f"  Probing {len(candidates)} NTP candidates...")
    for ip in candidates:
        result = _query_ntp_server(ip, timeout=timeout)
        if result:
            ntp_servers.append(result)
            logger.debug(f"  NTP server found: {ip} (stratum {result['stratum']})")

    logger.info(f"  NTP detection complete: {len(ntp_servers)} server(s) found.")
    return {
        "ntp_servers": ntp_servers,
        "system_ntp": system_ntp,
        "summary": {
            "ntp_server_count": len(ntp_servers),
            "is_synchronized": system_ntp["synchronized"],
        },
    }


# ── Phase 12: 802.1X / NAC Detection ──────────────────────────────────────

def phase12_nac_detection(config: dict) -> dict:
    """Phase 12: Detect whether the switch port enforces 802.1X / NAC."""
    logger.info("[Phase 12] 802.1X / NAC Detection...")

    eap_found = False
    evidence_parts = []

    # Check journalctl for EAP / 802.1X messages
    try:
        result = subprocess.run(
            ["journalctl", "-b", "--no-pager", "-g", "EAP|802.1X|EAPOL|wpa_supplicant"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            # Filter for actual EAP-related lines (not just "No entries")
            lines = [l for l in result.stdout.splitlines() if any(
                kw in l.upper() for kw in ("EAP", "EAPOL", "802.1X")
            )]
            if lines:
                eap_found = True
                evidence_parts.append(f"Found {len(lines)} EAP/802.1X message(s) in journal")
        if not eap_found:
            evidence_parts.append("No EAP/802.1X messages in journal")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        evidence_parts.append("journalctl not available")

    # Check dmesg for EAPOL frames
    checked_dmesg = False
    try:
        result = subprocess.run(
            ["dmesg"], capture_output=True, text=True, timeout=5,
        )
        checked_dmesg = True
        if result.returncode == 0:
            eap_lines = [l for l in result.stdout.splitlines() if any(
                kw in l.upper() for kw in ("EAP", "EAPOL", "802.1X")
            )]
            if eap_lines:
                eap_found = True
                evidence_parts.append(f"Found {len(eap_lines)} EAP reference(s) in dmesg")
            else:
                evidence_parts.append("No EAP references in dmesg")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        evidence_parts.append("dmesg not available")

    # If we're running and have an IP, DHCP succeeded
    dhcp_clean = True
    evidence_parts.append("DHCP obtained successfully (device is operational)")

    if eap_found:
        nac_detected = True
        evidence = "802.1X/NAC activity detected: " + "; ".join(evidence_parts)
    else:
        nac_detected = False
        evidence = "No NAC enforced: " + "; ".join(evidence_parts)

    logger.info(f"  NAC detection: {'DETECTED' if nac_detected else 'Not detected'}")
    return {
        "nac_detected": nac_detected,
        "evidence": evidence,
        "eap_messages_found": eap_found,
        "details": {
            "checked_journal": True,
            "checked_dmesg": checked_dmesg,
            "dhcp_obtained_cleanly": dhcp_clean,
        },
    }


# ── Phase 13: OSINT / External Reconnaissance ──────────────────────────────


def _derive_domains(recon: dict, hosts: list, dhcp_results: dict,
                    config: dict = None) -> list:
    """Derive likely company domain names from scan data.

    Sources (in priority order):
      0. from_email in config — the M365-licensed sender address is admin-specified
         and is by far the most reliable indicator of the actual business domain.
      1. AD domain names from LDAP probes (e.g. corp.contoso.com → contoso.com)
      2. DHCP domain name (e.g. office.local → skip, but office.acme.com → acme.com)
      3. SSL certificate common names / SANs from HTTPS services on the LAN

    NOTE: the public IP's reverse PTR hostname is NOT used — it resolves to the
    ISP's domain, not the customer's business domain.

    Returns a deduplicated list of domain strings with the from_email domain first.
    """
    domains = []          # ordered list — from_email domain goes first
    domains_seen = set()  # for dedup

    internal_tlds = {".local", ".internal", ".lan", ".home", ".corp", ".localdomain", ".test"}

    def _is_public(d: str) -> bool:
        return bool(d and not any(d.endswith(tld) for tld in internal_tlds))

    def _extract_registrable(fqdn: str) -> str:
        """Best-effort extraction of the registrable domain.
        e.g. 'mail.corp.contoso.com' → 'contoso.com'."""
        parts = fqdn.strip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return fqdn

    def _add(domain: str) -> None:
        if domain and domain not in domains_seen:
            domains.append(domain)
            domains_seen.add(domain)

    # 0. From-email domain (highest confidence — admin-specified, M365-licensed)
    if config:
        from_email = (config.get("graph_api") or {}).get("from_email", "")
        if from_email and "@" in from_email:
            email_domain = from_email.split("@", 1)[1].strip().lower()
            if email_domain and _is_public(email_domain):
                _add(email_domain)

    # 1. AD domain names
    for host in hosts:
        ad = host.get("ad_info") or {}
        dn = ad.get("domain_name", "")
        if dn and _is_public(dn):
            _add(_extract_registrable(dn))

    # 2. DHCP domain
    for srv in (dhcp_results or {}).get("dhcp_servers", []):
        dn = srv.get("domain_name", "")
        if dn and _is_public(dn):
            _add(_extract_registrable(dn))

    # 3. Public IP hostname from ipinfo.io.
    # ipinfo.io populates this from PTR records, but for some business ISPs the
    # PTR IS the customer's hostname (e.g. "wg.pacificoffice.com" set by the
    # customer).  We filter out ISP-style PTR encodings via _ISP_PTR_RE.
    pub_hostname = (recon.get("public_ip_info") or {}).get("hostname", "")
    if pub_hostname and _is_public(pub_hostname) and not _ISP_PTR_RE.search(pub_hostname):
        _add(_extract_registrable(pub_hostname))

    # 5. SSL cert common names (harvested during service enum)
    for host in hosts:
        for svc in host.get("services", {}).values():
            ssl_cn = svc.get("ssl_cn", "")
            if ssl_cn and _is_public(ssl_cn) and not ssl_cn.startswith("*"):
                _add(_extract_registrable(ssl_cn))
            for san in svc.get("ssl_sans", []):
                if san and _is_public(san) and not san.startswith("*"):
                    _add(_extract_registrable(san))

    return domains  # ordered: from_email first, then discovery sources


def _whois_rdap(ip: str, timeout: int = 8) -> dict:
    """Query RDAP (Registration Data Access Protocol) for IP WHOIS data.
    Falls back to whois CLI if RDAP fails.
    Returns dict with org, netname, cidr, country, etc."""
    result = {
        "ip": ip,
        "organization": "",
        "net_name": "",
        "cidr": "",
        "country": "",
        "description": "",
    }

    # Try RDAP first (JSON, no parsing headaches)
    try:
        url = f"https://rdap.arin.net/registry/ip/{ip}"
        req = urllib.request.Request(
            url, headers={"Accept": "application/rdap+json",
                          "User-Agent": "YeylandWutani-NetworkDiscovery/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())

        result["net_name"] = data.get("name", "")
        result["cidr"] = data.get("handle", "")

        # Walk entities for org / registrant
        for entity in data.get("entities", []):
            vcard = entity.get("vcardArray", [None, []])
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4:
                        if item[0] == "fn":
                            result["organization"] = str(item[3])
                            break
            roles = entity.get("roles", [])
            if "registrant" in roles or "abuse" in roles:
                # Prefer registrant org
                inner_vcard = entity.get("vcardArray", [None, []])
                if isinstance(inner_vcard, list) and len(inner_vcard) > 1:
                    for item in inner_vcard[1]:
                        if isinstance(item, list) and len(item) >= 4:
                            if item[0] == "fn":
                                result["organization"] = str(item[3])
                                break

        # Country from links or events
        for link in data.get("links", []):
            href = link.get("href", "")
            if "ripe.net" in href:
                result["country"] = "EU (RIPE NCC)"
            elif "apnic.net" in href:
                result["country"] = "APNIC"
            elif "arin.net" in href:
                result["country"] = "US (ARIN)"
            elif "lacnic.net" in href:
                result["country"] = "LACNIC"
            elif "afrinic.net" in href:
                result["country"] = "AFRINIC"

        if result["organization"]:
            return result

    except Exception as e:
        logger.debug(f"RDAP lookup failed for {ip}: {e}")

    # Fallback: whois CLI
    try:
        out = subprocess.run(
            ["whois", ip], capture_output=True, text=True, timeout=timeout,
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                lower = line.lower()
                if lower.startswith("orgname:") or lower.startswith("org-name:"):
                    result["organization"] = line.split(":", 1)[1].strip()
                elif lower.startswith("netname:"):
                    result["net_name"] = line.split(":", 1)[1].strip()
                elif lower.startswith("cidr:"):
                    result["cidr"] = line.split(":", 1)[1].strip()
                elif lower.startswith("country:"):
                    result["country"] = line.split(":", 1)[1].strip()
                elif lower.startswith("descr:") and not result["description"]:
                    result["description"] = line.split(":", 1)[1].strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.debug("whois CLI not available")

    return result


def _whois_rdap_domain(domain: str, timeout: int = 8) -> dict:
    """Query RDAP for domain-name registration data (registrant, registrar, dates).

    Uses rdap.org as a generic redirect gateway — it routes to the correct
    registry (Verisign, RIPE, ARIN, etc.) for any TLD automatically.

    Unlike IP WHOIS (which returns the ISP/netblock owner), domain RDAP returns
    the actual business that registered the domain name.
    """
    result = {
        "domain": domain,
        "registrant": "",
        "registrar": "",
        "created": "",
        "expires": "",
        "name_servers": [],
    }
    try:
        url = f"https://rdap.org/domain/{domain}"
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/rdap+json",
                "User-Agent": "YeylandWutani-NetworkDiscovery/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())

        # Registration / expiration dates
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate", "")[:10]  # ISO date only
            if action == "registration":
                result["created"] = date
            elif action == "expiration":
                result["expires"] = date

        # Name servers
        for ns in data.get("nameservers", []):
            ldhname = ns.get("ldhName", "")
            if ldhname:
                result["name_servers"].append(ldhname.lower())

        # Walk entities for registrant / registrar names
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [None, []])
            name = ""
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                        name = str(item[3])
                        break
            if "registrant" in roles and name and not result["registrant"]:
                result["registrant"] = name
            if "registrar" in roles and name and not result["registrar"]:
                result["registrar"] = name

        logger.debug(
            f"Domain RDAP {domain}: registrant='{result['registrant']}' "
            f"registrar='{result['registrar']}' created={result['created']}"
        )
    except Exception as e:
        logger.debug(f"Domain RDAP lookup failed for {domain}: {e}")

    return result


def _shodan_internetdb(ip: str, timeout: int = 8) -> dict:
    """Query Shodan InternetDB (free, no API key) for external attack surface.
    Returns open ports, vulns, hostnames, tags, CPEs visible from outside."""
    result = {
        "ip": ip,
        "ports": [],
        "vulns": [],
        "hostnames": [],
        "tags": [],
        "cpes": [],
    }
    try:
        url = f"https://internetdb.shodan.io/{ip}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "YeylandWutani-NetworkDiscovery/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())

        if "detail" in data and "not found" in str(data["detail"]).lower():
            # IP not indexed by Shodan
            return result

        result["ports"] = data.get("ports", [])
        result["vulns"] = data.get("vulns", [])
        result["hostnames"] = data.get("hostnames", [])
        result["tags"] = data.get("tags", [])
        result["cpes"] = data.get("cpes", [])

    except Exception as e:
        logger.debug(f"Shodan InternetDB lookup failed for {ip}: {e}")

    return result


def _crtsh_lookup(domain: str, timeout: int = 10) -> list:
    """Query crt.sh certificate transparency logs for subdomains.
    Returns list of unique domain names found in certificates."""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(
            url, headers={"User-Agent": "YeylandWutani-NetworkDiscovery/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())

        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*"):
                    subdomains.add(name)

        # Cap at 100 to avoid enormous results
        return sorted(subdomains)[:100]

    except Exception as e:
        logger.debug(f"crt.sh lookup failed for {domain}: {e}")
        return []


def _dns_security_check(domain: str, timeout: int = 5) -> dict:
    """Analyze MX, SPF, DKIM, DMARC records for an email domain.
    Returns dict with email infrastructure assessment."""
    result = {
        "domain": domain,
        "mx_records": [],
        "has_spf": False,
        "spf_record": "",
        "has_dmarc": False,
        "dmarc_record": "",
        "dmarc_policy": "",
        "has_dkim": False,
        "email_provider": "",
        "observations": [],
    }

    # MX records
    try:
        import subprocess as sp
        out = sp.run(
            ["dig", "+short", "MX", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        if out.returncode == 0:
            for line in out.stdout.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    priority = parts[0]
                    server = parts[1].rstrip(".")
                    result["mx_records"].append({
                        "priority": int(priority) if priority.isdigit() else 0,
                        "server": server,
                    })
            # Detect email provider
            mx_hosts = " ".join(m["server"].lower() for m in result["mx_records"])
            if "protection.outlook.com" in mx_hosts or "mail.protection" in mx_hosts:
                result["email_provider"] = "Microsoft 365"
            elif "google.com" in mx_hosts or "googlemail.com" in mx_hosts:
                result["email_provider"] = "Google Workspace"
            elif "pphosted.com" in mx_hosts or "proofpoint" in mx_hosts:
                result["email_provider"] = "Proofpoint"
            elif "mimecast" in mx_hosts:
                result["email_provider"] = "Mimecast"
            elif "barracuda" in mx_hosts:
                result["email_provider"] = "Barracuda"
            elif result["mx_records"]:
                result["email_provider"] = "Self-hosted / Other"
    except Exception as e:
        logger.debug(f"MX lookup failed for {domain}: {e}")

    # SPF record (TXT)
    try:
        out = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                cleaned = line.strip().strip('"')
                if "v=spf1" in cleaned.lower():
                    result["has_spf"] = True
                    result["spf_record"] = cleaned
                    if "-all" in cleaned:
                        result["observations"].append("SPF: Hard fail (-all) — good")
                    elif "~all" in cleaned:
                        result["observations"].append("SPF: Soft fail (~all) — acceptable")
                    elif "?all" in cleaned:
                        result["observations"].append(
                            "SPF: Neutral (?all) — weak, consider -all or ~all"
                        )
                    elif "+all" in cleaned:
                        result["observations"].append(
                            "SPF: Pass all (+all) — DANGEROUS, allows any sender"
                        )
                    break
            if not result["has_spf"]:
                result["observations"].append("No SPF record — email spoofing risk")
    except Exception as e:
        logger.debug(f"SPF lookup failed for {domain}: {e}")

    # DMARC record
    try:
        out = subprocess.run(
            ["dig", "+short", "TXT", f"_dmarc.{domain}"],
            capture_output=True, text=True, timeout=timeout,
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                cleaned = line.strip().strip('"')
                if "v=dmarc1" in cleaned.lower():
                    result["has_dmarc"] = True
                    result["dmarc_record"] = cleaned
                    # Extract policy
                    for part in cleaned.split(";"):
                        part = part.strip()
                        if part.lower().startswith("p="):
                            result["dmarc_policy"] = part.split("=", 1)[1].strip()
                    if result["dmarc_policy"] == "none":
                        result["observations"].append(
                            "DMARC: Policy 'none' — monitoring only, no enforcement"
                        )
                    elif result["dmarc_policy"] == "quarantine":
                        result["observations"].append(
                            "DMARC: Policy 'quarantine' — suspicious emails quarantined"
                        )
                    elif result["dmarc_policy"] == "reject":
                        result["observations"].append(
                            "DMARC: Policy 'reject' — strongest protection"
                        )
                    break
            if not result["has_dmarc"]:
                result["observations"].append("No DMARC record — email authentication gap")
    except Exception as e:
        logger.debug(f"DMARC lookup failed for {domain}: {e}")

    # DKIM — check common selectors
    dkim_selectors = ["google", "selector1", "selector2", "default", "dkim", "mail", "k1"]
    for selector in dkim_selectors:
        try:
            out = subprocess.run(
                ["dig", "+short", "TXT", f"{selector}._domainkey.{domain}"],
                capture_output=True, text=True, timeout=timeout,
            )
            if out.returncode == 0 and "v=dkim1" in out.stdout.lower():
                result["has_dkim"] = True
                result["observations"].append(
                    f"DKIM: Found (selector: {selector})"
                )
                break
        except Exception:
            pass

    if not result["has_dkim"]:
        result["observations"].append(
            "DKIM: Not found on common selectors — may use custom selector"
        )

    return result


# Hostname patterns that indicate an ISP/cloud-provider PTR record rather
# than a customer-owned domain.  Used in phase13 and _derive_domains.
_ISP_PTR_RE = re.compile(
    r'\b\d{1,3}[.\-]\d{1,3}[.\-]\d{1,3}'  # IP octets encoded in hostname
    r'|\.googleusercontent\.com$'           # Google Fiber / GCP reverse PTR
    r'|\.bc\.googleusercontent\.com$'
    r'|\.amazonaws\.com$'                   # AWS EC2 public hostnames
    r'|\.compute\.amazonaws\.com$'
    r'|\.cloudfront\.net$'                  # AWS CloudFront
    r'|\.azure\.com$|\.azurewebsites\.net$' # Azure
    r'|\.comcast\.net$|\.comcastbiz\.net$'  # Comcast
    r'|\.res\.spectrum\.com$'               # Charter / Spectrum
    r'|\.cox\.net$'                         # Cox
    r'|\.verizon\.net$'                     # Verizon
    r'|\.att\.net$|\.sbcglobal\.net$'       # AT&T
    r'|\.centurylink\.net$'                 # CenturyLink / Lumen
    r'|\.telepacific\.net$'                 # TelePacific
)


def _hackertarget_reverse_ip(ip: str, timeout: int = 10) -> list:
    """Query HackerTarget reverse-IP to find A records pointing at this IP.

    Unlike PTR / reverse DNS (which only returns what the netblock owner
    configured), HackerTarget's database is built from forward DNS crawls.
    So if 'wg.pacificoffice.com' has an A record pointing at 66.249.177.130,
    HackerTarget will return it even though the PTR says 'googleusercontent.com'.

    Free tier: 100 req/day, no API key required.
    Returns a list of hostname strings, empty on any failure.
    """
    hostnames: list = []
    try:
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        req = urllib.request.Request(
            url, headers={"User-Agent": "YeylandWutani-NetworkDiscovery/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
        # Response is one hostname per line; error/quota responses contain "error"
        if body and not body.lower().startswith("error") and "api count" not in body.lower():
            hostnames = [h.strip() for h in body.splitlines()
                         if h.strip() and "." in h]
    except Exception as e:
        logger.debug(f"HackerTarget reverse IP lookup failed for {ip}: {e}")
    return hostnames


def phase13_osint(recon: dict, hosts: list, dhcp_results: dict,
                  config: dict) -> dict:
    """Phase 13: OSINT / External Reconnaissance.

    Leverages the public IP from Phase 1 and derived domain names to perform:
      - WHOIS / RDAP lookup on public IP (organization, netblock)
      - Shodan InternetDB query (external attack surface, CVEs)
      - DNS security assessment (MX, SPF, DKIM, DMARC)
      - crt.sh certificate transparency (subdomain discovery)
    All lookups are free and require no API keys.
    """
    logger.info("[Phase 13] OSINT / External Reconnaissance...")
    osint_timeout = config.get("osint_timeout", 8)

    result = {
        "public_ip": "",
        "whois": {},
        "domain_whois": {},
        "shodan": {},
        "hackertarget_hostnames": [],
        "domains_discovered": [],
        "dns_security": [],
        "crtsh_subdomains": {},
        "company_identification": {},
        "summary": {
            "domains_found": 0,
            "external_ports": 0,
            "external_vulns": 0,
            "subdomains_found": 0,
            "email_provider": "",
            "email_security_score": "",
        },
    }

    pub_ip = recon.get("public_ip_info", {}).get("public_ip", "")
    result["public_ip"] = pub_ip

    # Derive company domains — from_email is source #0 and goes first in the list
    domains = _derive_domains(recon, hosts, dhcp_results, config)
    result["domains_discovered"] = domains
    result["summary"]["domains_found"] = len(domains)
    logger.info(f"  Derived {len(domains)} domain(s): {domains}")

    pub_info = recon.get("public_ip_info", {})

    # ── HackerTarget reverse IP — runs before domain WHOIS so found domains
    # are included in the WHOIS lookup.  HackerTarget crawls forward DNS records
    # (A records) not just PTR, so "wg.pacificoffice.com → 66.249.177.130" is
    # returned even when the PTR only says "*.googleusercontent.com".
    if pub_ip:
        logger.info(f"  HackerTarget reverse IP for {pub_ip}...")
        try:
            ht_hostnames = _hackertarget_reverse_ip(pub_ip, timeout=osint_timeout)
            result["hackertarget_hostnames"] = ht_hostnames
            for hostname in ht_hostnames:
                if _ISP_PTR_RE.search(hostname):
                    logger.debug(f"  Skipping ISP-style HackerTarget hostname: {hostname}")
                    continue
                parts = hostname.split(".")
                if len(parts) >= 2:
                    reg = ".".join(parts[-2:])
                    if reg not in domains:
                        domains.append(reg)
                        logger.info(f"  HackerTarget: added domain {reg} (from {hostname})")
            result["domains_discovered"] = domains
            result["summary"]["domains_found"] = len(domains)
        except Exception as e:
            logger.error(f"  HackerTarget lookup failed: {e}")

    # Compile company identification (after HackerTarget enrichment)
    result["company_identification"] = {
        "public_ip": pub_ip,
        "primary_domain": domains[0] if domains else "",
        "isp": pub_info.get("isp", ""),
        "city": pub_info.get("city", ""),
        "region": pub_info.get("region", ""),
        "country": pub_info.get("country", ""),
        "domains": domains,
        "domain_registrant": "",
        "domain_registrar": "",
        "domain_created": "",
    }

    # Domain WHOIS — look up the registrant of the business domain itself.
    # This gives the actual business name, unlike IP WHOIS which returns the ISP.
    if domains and config.get("enable_whois_lookup", True):
        primary_domain = domains[0]
        logger.info(f"  Domain WHOIS/RDAP for {primary_domain}...")
        try:
            domain_whois = _whois_rdap_domain(primary_domain, timeout=osint_timeout)
            result["domain_whois"] = domain_whois
            if domain_whois.get("registrant"):
                result["company_identification"]["domain_registrant"] = domain_whois["registrant"]
                logger.info(f"  Domain registrant: {domain_whois['registrant']}")
            if domain_whois.get("registrar"):
                result["company_identification"]["domain_registrar"] = domain_whois["registrar"]
            if domain_whois.get("created"):
                result["company_identification"]["domain_created"] = domain_whois["created"]
        except Exception as e:
            logger.error(f"  Domain WHOIS failed for {primary_domain}: {e}")

    # IP WHOIS / RDAP — identifies the ISP / netblock owner (not the business)
    if pub_ip and config.get("enable_whois_lookup", True):
        logger.info(f"  IP WHOIS/RDAP for {pub_ip}...")
        try:
            result["whois"] = _whois_rdap(pub_ip, timeout=osint_timeout)
            org = result["whois"].get("organization", "")
            if org:
                logger.info(f"  IP WHOIS org (ISP): {org}")
        except Exception as e:
            logger.error(f"  IP WHOIS lookup failed: {e}")

    # Shodan InternetDB (free, no API key)
    if pub_ip and config.get("enable_shodan_internetdb", True):
        logger.info(f"  Shodan InternetDB lookup for {pub_ip}...")
        try:
            result["shodan"] = _shodan_internetdb(pub_ip, timeout=osint_timeout)
            ext_ports = result["shodan"].get("ports", [])
            ext_vulns = result["shodan"].get("vulns", [])
            result["summary"]["external_ports"] = len(ext_ports)
            result["summary"]["external_vulns"] = len(ext_vulns)
            if ext_ports:
                logger.info(f"  Shodan: {len(ext_ports)} external port(s), "
                            f"{len(ext_vulns)} CVE(s)")
            # Merge Shodan hostnames into domain list, skipping ISP/cloud PTR records.
            # Uses the module-level _ISP_PTR_RE which covers IP-octet patterns,
            # Google, AWS, Azure, and major ISP reverse-DNS formats.
            for hostname in result["shodan"].get("hostnames", []):
                if _ISP_PTR_RE.search(hostname):
                    logger.debug(f"  Skipping ISP PTR-style Shodan hostname: {hostname}")
                    continue
                parts = hostname.split(".")
                if len(parts) >= 2:
                    reg_domain = ".".join(parts[-2:])
                    if reg_domain not in domains:
                        domains.append(reg_domain)
                        result["domains_discovered"] = domains
                        result["summary"]["domains_found"] = len(domains)
        except Exception as e:
            logger.error(f"  Shodan lookup failed: {e}")

    # DNS security assessment for each discovered domain
    if domains and config.get("enable_dns_security", True):
        for domain in domains[:5]:  # cap at 5 domains to avoid slow scans
            logger.info(f"  DNS security check for {domain}...")
            try:
                dns_result = _dns_security_check(domain, timeout=osint_timeout)
                result["dns_security"].append(dns_result)
                if dns_result.get("email_provider"):
                    result["summary"]["email_provider"] = dns_result["email_provider"]
            except Exception as e:
                logger.error(f"  DNS security check failed for {domain}: {e}")

    # Email security score (for first domain)
    if result["dns_security"]:
        first = result["dns_security"][0]
        score_parts = []
        if first.get("has_spf"):
            score_parts.append("SPF")
        if first.get("has_dkim"):
            score_parts.append("DKIM")
        if first.get("has_dmarc"):
            score_parts.append("DMARC")
        if len(score_parts) == 3:
            result["summary"]["email_security_score"] = "Strong"
        elif len(score_parts) == 2:
            result["summary"]["email_security_score"] = "Moderate"
        elif len(score_parts) == 1:
            result["summary"]["email_security_score"] = "Weak"
        else:
            result["summary"]["email_security_score"] = "None"

    # crt.sh certificate transparency
    total_subs = 0
    if domains and config.get("enable_crtsh_lookup", True):
        for domain in domains[:3]:  # cap at 3 domains
            logger.info(f"  crt.sh lookup for {domain}...")
            try:
                subs = _crtsh_lookup(domain, timeout=osint_timeout + 2)
                if subs:
                    result["crtsh_subdomains"][domain] = subs
                    total_subs += len(subs)
                    logger.info(f"  crt.sh: {len(subs)} subdomain(s) for {domain}")
            except Exception as e:
                logger.error(f"  crt.sh lookup failed for {domain}: {e}")
    result["summary"]["subdomains_found"] = total_subs

    logger.info(f"  OSINT complete: {len(domains)} domain(s), "
                f"{result['summary']['external_ports']} external port(s), "
                f"{total_subs} subdomain(s)")
    return result


# ── Phase 14: SSL/TLS Certificate Health Audit ─────────────────────────────

# Ports commonly serving TLS
_TLS_PORTS = {443, 8443, 636, 993, 995, 465, 587, 8080, 8444, 9443, 4443}

# Well-known public CA org keywords (for self-signed / internal CA detection)
_PUBLIC_CA_KEYWORDS = {
    "digicert", "let's encrypt", "letsencrypt", "comodo", "sectigo",
    "globalsign", "godaddy", "entrust", "verisign", "thawte",
    "geotrust", "rapidssl", "amazon", "starfield", "microsoft",
    "google trust", "isrg", "baltimore", "cybertrust", "usertrust",
    "buypass", "certum", "actalis", "affirmtrust", "quovadis",
    "ssl.com", "zerossl",
}


def _ssl_connect_and_inspect(ip: str, port: int, timeout: int = 5) -> dict:
    """Connect to an SSL/TLS service and extract full certificate details.

    Uses Python's ssl module to get richer data than nmap's ssl-cert script:
    signature algorithm, key size, SANs, issuer chain, serial.
    """
    result = {
        "ip": ip, "port": port, "subject_cn": "", "issuer_cn": "",
        "issuer_org": "", "sans": [], "not_before": "", "not_after": "",
        "days_remaining": None, "signature_algorithm": "",
        "key_size": 0, "is_self_signed": False, "serial": "",
        "protocol_version": "", "error": "",
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                result["protocol_version"] = ssock.version() or ""

                # Binary DER cert for algorithm + key size
                der_cert = ssock.getpeercert(binary_form=True)

                # Parsed cert dict (only available with CERT_NONE via binary)
                # We'll parse manually from DER using hashlib for serial
                # and ssl helpers for the rest
                cert = ssock.getpeercert()

                # If getpeercert() returns empty with CERT_NONE, re-parse
                if not cert and der_cert:
                    # Use openssl-style parsing from the binary cert
                    import subprocess as sp
                    proc = sp.run(
                        ["openssl", "x509", "-inform", "DER", "-noout",
                         "-subject", "-issuer", "-dates", "-serial",
                         "-ext", "subjectAltName",
                         "-text"],
                        input=der_cert, capture_output=True, timeout=timeout,
                    )
                    if proc.returncode == 0:
                        text = proc.stdout.decode("utf-8", errors="replace")
                        for line in text.splitlines():
                            line = line.strip()
                            if line.startswith("Subject:"):
                                cn_m = re.search(r"CN\s*=\s*([^,/]+)", line)
                                if cn_m:
                                    result["subject_cn"] = cn_m.group(1).strip()
                            elif line.startswith("Issuer:"):
                                cn_m = re.search(r"CN\s*=\s*([^,/]+)", line)
                                if cn_m:
                                    result["issuer_cn"] = cn_m.group(1).strip()
                                org_m = re.search(r"O\s*=\s*([^,/]+)", line)
                                if org_m:
                                    result["issuer_org"] = org_m.group(1).strip()
                            elif "Not Before" in line or "notBefore" in line:
                                result["not_before"] = line.split(":", 1)[1].strip()[:40] if ":" in line else ""
                            elif "Not After" in line or "notAfter" in line:
                                result["not_after"] = line.split(":", 1)[1].strip()[:40] if ":" in line else ""
                            elif line.startswith("serial="):
                                result["serial"] = line.split("=", 1)[1].strip()[:60]
                            elif "DNS:" in line:
                                for san_m in re.finditer(r"DNS:([^\s,]+)", line):
                                    result["sans"].append(san_m.group(1))

                        # Key size + algorithm
                        key_m = re.search(r"Public-Key:\s*\((\d+)\s*bit\)", text)
                        if key_m:
                            result["key_size"] = int(key_m.group(1))
                        sig_m = re.search(r"Signature Algorithm:\s*(\S+)", text)
                        if sig_m:
                            result["signature_algorithm"] = sig_m.group(1)

                else:
                    # Parse from Python cert dict
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    result["subject_cn"] = subject.get("commonName", "")
                    result["issuer_cn"] = issuer.get("commonName", "")
                    result["issuer_org"] = issuer.get("organizationName", "")
                    result["not_before"] = cert.get("notBefore", "")
                    result["not_after"] = cert.get("notAfter", "")
                    result["serial"] = cert.get("serialNumber", "")

                    for san_type, san_val in cert.get("subjectAltName", ()):
                        if san_type == "DNS":
                            result["sans"].append(san_val)

                # Self-signed check
                subj_cn = result["subject_cn"].lower()
                iss_cn = result["issuer_cn"].lower()
                if subj_cn and iss_cn and subj_cn == iss_cn:
                    result["is_self_signed"] = True

                # Days remaining
                for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S",
                            "%Y-%m-%d", "%b %d %H:%M:%S %Y"):
                    try:
                        exp = datetime.strptime(result["not_after"].strip(), fmt)
                        result["days_remaining"] = (exp - datetime.now()).days
                        break
                    except (ValueError, TypeError):
                        pass

    except (socket.timeout, ConnectionRefusedError, ConnectionResetError,
            OSError, ssl.SSLError) as e:
        result["error"] = str(e)[:80]
    except Exception as e:
        result["error"] = str(e)[:80]

    return result


def _assess_cert_health(cert: dict, config: dict) -> list:
    """Evaluate a certificate and return list of issue strings."""
    issues = []
    warn_days = config.get("ssl_cert_warning_days", 30)
    crit_days = config.get("ssl_cert_critical_days", 7)

    days = cert.get("days_remaining")
    if days is not None:
        if days < 0:
            issues.append(f"EXPIRED ({abs(days)} days ago)")
        elif days <= crit_days:
            issues.append(f"Expires in {days} day(s) — CRITICAL")
        elif days <= warn_days:
            issues.append(f"Expires in {days} day(s)")

    if cert.get("is_self_signed"):
        issues.append("Self-signed certificate")

    sig = (cert.get("signature_algorithm") or "").lower()
    if "md5" in sig:
        issues.append("Weak signature: MD5")
    elif "sha1" in sig and "sha1with" in sig:
        issues.append("Deprecated signature: SHA-1")

    key_size = cert.get("key_size", 0)
    if 0 < key_size < 2048:
        issues.append(f"Weak key: {key_size}-bit (min 2048)")

    # Check if issuer is internal (not a well-known public CA)
    issuer_lower = (cert.get("issuer_org") or cert.get("issuer_cn") or "").lower()
    if issuer_lower and not cert.get("is_self_signed"):
        is_public = any(kw in issuer_lower for kw in _PUBLIC_CA_KEYWORDS)
        if not is_public:
            issues.append(f"Internal/private CA: {cert.get('issuer_cn', 'Unknown')}")

    return issues


def phase14_ssl_audit(hosts: list, config: dict) -> dict:
    """Phase 14: SSL/TLS Certificate Health Audit.

    Two-pass approach:
      Pass 1: Analyse certs already captured by Phase 4 (nmap ssl-cert)
      Pass 2: Connect to every TLS-capable port with Python ssl to get
              richer data (signature algorithm, key size, SANs, issuer chain)
    """
    logger.info("[Phase 14] SSL/TLS Certificate Health Audit...")
    timeout = config.get("ssl_audit_timeout", 5)

    certificates = []
    seen = set()  # (ip, port) dedup
    internal_cas = set()

    for host in hosts:
        ip = host.get("ip", "")
        hostname = host.get("hostname", "N/A")
        ports_set = set(host.get("open_ports", []))
        tls_ports = sorted(ports_set & _TLS_PORTS)

        if not tls_ports:
            continue

        for port in tls_ports:
            if (ip, port) in seen:
                continue
            seen.add((ip, port))

            cert = _ssl_connect_and_inspect(ip, port, timeout=timeout)
            if cert.get("error") and not cert.get("subject_cn"):
                # Could not connect / no cert — skip
                continue

            cert["hostname"] = hostname
            cert["issues"] = _assess_cert_health(cert, config)

            # Track internal CAs
            issuer_lower = (cert.get("issuer_org") or cert.get("issuer_cn") or "").lower()
            if issuer_lower and not cert.get("is_self_signed"):
                is_public = any(kw in issuer_lower for kw in _PUBLIC_CA_KEYWORDS)
                if not is_public:
                    ca_name = cert.get("issuer_cn") or cert.get("issuer_org", "")
                    if ca_name:
                        internal_cas.add(ca_name)

            certificates.append(cert)

    # Summary counts
    expired = sum(1 for c in certificates if (c.get("days_remaining") or 999) < 0)
    warn_days = config.get("ssl_cert_warning_days", 30)
    crit_days = config.get("ssl_cert_critical_days", 7)
    expiring_30d = sum(
        1 for c in certificates
        if 0 <= (c.get("days_remaining") or 999) <= warn_days
    )
    expiring_7d = sum(
        1 for c in certificates
        if 0 <= (c.get("days_remaining") or 999) <= crit_days
    )
    self_signed = sum(1 for c in certificates if c.get("is_self_signed"))
    weak_key = sum(
        1 for c in certificates
        if 0 < (c.get("key_size") or 9999) < 2048
    )
    sha1_sig = sum(
        1 for c in certificates
        if "sha1" in (c.get("signature_algorithm") or "").lower()
    )

    logger.info(
        f"  SSL audit: {len(certificates)} cert(s) — {expired} expired, "
        f"{expiring_30d} expiring ≤{warn_days}d, {self_signed} self-signed, "
        f"{len(internal_cas)} internal CA(s)"
    )

    return {
        "certificates": certificates,
        "internal_cas": sorted(internal_cas),
        "summary": {
            "total_certs": len(certificates),
            "expired": expired,
            "expiring_30d": expiring_30d,
            "expiring_7d": expiring_7d,
            "self_signed": self_signed,
            "weak_key": weak_key,
            "sha1_signature": sha1_sig,
            "internal_ca_count": len(internal_cas),
        },
    }


# ── Phase 15: Backup & DR Posture Inference ─────────────────────────────────

# Backup software detection rules: (product, port_set, keyword_list)
_BACKUP_PORT_SIGNATURES = [
    ("Veeam Backup & Replication", {9392, 6160, 6162}, ["veeam"]),
    ("Veeam Cloud Connect", {6180}, ["veeam", "cloud connect"]),
    ("Commvault", {8400, 8402, 8403}, ["commvault"]),
    ("Acronis Cyber Protect", {9876, 30443}, ["acronis"]),
    ("Datto / Kaseya BCDR", {5000, 7726}, ["datto", "kaseya"]),
    ("Nakivo Backup", {4443}, ["nakivo"]),
    ("Rubrik", set(), ["rubrik"]),
    ("Cohesity DataProtect", set(), ["cohesity"]),
    ("Unitrends", {1743, 1744}, ["unitrends"]),
    ("Veritas Backup Exec", {10000}, ["backup exec", "backupexec"]),
    ("Arcserve", {8014, 8015}, ["arcserve"]),
    ("NAKIVO", {4443}, ["nakivo"]),
    ("StorageCraft / Arcserve ShadowProtect", set(), ["shadowprotect", "storagecraft"]),
]

# Replication / offsite indicators
_REPLICATION_PORTS = {
    873: "rsync",
    9669: "Zerto ZVM",
    9779: "Zerto ZVRA",
    6180: "Veeam Cloud Connect",
    2500: "Veeam Cloud Gateway",
}

# NAS / storage SNMP keywords
_NAS_SNMP_KEYWORDS = [
    ("synology", "Synology DiskStation"),
    ("qnap", "QNAP NAS"),
    ("truenas", "TrueNAS"),
    ("freenas", "FreeNAS"),
    ("netapp", "NetApp"),
    ("emc", "Dell EMC"),
    ("isilon", "Dell Isilon"),
    ("drobo", "Drobo"),
    ("buffalo", "Buffalo NAS"),
    ("readynas", "NETGEAR ReadyNAS"),
    ("wd.*my.*cloud", "Western Digital My Cloud"),
]


def phase15_backup_posture(hosts: list, config: dict) -> dict:
    """Phase 15: Backup & DR Posture Inference.

    Pure analysis of existing Phase 3/4 data — no new network traffic.
    Detects backup software, NAS/SAN storage, hypervisors, and replication
    indicators from ports, banners, SNMP, and device classifications.
    """
    logger.info("[Phase 15] Backup & DR Posture Inference...")

    backup_software = []
    storage_targets = []
    hypervisors = []
    replication_indicators = []
    observations = []
    seen_products = set()

    for host in hosts:
        ip = host.get("ip", "")
        hostname = host.get("hostname", "N/A")
        ports_set = set(host.get("open_ports", []))
        services = host.get("services", {})
        category = host.get("category", "")
        os_guess = (host.get("os_guess") or "").lower()

        # Collect all text to search (banners, titles, server headers)
        searchable_text = os_guess
        for key, svc in services.items():
            if isinstance(svc, dict):
                for field in ("banner", "title", "server", "version",
                              "nse_banner", "name"):
                    searchable_text += " " + (svc.get(field) or "")
        snmp_descr = (services.get("snmp", {}) or {}).get("sysDescr", "")
        searchable_text += " " + snmp_descr
        searchable_lower = searchable_text.lower()

        # ── Backup software detection ──
        for product, sig_ports, keywords in _BACKUP_PORT_SIGNATURES:
            if product in seen_products and ip in [b["ip"] for b in backup_software]:
                continue

            port_match = sig_ports & ports_set if sig_ports else False
            keyword_match = any(kw in searchable_lower for kw in keywords)

            if port_match or keyword_match:
                evidence_parts = []
                if port_match:
                    evidence_parts.append(
                        f"Port(s) {', '.join(str(p) for p in sorted(port_match))}"
                    )
                if keyword_match:
                    matched_kw = [kw for kw in keywords if kw in searchable_lower]
                    evidence_parts.append(f"Keyword: {matched_kw[0]}")

                backup_software.append({
                    "ip": ip, "hostname": hostname, "product": product,
                    "evidence": "; ".join(evidence_parts),
                    "ports": sorted(sig_ports & ports_set),
                })
                seen_products.add(product)

        # ── NAS / Storage detection ──
        if category in ("NAS / Storage",):
            storage_targets.append({
                "ip": ip, "hostname": hostname,
                "product": category,
                "evidence": f"Classified as {category} by device fingerprint",
                "role": "NAS",
            })
        else:
            # Check SNMP sysDescr for NAS keywords
            descr_lower = snmp_descr.lower()
            for kw, product_name in _NAS_SNMP_KEYWORDS:
                if re.search(kw, descr_lower):
                    storage_targets.append({
                        "ip": ip, "hostname": hostname, "product": product_name,
                        "evidence": f"SNMP sysDescr: {snmp_descr[:80]}",
                        "role": "NAS",
                    })
                    break

        # iSCSI targets
        if 3260 in ports_set:
            storage_targets.append({
                "ip": ip, "hostname": hostname,
                "product": "iSCSI Target",
                "evidence": "Port 3260 (iSCSI) open",
                "role": "SAN/iSCSI",
            })

        # NFS
        if 2049 in ports_set:
            storage_targets.append({
                "ip": ip, "hostname": hostname,
                "product": "NFS Server",
                "evidence": "Port 2049 (NFS) open",
                "role": "NFS",
            })

        # ── Hypervisor detection ──
        if category == "Hypervisor":
            hypervisors.append({
                "ip": ip, "hostname": hostname,
                "product": os_guess[:60] or "Hypervisor",
                "evidence": f"Classified as Hypervisor",
                "role": "Hypervisor",
            })
        elif 902 in ports_set:
            hypervisors.append({
                "ip": ip, "hostname": hostname,
                "product": "VMware ESXi (probable)",
                "evidence": "Port 902 (VMware auth) open",
                "role": "Hypervisor",
            })

        # Hyper-V detection
        if any(kw in searchable_lower for kw in ("hyper-v", "hyperv", "vmms")):
            hypervisors.append({
                "ip": ip, "hostname": hostname,
                "product": "Microsoft Hyper-V",
                "evidence": "Hyper-V keyword detected in service banners",
                "role": "Hypervisor",
            })

        # Proxmox
        if 8006 in ports_set and "proxmox" in searchable_lower:
            hypervisors.append({
                "ip": ip, "hostname": hostname,
                "product": "Proxmox VE",
                "evidence": "Port 8006 + Proxmox keyword",
                "role": "Hypervisor",
            })

        # ── Replication indicators ──
        for rport, rproto in _REPLICATION_PORTS.items():
            if rport in ports_set:
                replication_indicators.append({
                    "ip": ip, "protocol": rproto,
                    "port": rport, "direction": "service detected",
                })

    # ── Build observations ──
    solution_names = sorted(set(b["product"] for b in backup_software))

    if not backup_software:
        observations.append(
            "No backup software detected on the network — potential gap in data protection"
        )
    else:
        observations.append(
            f"Backup solution(s) detected: {', '.join(solution_names)}"
        )

    if not storage_targets:
        observations.append(
            "No dedicated NAS/SAN storage detected — backups may reside on local disk"
        )

    nas_with_smb = [
        s for s in storage_targets
        if s["role"] == "NAS"
        and any(h.get("ip") == s["ip"] and 445 in set(h.get("open_ports", []))
                for h in hosts)
    ]
    if nas_with_smb:
        observations.append(
            f"{len(nas_with_smb)} NAS device(s) with SMB shares exposed — "
            f"potential ransomware risk if not network-isolated"
        )

    if not replication_indicators:
        observations.append(
            "No offsite replication indicators detected (rsync, Zerto, "
            "Veeam Cloud Connect)"
        )

    if hypervisors and not backup_software:
        observations.append(
            f"{len(hypervisors)} hypervisor(s) found but no backup software — "
            f"VM backups may not be automated"
        )

    # Coverage estimate
    has_backup = len(backup_software) > 0
    has_storage = len(storage_targets) > 0
    has_offsite = len(replication_indicators) > 0
    if has_backup and has_storage and has_offsite:
        coverage = "Good"
    elif has_backup and (has_storage or has_offsite):
        coverage = "Partial"
    elif has_backup:
        coverage = "Partial"
    else:
        coverage = "None"

    # Dedup storage targets by IP
    seen_storage_ips = set()
    deduped_storage = []
    for s in storage_targets:
        if s["ip"] not in seen_storage_ips:
            seen_storage_ips.add(s["ip"])
            deduped_storage.append(s)

    # Dedup hypervisors by IP
    seen_hyper_ips = set()
    deduped_hypers = []
    for h in hypervisors:
        if h["ip"] not in seen_hyper_ips:
            seen_hyper_ips.add(h["ip"])
            deduped_hypers.append(h)

    logger.info(
        f"  Backup posture: {len(backup_software)} solution(s), "
        f"{len(deduped_storage)} storage target(s), "
        f"{len(deduped_hypers)} hypervisor(s), "
        f"coverage={coverage}"
    )

    return {
        "backup_software": backup_software,
        "storage_targets": deduped_storage,
        "hypervisors": deduped_hypers,
        "replication_indicators": replication_indicators,
        "observations": observations,
        "summary": {
            "backup_solutions_found": solution_names,
            "storage_device_count": len(deduped_storage),
            "hypervisor_count": len(deduped_hypers),
            "has_offsite_replication": has_offsite,
            "estimated_coverage": coverage,
        },
    }


# ── Phase 16: End-of-Life / End-of-Support Detection ───────────────────────

# Path to the external EOL database (auto-updated via self-update.sh from
# the GitHub repo).  Falls back to a minimal embedded list if the file
# cannot be loaded.
_EOL_DB_FILE = Path(__file__).parent.parent / "data" / "eol-database.json"
_EOL_DB_INSTALLED = DATA_DIR / "eol-database.json"   # install-dir copy

# Minimal embedded fallback (used only if the JSON file is missing/corrupt)
_EOL_DATABASE_FALLBACK = [
    (r"Windows Server 2008",  "os", "Windows Server 2008/R2", "2020-01-14", "CRITICAL", "No patches since Jan 2020"),
    (r"Windows Server 2012",  "os", "Windows Server 2012/R2", "2023-10-10", "CRITICAL", "Extended support ended Oct 2023"),
    (r"Windows 7",            "os", "Windows 7",               "2020-01-14", "CRITICAL", ""),
    (r"Ubuntu 18\.04",        "os", "Ubuntu 18.04 LTS",       "2023-05-31", "HIGH",     "Standard support ended"),
    (r"CentOS (?:Linux )?7",  "os", "CentOS 7",               "2024-06-30", "HIGH",     ""),
    (r"(?:ESXi|vSphere)[^\d]*6\.[057]", "firmware", "VMware ESXi 6.x", "2022-10-15", "CRITICAL", ""),
    (r"FortiOS[^\d]*6\.[02]", "firmware", "FortiOS 6.0/6.2",  "2023-09-29", "CRITICAL", ""),
    (r"Apache/2\.2\.",        "service", "Apache 2.2",         "2017-07-11", "CRITICAL", ""),
    (r"OpenSSH[_ ](?:[1-5]\.|6\.[0-6])", "service", "OpenSSH (very old)", "varies", "CRITICAL", "Known CVEs"),
    (r"PHP/5\.",              "service", "PHP 5.x",            "2018-12-31", "CRITICAL", "No security fixes"),
]


def _load_eol_database() -> list:
    """Load EOL database from JSON file, falling back to embedded list.

    Searches for the file at two paths:
      1. Relative to the script (repo checkout / dev)
      2. Installed path under DATA_DIR (/opt/network-discovery/data/)
    Returns a list of (regex, category, product, eol_date, severity, notes).
    """
    for path in (_EOL_DB_FILE, _EOL_DB_INSTALLED):
        try:
            if path.exists():
                with open(path) as f:
                    data = json.load(f)

                entries = data.get("entries", [])
                if not entries:
                    continue

                db = []
                for entry in entries:
                    if isinstance(entry, list) and len(entry) >= 6:
                        db.append(tuple(entry[:6]))
                    elif isinstance(entry, dict):
                        db.append((
                            entry.get("pattern", ""),
                            entry.get("category", ""),
                            entry.get("product", ""),
                            entry.get("eol_date", ""),
                            entry.get("severity", ""),
                            entry.get("notes", ""),
                        ))

                if db:
                    version = data.get("_meta", {}).get("version", "?")
                    updated = data.get("_meta", {}).get("updated", "?")
                    logger.info(
                        f"  Loaded EOL database from {path} "
                        f"(v{version}, updated {updated}, {len(db)} entries)"
                    )
                    return db

        except (json.JSONDecodeError, IOError, OSError) as e:
            logger.warning(f"  Failed to load EOL database from {path}: {e}")

    logger.warning("  Using minimal embedded EOL fallback database")
    return list(_EOL_DATABASE_FALLBACK)


def _collect_matchable_strings(host: dict) -> dict:
    """Gather all strings from a host that can be matched against EOL DB.

    Returns dict with keys 'os', 'firmware', 'service' each containing a
    list of (source_label, text) tuples.
    """
    strings = {"os": [], "firmware": [], "service": []}

    # OS-level strings
    os_guess = host.get("os_guess", "")
    if os_guess:
        strings["os"].append(("nmap OS", os_guess))

    # SMB OS
    smb = host.get("services", {}).get("smb", {}) or {}
    smb_os = smb.get("smb_os", "")
    if smb_os:
        strings["os"].append(("SMB OS discovery", smb_os))

    # SNMP sysDescr → both firmware and OS
    snmp = host.get("services", {}).get("snmp", {}) or {}
    descr = snmp.get("sysDescr", "")
    if descr:
        strings["firmware"].append(("SNMP sysDescr", descr))
        strings["os"].append(("SNMP sysDescr", descr))

    # Gateway fingerprint
    gw = host.get("gateway_info", {}) or {}
    gw_product = gw.get("product", "")
    gw_version = gw.get("version", "")
    if gw_product:
        strings["firmware"].append(("Gateway fingerprint", f"{gw_product} {gw_version}"))

    # Service versions + banners
    services = host.get("services", {})
    for key, svc in services.items():
        if not isinstance(svc, dict) or not isinstance(key, int):
            continue
        version = svc.get("version", "")
        banner = svc.get("banner", "")
        nse_banner = svc.get("nse_banner", "")
        server = svc.get("server", "")
        for val, src in [(version, f"port {key} version"),
                         (banner, f"port {key} banner"),
                         (nse_banner, f"port {key} NSE"),
                         (server, f"port {key} server header")]:
            if val:
                strings["service"].append((src, val))

    # HTTP titles sometimes reveal versions
    for key, svc in services.items():
        if isinstance(svc, dict) and svc.get("title"):
            strings["service"].append((f"port {key} HTTP title", svc["title"]))

    return strings


def phase16_eol_detection(hosts: list, config: dict) -> dict:
    """Phase 16: End-of-Life / End-of-Support Detection.

    Matches OS fingerprints, service versions, SNMP sysDescr, and banner
    strings against a curated EOL database. Groups results by product and
    severity.
    """
    logger.info("[Phase 16] End-of-Life / End-of-Support Detection...")

    eol_db = _load_eol_database()
    logger.info(f"  Loaded {len(eol_db)} EOL database entries")

    eol_devices = []   # CRITICAL/HIGH: already past EOL
    approaching = []   # MEDIUM/INFO: approaching EOL
    eol_services = []  # Service-level (per port)
    seen = set()       # (ip, product_label) dedup

    for host in hosts:
        ip = host.get("ip", "")
        hostname = host.get("hostname", "N/A")
        matchable = _collect_matchable_strings(host)

        for pattern, category, product_label, eol_date, severity, notes in eol_db:
            if (ip, product_label) in seen:
                continue

            texts = matchable.get(category, [])
            for source_label, text in texts:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        entry = {
                            "ip": ip,
                            "hostname": hostname,
                            "product": product_label,
                            "version_detected": text[:100],
                            "eol_date": eol_date,
                            "severity": severity,
                            "match_source": source_label,
                            "notes": notes,
                        }

                        seen.add((ip, product_label))

                        if category == "service":
                            # Try to get port number from source_label
                            port_m = re.search(r"port (\d+)", source_label)
                            entry["port"] = int(port_m.group(1)) if port_m else 0
                            eol_services.append(entry)
                        elif severity in ("CRITICAL", "HIGH"):
                            eol_devices.append(entry)
                        else:
                            approaching.append(entry)

                        break  # Only first match per (host, product)
                except re.error:
                    pass

    # Summary stats
    all_entries = eol_devices + approaching + eol_services
    crit = sum(1 for e in all_entries if e["severity"] == "CRITICAL")
    high = sum(1 for e in all_entries if e["severity"] == "HIGH")
    med = sum(1 for e in all_entries if e["severity"] == "MEDIUM")

    # Find top risk (product with most affected IPs)
    product_counts = {}
    for e in all_entries:
        if e["severity"] in ("CRITICAL", "HIGH"):
            product_counts.setdefault(e["product"], set()).add(e["ip"])
    top_risk = ""
    if product_counts:
        top_prod = max(product_counts, key=lambda k: len(product_counts[k]))
        top_risk = f"{top_prod} ({len(product_counts[top_prod])} device(s))"

    logger.info(
        f"  EOL detection: {len(all_entries)} finding(s) — "
        f"{crit} CRITICAL, {high} HIGH, {med} MEDIUM"
    )

    return {
        "eol_devices": eol_devices,
        "approaching_eol": approaching,
        "eol_services": eol_services,
        "summary": {
            "critical_eol_count": crit,
            "high_eol_count": high,
            "medium_eol_count": med,
            "total_eol_products": len(all_entries),
            "top_risk": top_risk,
        },
    }


# ── Summary Statistics ─────────────────────────────────────────────────────

def build_summary(recon: dict, hosts: list) -> dict:
    """Build summary statistics from scan results."""
    total_hosts = len(hosts)
    total_open_ports = sum(len(h["open_ports"]) for h in hosts)

    port_freq: dict = {}
    for h in hosts:
        for port in h["open_ports"]:
            svc = port_to_service(port)
            port_freq[svc] = port_freq.get(svc, 0) + 1
    top_services = sorted(port_freq.items(), key=lambda x: -x[1])[:10]

    vendor_freq: dict = {}
    for h in hosts:
        vendor = h.get("vendor", "Unknown")
        vendor_freq[vendor] = vendor_freq.get(vendor, 0) + 1
    top_vendors = sorted(vendor_freq.items(), key=lambda x: -x[1])[:10]

    category_freq: dict = {}
    for h in hosts:
        cat = h.get("category", "Unknown")
        category_freq[cat] = category_freq.get(cat, 0) + 1

    security_count = sum(len(h.get("security_flags", [])) for h in hosts)
    critical_hosts = [h for h in hosts if any(
        f["severity"] == "CRITICAL" for f in h.get("security_flags", [])
    )]

    pub = recon.get("public_ip_info", {})

    return {
        "total_hosts": total_hosts,
        "total_open_ports": total_open_ports,
        "subnets_scanned": recon.get("subnets", []),
        "additional_subnets_found": len(recon.get("additional_subnets", [])),
        "top_services": [{"service": s, "count": c} for s, c in top_services],
        "top_vendors": [{"vendor": v, "count": c} for v, c in top_vendors],
        "category_breakdown": category_freq,
        "security_observations": security_count,
        "critical_hosts": [h["ip"] for h in critical_hosts],
        "security_gaps": _aggregate_security_gaps(hosts),
        # Convenience keys for report
        "public_ip": pub.get("public_ip", ""),
        "isp": pub.get("isp", ""),
    }


# ── Main scanner entry point ───────────────────────────────────────────────

def run_discovery(progress_callback=None) -> dict:
    """Execute all discovery phases and return structured results."""
    config = load_scan_config()
    start_time = datetime.now()
    phase_timings = []  # Collected for operational statistics in the report

    def progress(msg: str):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    def _run_phase(phase_num, phase_name, func, *args, config_key=None, **kwargs):
        """Run a phase with timing, logging, and error handling.

        Returns the phase result (or default empty value on failure/skip).
        Records timing entry in phase_timings list.
        """
        if config_key and not config.get(config_key, True):
            logger.info(f"Phase {phase_num} ({phase_name}): SKIPPED (disabled in config)")
            phase_timings.append({
                "phase": phase_num, "name": phase_name,
                "duration": 0.0, "status": "skipped",
            })
            return kwargs.get("default", {})

        progress(f"Phase {phase_num}: {phase_name}...")
        t0 = time.time()
        try:
            result = func(*args)
            elapsed = time.time() - t0
            logger.info(
                f"Phase {phase_num} ({phase_name}): completed in {elapsed:.1f}s"
            )
            phase_timings.append({
                "phase": phase_num, "name": phase_name,
                "duration": round(elapsed, 2), "status": "ok",
            })
            return result
        except Exception as e:
            elapsed = time.time() - t0
            logger.error(
                f"Phase {phase_num} ({phase_name}): FAILED after {elapsed:.1f}s — {e}",
                exc_info=True,
            )
            phase_timings.append({
                "phase": phase_num, "name": phase_name,
                "duration": round(elapsed, 2), "status": "error",
                "error": str(e),
            })
            return kwargs.get("default", {})

    progress("Starting network discovery...")

    # ── Core phases (1–6) ────────────────────────────────────────────────
    recon = _run_phase("1", "Reconnaissance", phase1_reconnaissance, config)

    recon = _run_phase("1b", "Alternate subnet detection",
                       phase1b_alternate_subnet_detection, recon, config)

    hosts = _run_phase("2", "Host discovery",
                       phase2_host_discovery, recon, config, default=[])
    if not hosts:
        logger.warning(
            "No hosts discovered. Network may be empty or scanning may be blocked."
        )

    hosts = _run_phase("3", "Port scan",
                       phase3_port_scan, hosts, config, default=hosts)

    hosts = _run_phase("4", "Service enumeration",
                       phase4_service_enumeration, hosts, config, default=hosts)

    topology = _run_phase("5", "Topology mapping",
                          phase5_topology, recon, config)

    hosts = _run_phase("6", "Security analysis",
                       phase6_security, hosts, default=hosts)

    # ── Extended discovery phases (7–16) ─────────────────────────────────
    wifi_results = _run_phase(
        "7", "WiFi enumeration", phase7_wifi_scan, config,
        config_key="enable_wifi_scan")

    mdns_results = _run_phase(
        "8", "mDNS / Bonjour discovery", phase8_mdns_discovery, config,
        config_key="enable_mdns_discovery")

    ssdp_results = _run_phase(
        "9", "UPnP / SSDP discovery", phase9_ssdp_discovery, config,
        config_key="enable_ssdp_discovery")

    dhcp_results = _run_phase(
        "10", "DHCP scope analysis", phase10_dhcp_analysis, recon, config,
        config_key="enable_dhcp_analysis")

    ntp_results = _run_phase(
        "11", "NTP server detection", phase11_ntp_detection, hosts, recon, config,
        config_key="enable_ntp_detection")

    nac_results = _run_phase(
        "12", "802.1X / NAC detection", phase12_nac_detection, config,
        config_key="enable_nac_detection")

    osint_results = _run_phase(
        "13", "OSINT / External reconnaissance",
        phase13_osint, recon, hosts, dhcp_results, config,
        config_key="enable_osint")

    ssl_audit_results = _run_phase(
        "14", "SSL/TLS certificate health audit",
        phase14_ssl_audit, hosts, config,
        config_key="enable_ssl_audit")

    backup_results = _run_phase(
        "15", "Backup & DR posture inference",
        phase15_backup_posture, hosts, config,
        config_key="enable_backup_posture")

    eol_results = _run_phase(
        "16", "End-of-life / end-of-support detection",
        phase16_eol_detection, hosts, config,
        config_key="enable_eol_detection")

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    summary = build_summary(recon, hosts)

    # ── Phase timing summary log ─────────────────────────────────────────
    logger.info("-" * 60)
    logger.info("PHASE TIMING SUMMARY")
    for pt in phase_timings:
        status_tag = pt["status"].upper()
        if pt["status"] == "skipped":
            logger.info(f"  Phase {pt['phase']:>3s}  {pt['name']:<40s}  SKIPPED")
        elif pt["status"] == "error":
            logger.info(
                f"  Phase {pt['phase']:>3s}  {pt['name']:<40s}  "
                f"FAILED  {pt['duration']:>7.1f}s"
            )
        else:
            logger.info(
                f"  Phase {pt['phase']:>3s}  {pt['name']:<40s}  "
                f"OK      {pt['duration']:>7.1f}s"
            )
    logger.info(f"  {'':>5s}  {'TOTAL':<40s}          {duration:>7.1f}s")
    logger.info("-" * 60)

    results = {
        "scan_start": start_time.isoformat(),
        "scan_end": end_time.isoformat(),
        "duration_seconds": duration,
        "scanner_host": get_hostname(),
        "reconnaissance": recon,
        "hosts": hosts,
        "topology": topology,
        "summary": summary,
        "subnet_labels": config.get("subnet_labels", {}),
        # Extended discovery results
        "wifi": wifi_results,
        "mdns": mdns_results,
        "ssdp": ssdp_results,
        "dhcp_analysis": dhcp_results,
        "ntp": ntp_results,
        "nac": nac_results,
        "osint": osint_results,
        "ssl_audit": ssl_audit_results,
        "backup_posture": backup_results,
        "eol_detection": eol_results,
        # Operational statistics
        "phase_timings": phase_timings,
    }

    timestamp_str = start_time.strftime("%Y%m%d_%H%M%S")
    json_path = DATA_DIR / f"scan_{timestamp_str}.json"
    # Write atomically: temp file + rename so a mid-write kill never leaves a corrupt file
    tmp_json = json_path.with_suffix(".json.tmp")
    with open(tmp_json, "w") as f:
        json.dump(results, f, indent=2)
    tmp_json.replace(json_path)
    logger.info(f"Scan results saved: {json_path}")

    progress(f"Discovery complete. {len(hosts)} hosts found in {duration:.0f}s.")
    return results


# ── CLI entrypoint ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    results = run_discovery()
    print(json.dumps(results["summary"], indent=2))
