#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
network_utils.py - Network utility functions

Shared helpers for IP handling, interface enumeration, MAC vendor lookup,
gateway/DNS detection, and service name mapping.
"""

import ipaddress
import json
import logging
import os
import re
import socket
import struct
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── OUI / MAC Vendor database (top vendors - loaded lazily) ───────────────

_OUI_DB: dict = {}
_OUI_DB_LOADED = False

# Embedded mini-OUI table for offline use (covers common vendors)
# Format: "XX:XX:XX" -> "Vendor Name"
_BUILTIN_OUI = {
    # Cisco / networking
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:02:17": "Cisco",
    "00:1D:19": "Cisco-Linksys", "00:23:69": "Cisco-Linksys", "00:60:2F": "Cisco-Linksys",
    # VMware / virtualization
    "00:0C:29": "VMware", "00:50:56": "VMware", "00:05:69": "VMware",
    # Google / Chromecast
    "00:1A:11": "Google", "F4:F5:D8": "Google",
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Ltd",
    "E4:5F:01": "Raspberry Pi Ltd",
    # Intel
    "00:1B:21": "Intel", "00:1F:C6": "Intel", "00:22:FB": "Intel",
    # Apple
    "B4:2E:99": "Apple", "F0:18:98": "Apple", "3C:07:54": "Apple",
    "00:25:00": "Apple", "78:4F:43": "Apple", "A8:66:7F": "Apple",
    "00:1C:B3": "Apple", "00:1D:4F": "Apple", "00:0A:95": "Apple",
    # Dell
    "00:1A:A0": "Dell", "18:03:73": "Dell", "D4:BE:D9": "Dell",
    "00:14:22": "Dell", "14:18:77": "Dell",
    # Microsoft
    "00:0D:3A": "Microsoft", "00:15:5D": "Microsoft", "28:18:78": "Microsoft",
    "00:50:F2": "Microsoft",
    # HP / Hewlett Packard
    "00:1E:67": "Hewlett Packard", "3C:D9:2B": "Hewlett Packard",
    "00:21:5A": "Hewlett Packard", "28:92:4A": "Hewlett Packard",
    # Netgear
    "00:16:17": "Netgear", "C0:FF:D4": "Netgear", "A0:40:A0": "Netgear",
    "00:0F:B5": "Netgear", "20:E5:2A": "Netgear",
    # TP-Link / Tenda
    "50:C7:BF": "TP-Link", "B0:BE:76": "TP-Link", "98:DA:C4": "TP-Link",
    "C8:3A:35": "Tenda", "00:26:75": "Tenda",
    # D-Link
    "00:18:F8": "D-Link", "28:10:7B": "D-Link", "14:D6:4D": "D-Link",
    # Ubiquiti Networks (UniFi / EdgeMax / airMAX)
    "1C:AF:F7": "Ubiquiti", "00:27:22": "Ubiquiti", "24:A4:3C": "Ubiquiti",
    "04:18:D6": "Ubiquiti", "F0:9F:C2": "Ubiquiti", "68:72:51": "Ubiquiti",
    "74:83:C2": "Ubiquiti", "B4:FB:E4": "Ubiquiti", "78:8A:20": "Ubiquiti",
    "80:2A:A8": "Ubiquiti", "DC:9F:DB": "Ubiquiti", "E0:63:DA": "Ubiquiti",
    "F4:92:BF": "Ubiquiti", "44:D9:E7": "Ubiquiti",
    # Aruba Networks (HP/Aruba APs/switches)
    "00:0B:86": "Aruba Networks", "00:1A:1E": "Aruba Networks",
    "24:DE:C6": "Aruba Networks", "70:3A:0E": "Aruba Networks",
    "9C:1C:12": "Aruba Networks", "AC:A3:1E": "Aruba Networks",
    # Ruckus / CommScope
    "00:24:82": "Ruckus Wireless", "08:EA:44": "Ruckus Wireless",
    "2C:6B:F5": "Ruckus Wireless", "D4:68:BA": "Ruckus Wireless",
    # Meraki / Cisco Meraki
    "0C:8D:DB": "Cisco Meraki", "34:56:FE": "Cisco Meraki",
    "88:15:44": "Cisco Meraki", "E0:CB:BC": "Cisco Meraki",
    # Fortinet (FortiGate)
    "00:09:0F": "Fortinet", "08:5B:0E": "Fortinet",
    "70:4C:A5": "Fortinet", "90:6C:AC": "Fortinet",
    # SonicWall
    "00:17:C5": "SonicWall", "C0:EA:E4": "SonicWall",
    # Palo Alto Networks
    "00:1B:17": "Palo Alto Networks",
    # WatchGuard Technologies
    "00:90:7F": "WatchGuard",
    # Hikvision (IP cameras/NVRs)
    "44:19:B6": "Hikvision", "54:C4:15": "Hikvision", "C0:56:E3": "Hikvision",
    "BC:AD:28": "Hikvision", "E4:24:6C": "Hikvision",
    # Dahua Technology (cameras)
    "3C:EF:8C": "Dahua", "90:02:A9": "Dahua",
    # Axis Communications (cameras)
    "00:40:8C": "Axis Communications", "AC:CC:8E": "Axis Communications",
    # Hanwha / Samsung Techwin (cameras)
    "00:09:18": "Hanwha Techwin",
    # Synology (NAS)
    "00:11:32": "Synology", "00:1F:1E": "Synology",
    # QNAP Systems (NAS)
    "00:08:9B": "QNAP", "24:5E:BE": "QNAP",
    # Western Digital (NAS/drives)
    "00:90:A9": "Western Digital", "A0:18:28": "Western Digital",
    # Yealink (VoIP phones)
    "80:5E:C0": "Yealink", "00:15:65": "Yealink",
    # Polycom (VoIP / conference)
    "00:04:F2": "Polycom", "64:16:7F": "Polycom",
    # Grandstream (VoIP)
    "00:0B:82": "Grandstream",
    # Cisco IP Phone (VoIP)
    "00:11:21": "Cisco IP Phone", "00:1B:2B": "Cisco IP Phone",
    # APC / Schneider (UPS)
    "00:C0:B7": "APC / Schneider", "B8:E8:56": "APC / Schneider",
    # Amazon (Echo/FireTV)
    "44:65:0D": "Amazon", "74:75:48": "Amazon", "FC:65:DE": "Amazon",
    "68:37:E9": "Amazon",
    # Philips Hue / IoT
    "00:17:88": "Philips Hue",
    # Espressif (ESP8266/ESP32 IoT)
    "18:FE:34": "Espressif", "24:6F:28": "Espressif", "30:AE:A4": "Espressif",
    # Printers
    "AC:0D:1B": "Epson", "00:26:AB": "Epson",
    "00:1C:A8": "Ricoh", "00:00:74": "Ricoh",
    "00:04:00": "Lexmark", "00:1B:78": "Lexmark",
    "00:00:AA": "Xerox", "08:00:2B": "Xerox",
    "00:00:48": "Kyocera", "00:C0:EE": "Kyocera",
    "00:00:F0": "Samsung", "78:1F:DB": "Samsung",
}

# ── Service port name mapping ──────────────────────────────────────────────

PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD-Print",
    554: "RTSP",
    587: "SMTP-Submission",
    631: "IPP-Print",
    636: "LDAPS",
    902: "VMware-vSphere",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    1723: "PPTP-VPN",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    4444: "Ubiquiti-UNMS",
    5000: "Synology-DSM",
    5001: "Synology-DSM-HTTPS",
    5060: "SIP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    7070: "WebLogic",
    8080: "HTTP-Alt",
    8291: "MikroTik-Winbox",
    8443: "HTTPS-Alt",
    9100: "Printer-JetDirect",
    10000: "Webmin",
    27017: "MongoDB",
    49152: "WSD",
}


# ── IP / Subnet utilities ──────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ip_to_network(ip: str, netmask: str) -> str:
    """Convert IP + netmask to CIDR notation (e.g. '192.168.1.0/24')."""
    try:
        network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
        return str(network)
    except ValueError:
        return ""


def get_network_hosts(cidr: str) -> list:
    """Return all usable host IPs in a CIDR subnet."""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def cidr_to_range(cidr: str) -> tuple:
    """Return (first_ip, last_ip, host_count) for a CIDR block."""
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        hosts = list(net.hosts())
        return (str(hosts[0]), str(hosts[-1]), len(hosts)) if hosts else ("", "", 0)
    except ValueError:
        return ("", "", 0)


# ── Network interface enumeration ─────────────────────────────────────────

def get_network_interfaces() -> list:
    """
    Return a list of dicts describing active network interfaces.
    Each dict: {name, ip, netmask, cidr, mac, is_up}
    """
    interfaces = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            if iface == "lo":
                continue
            addrs = netifaces.ifaddresses(iface)
            ip_info = addrs.get(netifaces.AF_INET, [{}])[0]
            mac_info = addrs.get(netifaces.AF_LINK, [{}])[0]

            ip = ip_info.get("addr", "")
            netmask = ip_info.get("netmask", "")
            mac = mac_info.get("addr", "")

            if not ip:
                continue

            cidr = ip_to_network(ip, netmask) if netmask else ""

            interfaces.append({
                "name": iface,
                "ip": ip,
                "netmask": netmask,
                "cidr": cidr,
                "mac": mac.upper() if mac else "",
                "is_up": True,
            })
    except ImportError:
        logger.warning("netifaces not installed — falling back to ip command")
        interfaces = _get_interfaces_via_ip_cmd()

    if interfaces:
        logger.info(
            f"Network interfaces found: {len(interfaces)} — "
            + ", ".join(f"{i['name']}({i['ip']})" for i in interfaces)
        )
    else:
        logger.warning("No active network interfaces detected")
    return interfaces


def _get_interfaces_via_ip_cmd() -> list:
    """Fallback: parse 'ip addr show' output."""
    interfaces = []
    try:
        output = subprocess.check_output(["ip", "addr", "show"], text=True, timeout=10)
        current_iface = None
        for line in output.splitlines():
            line = line.strip()
            if re.match(r"^\d+:", line):
                parts = line.split(":")
                if len(parts) >= 2:
                    current_iface = parts[1].strip().split("@")[0]
            elif line.startswith("inet ") and current_iface and current_iface != "lo":
                parts = line.split()
                ip_cidr = parts[1]
                try:
                    net = ipaddress.IPv4Interface(ip_cidr)
                    interfaces.append({
                        "name": current_iface,
                        "ip": str(net.ip),
                        "netmask": str(net.netmask),
                        "cidr": str(net.network),
                        "mac": "",
                        "is_up": True,
                    })
                except ValueError:
                    pass
    except Exception as e:
        logger.error(f"Failed to enumerate interfaces: {e}")
    return interfaces


def get_default_gateway() -> Optional[str]:
    """Return the default gateway IP address."""
    # Method 1: netifaces
    try:
        import netifaces
        gws = netifaces.gateways()
        default = gws.get("default", {})
        gw_entry = default.get(netifaces.AF_INET)
        if gw_entry:
            logger.debug(f"Default gateway via netifaces: {gw_entry[0]}")
            return gw_entry[0]
    except ImportError:
        logger.debug("netifaces not available for gateway detection")

    # Method 2: /proc/net/route
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gw_hex = parts[2]
                    gw_int = int(gw_hex, 16)
                    gw_ip = socket.inet_ntoa(struct.pack("<L", gw_int))
                    logger.debug(f"Default gateway via /proc/net/route: {gw_ip}")
                    return gw_ip
    except Exception as e:
        logger.debug(f"/proc/net/route read failed: {e}")

    # Method 3: ip route
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"], text=True, timeout=5)
        match = re.search(r"default via (\S+)", output)
        if match:
            logger.debug(f"Default gateway via ip route: {match.group(1)}")
            return match.group(1)
    except Exception as e:
        logger.debug(f"ip route command failed: {e}")

    logger.warning("Could not determine default gateway via any method")
    return None


def get_dns_servers() -> list:
    """Return list of configured DNS server IPs."""
    servers = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) == 2 and is_valid_ip(parts[1]):
                        servers.append(parts[1])
    except Exception as e:
        logger.warning(f"Could not read /etc/resolv.conf: {e}")
    if servers:
        logger.debug(f"DNS servers: {', '.join(servers)}")
    else:
        logger.warning("No DNS servers found in /etc/resolv.conf")
    return servers


# ── DNS utilities ──────────────────────────────────────────────────────────

def reverse_dns(ip: str, timeout: float = 2.0) -> Optional[str]:
    """Perform reverse DNS lookup. Returns hostname or None.

    Uses subprocess with 'getent' to avoid mutating the process-global
    socket timeout, which is unsafe when called from worker threads.
    """
    try:
        result = subprocess.run(
            ["getent", "hosts", ip],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 2:
                return parts[1]
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    # Fallback: use socket with a brief global-timeout window (best-effort)
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        socket.setdefaulttimeout(old_timeout)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        socket.setdefaulttimeout(old_timeout if 'old_timeout' in dir() else None)
        return None


def forward_dns(hostname: str, timeout: float = 2.0) -> Optional[str]:
    """Resolve hostname to IP. Returns IP or None.

    Uses subprocess with 'getent' to avoid mutating the process-global
    socket timeout, which is unsafe when called from worker threads.
    """
    try:
        result = subprocess.run(
            ["getent", "hosts", hostname],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) >= 1:
                return parts[0]
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    # Fallback
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(hostname)
        socket.setdefaulttimeout(old_timeout)
        return ip
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        socket.setdefaulttimeout(old_timeout if 'old_timeout' in dir() else None)
        return None


# ── MAC vendor lookup ──────────────────────────────────────────────────────

def normalize_mac(mac: str) -> str:
    """Normalize MAC address to upper-case colon-separated format."""
    mac = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(mac) == 12:
        return ":".join(mac[i:i+2].upper() for i in range(0, 12, 2))
    return mac.upper()


def get_mac_vendor(mac: str) -> str:
    """
    Look up MAC address vendor using the embedded OUI table.
    Returns vendor name or 'Unknown'.
    """
    if not mac:
        return "Unknown"

    mac_norm = normalize_mac(mac)
    oui = mac_norm[:8]  # First 3 octets: "XX:XX:XX"

    # Check builtin table
    vendor = _BUILTIN_OUI.get(oui)
    if vendor:
        return vendor

    # Try first 2 octets for broader match (some OUI blocks)
    oui_short = mac_norm[:5]
    for key, val in _BUILTIN_OUI.items():
        if key.startswith(oui_short):
            return val

    return "Unknown"


# ── Port / service helpers ─────────────────────────────────────────────────

def port_to_service(port: int, proto: str = "tcp") -> str:
    """Return human-readable service name for a port number."""
    return PORT_SERVICE_MAP.get(port, f"port-{port}/{proto}")


def is_web_port(port: int) -> bool:
    return port in (80, 443, 8080, 8443, 8000, 8888, 3000, 4443, 9443)


def is_management_port(port: int) -> bool:
    return port in (22, 23, 3389, 5900, 5985, 5986, 8080, 10000)


def is_file_service_port(port: int) -> bool:
    return port in (21, 139, 445, 2049, 137, 138)


def is_database_port(port: int) -> bool:
    return port in (1433, 3306, 5432, 1521, 27017, 6379)


def is_print_port(port: int) -> bool:
    return port in (9100, 515, 631)


# ── Vendor keyword sets for fast classification ────────────────────────────

_FIREWALL_VENDORS = frozenset([
    "fortinet", "sonicwall", "sonic wall", "palo alto", "watchguard",
    "watch guard", "sophos", "barracuda", "check point",
])
_AP_VENDORS = frozenset([
    "ubiquiti", "aruba", "ruckus", "meraki", "cisco meraki",
    "aerohive", "cambium", "engenius",
])
_SWITCH_VENDORS = frozenset([
    "cisco", "juniper", "aruba", "netgear", "d-link", "tp-link",
    "hewlett packard", "hp", "extreme networks", "brocade",
])
_CAMERA_VENDORS = frozenset([
    "hikvision", "dahua", "axis communications", "hanwha", "samsung techwin",
    "amcrest", "vivotek", "avigilon",
])
_NAS_VENDORS = frozenset([
    "synology", "qnap", "western digital", "buffalo",
])
_VOIP_VENDORS = frozenset([
    "yealink", "polycom", "grandstream", "cisco ip phone",
    "avaya", "snom", "fanvil",
])
_PRINTER_VENDORS = frozenset([
    "epson", "canon", "ricoh", "lexmark", "xerox", "brother",
    "kyocera", "konica", "oki", "sharp",
])
_UPS_VENDORS = frozenset([
    "apc", "schneider", "eaton", "tripplite", "tripp lite", "cyberpower",
])


# ── Host classification heuristics ────────────────────────────────────────

def classify_device(
    open_ports: list,
    mac: str = "",
    hostname: str = "",
    snmp_info: dict = None,
    version_info: dict = None,
) -> str:
    """
    Heuristically classify a device based on open ports, MAC vendor, hostname,
    SNMP sysDescr, and nmap service version strings.
    Returns a category string.

    MSP-focused categories (in priority order):
      Firewall | Network Switch | Wireless Access Point | IP Camera / NVR |
      NAS / Storage | VoIP Phone | Printer | UPS / Power Device |
      Hypervisor | Windows Server | Linux/Unix Server | Database Server |
      Server | Windows Workstation | Windows Device | Apple Device |
      Raspberry Pi | Virtual Machine | IoT Device | Unknown Device
    """
    ports_set = set(open_ports)
    vendor = get_mac_vendor(mac).lower()
    hostname_lower = (hostname or "").lower()

    # ── SNMP sysDescr — most authoritative signal ─────────────────────────
    sys_descr = ""
    sys_name = ""
    if snmp_info:
        sys_descr = (
            snmp_info.get("sysDescr") or snmp_info.get("snmp_sysdescr") or ""
        ).lower()
        sys_name = (snmp_info.get("sysName") or "").lower()
        ifdescr_count = len(snmp_info.get("ifDescr", []))

        if sys_descr:
            # Firewall / security appliances
            if any(kw in sys_descr for kw in ("fortios", "fortigate")):
                return "Firewall"
            if any(kw in sys_descr for kw in ("sonicwall", "sonicos")):
                return "Firewall"
            if any(kw in sys_descr for kw in ("palo alto", "pan-os")):
                return "Firewall"
            if any(kw in sys_descr for kw in ("watchguard", "fireware")):
                return "Firewall"
            if any(kw in sys_descr for kw in ("sophos", "xg firewall", "utm")):
                return "Firewall"
            if any(kw in sys_descr for kw in ("pfsense", "opnsense", "openbsd")):
                return "Firewall"
            if any(kw in sys_descr for kw in ("cisco adaptive security", "cisco asa")):
                return "Firewall"
            if any(kw in sys_descr for kw in ("cisco ios", "cisco nx-os", "cisco ios xe")):
                # Distinguish switch vs router by interface count
                return "Network Switch" if ifdescr_count > 6 else "Network Infrastructure"
            if any(kw in sys_descr for kw in ("junos", "juniper")):
                return "Network Infrastructure"
            if any(kw in sys_descr for kw in ("edgeos", "ubnt edgerouter")):
                return "Firewall"
            if any(kw in sys_descr for kw in ("mikrotik", "routeros")):
                return "Network Infrastructure"
            if "meraki" in sys_descr:
                return "Wireless Access Point" if "mr" in sys_descr else "Network Infrastructure"
            # IP Camera / NVR
            if any(kw in sys_descr for kw in ("camera", "nvr", "dvr", "ipcam", "hikvision", "dahua", "axis")):
                return "IP Camera / NVR"
            # NAS / Storage
            if any(kw in sys_descr for kw in ("synology", "diskstation", "qnap", "nas", "storage station")):
                return "NAS / Storage"
            # Printer
            if any(kw in sys_descr for kw in ("printer", "jetdirect", "laserjet", "officejet", "photosmart")):
                return "Printer"
            # UPS
            if any(kw in sys_descr for kw in ("ups", "uninterruptible", "apc smart", "eaton")):
                return "UPS / Power Device"
            # Hypervisor
            if any(kw in sys_descr for kw in ("esxi", "vmware esxi", "vsphere")):
                return "Hypervisor"
            # Raspberry Pi
            if "raspberry" in sys_descr:
                return "Raspberry Pi"
            # Windows (check for DC indicators before generic Windows Server)
            if "windows" in sys_descr:
                if "active directory" in sys_descr or "domain controller" in sys_descr:
                    return "Domain Controller"
                if any(kw in sys_descr for kw in ("server 2019", "server 2022", "server 2016",
                                                    "server 2012", "server 2008")):
                    return "Windows Server"
                return "Windows Server" if "server" in sys_descr else "Windows Device"
            # Linux
            if "linux" in sys_descr:
                return "Linux/Unix Server"

    # ── Service version strings ────────────────────────────────────────────
    if version_info:
        all_versions = " ".join(
            str(v.get("version", ""))
            for v in version_info.values()
            if isinstance(v, dict)
        ).lower()
        if all_versions:
            if "microsoft-iis" in all_versions or "microsoft iis" in all_versions:
                return "Windows Server"
            if "windows" in all_versions and "server" in all_versions:
                return "Windows Server"
            if "windows" in all_versions:
                return "Windows Device"
            if any(kw in all_versions for kw in ("apache", "nginx", "lighttpd", "openlitespeed")):
                return "Server"
            if "openssh" in all_versions and any(kw in all_versions for kw in (
                    "ubuntu", "debian", "centos", "rhel", "fedora", "raspbian")):
                return "Linux/Unix Server"
            if "cisco" in all_versions:
                return "Network Infrastructure"
            if "esxi" in all_versions or "vmware" in all_versions:
                return "Hypervisor"

    # ── Port 554 (RTSP) — strong camera signal ─────────────────────────────
    if 554 in ports_set:
        return "IP Camera / NVR"

    # ── Printer ports ──────────────────────────────────────────────────────
    if ports_set & {9100, 515, 631}:
        return "Printer"
    if any(kw in vendor for kw in _PRINTER_VENDORS):
        return "Printer"
    if any(kw in hostname_lower for kw in ("print", "printer", "mfp", "copier",
                                            "kyocera", "canon", "ricoh", "xerox")):
        return "Printer"

    # ── UPS ────────────────────────────────────────────────────────────────
    if any(kw in vendor for kw in _UPS_VENDORS):
        return "UPS / Power Device"
    if any(kw in hostname_lower for kw in ("ups", "pdu", "poweredge-ups")):
        return "UPS / Power Device"

    # ── Firewall — vendor OUI ──────────────────────────────────────────────
    if any(kw in vendor for kw in _FIREWALL_VENDORS):
        return "Firewall"
    if any(kw in hostname_lower for kw in ("firewall", "fw-", "-fw", "asa-", "fortigate",
                                            "sonicwall", "panos", "watchguard")):
        return "Firewall"

    # ── IP Camera / NVR — vendor OUI ──────────────────────────────────────
    if any(kw in vendor for kw in _CAMERA_VENDORS):
        return "IP Camera / NVR"
    if any(kw in hostname_lower for kw in ("cam", "camera", "nvr", "dvr", "ipcam",
                                            "cctv", "hikvision", "dahua", "axis")):
        return "IP Camera / NVR"

    # ── NAS / Storage ──────────────────────────────────────────────────────
    if any(kw in vendor for kw in _NAS_VENDORS):
        return "NAS / Storage"
    if ports_set & {5000, 5001} and not (ports_set & {22, 3389, 445}):
        return "NAS / Storage"   # Synology DSM ports, minimal other services
    if any(kw in hostname_lower for kw in ("nas", "synology", "qnap", "diskstation",
                                            "storage", "nfs-server")):
        return "NAS / Storage"

    # ── VoIP Phone ─────────────────────────────────────────────────────────
    if 5060 in ports_set:
        return "VoIP Phone"
    if any(kw in vendor for kw in _VOIP_VENDORS):
        return "VoIP Phone"
    if any(kw in hostname_lower for kw in ("voip", "phone", "sip-", "polycom",
                                            "yealink", "grandstream")):
        return "VoIP Phone"

    # ── Hypervisor ─────────────────────────────────────────────────────────
    if 902 in ports_set and (443 in ports_set or 8080 in ports_set):
        return "Hypervisor"
    if "vmware" in vendor and ports_set & {902, 443}:
        return "Hypervisor"

    # ── Wireless Access Point ──────────────────────────────────────────────
    if any(kw in vendor for kw in _AP_VENDORS):
        # Distinguish AP from switch/router: APs typically only have 80/443/22
        non_ap_ports = ports_set - {22, 80, 443, 8080, 8443}
        if len(non_ap_ports) <= 2:
            return "Wireless Access Point"
    if any(kw in hostname_lower for kw in ("ap-", "-ap", "wap", "wifi", "wireless",
                                            "unifi", "meraki", "airmax", "ruckus",
                                            "aruba-ap")):
        return "Wireless Access Point"

    # ── Network Switch ─────────────────────────────────────────────────────
    if any(kw in vendor for kw in _SWITCH_VENDORS):
        # Switches typically: SSH, HTTP/HTTPS for management, no workstation ports
        if not (ports_set & {3389, 5900, 445}):  # no RDP/VNC/SMB
            return "Network Switch"
    if any(kw in hostname_lower for kw in ("switch", "sw-", "-sw", "stack",
                                            "catalyst", "procurve", "aruba-sw")):
        return "Network Switch"

    # ── General network infrastructure ─────────────────────────────────────
    if any(kw in vendor for kw in ("cisco", "ubiquiti", "netgear", "d-link",
                                    "tp-link", "linksys", "juniper",
                                    "fortinet", "mikrotik", "sonicwall")):
        return "Network Infrastructure"
    if any(kw in hostname_lower for kw in ("router", "switch", "firewall", "gateway",
                                            "fw", "rt-", "gw-")):
        return "Network Infrastructure"
    if 8291 in ports_set:   # MikroTik Winbox
        return "Network Infrastructure"

    # ── Domain Controller (Windows AD) ────────────────────────────────────
    # Ports 88 (Kerberos) + 389 (LDAP) together are near-definitive for a DC
    if 88 in ports_set and 389 in ports_set:
        return "Domain Controller"
    if any(kw in hostname_lower for kw in ("dc-", "-dc", "dc01", "dc02",
                                            "domaincontroller", "adserver")):
        if 389 in ports_set or 445 in ports_set:
            return "Domain Controller"

    # ── Server indicators ──────────────────────────────────────────────────
    if {445, 139} & ports_set and {3389, 5985} & ports_set:
        return "Windows Server"
    if 22 in ports_set and {111, 2049} & ports_set:
        return "Linux/Unix Server"
    if {80, 443} & ports_set and {22, 3389} & ports_set:
        return "Server"
    if any(is_database_port(p) for p in open_ports):
        return "Database Server"

    # ── Windows workstation / device ───────────────────────────────────────
    if {445, 139} & ports_set and 3389 in ports_set:
        return "Windows Workstation"
    if {445, 139} & ports_set:
        return "Windows Device"

    # ── Raspberry Pi / IoT / embedded ──────────────────────────────────────
    if "raspberry" in vendor:
        return "Raspberry Pi"
    if any(kw in vendor for kw in ("espressif", "particle", "arduino")):
        return "IoT Device"

    # ── Apple ──────────────────────────────────────────────────────────────
    if "apple" in vendor:
        return "Apple Device"

    # ── VMware virtual machine ──────────────────────────────────────────────
    if "vmware" in vendor:
        return "Virtual Machine"

    # ── Generic ────────────────────────────────────────────────────────────
    return "Unknown Device"


# ── System info helpers ────────────────────────────────────────────────────

def get_hostname() -> str:
    return socket.gethostname()


def get_pi_model() -> str:
    """Return Raspberry Pi model string if available."""
    try:
        model_path = Path("/proc/device-tree/model")
        if model_path.exists():
            return model_path.read_text().rstrip("\x00").strip()
    except Exception:
        pass
    return "Unknown"


def get_os_info() -> str:
    """Return OS description string."""
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return "Unknown OS"


# ── WiFi helpers ──────────────────────────────────────────────────────────

def get_wifi_interfaces() -> list:
    """Return list of wireless interface names (e.g. ['wlan0']).

    Tries /sys/class/net/*/wireless first (fastest, no external commands),
    then falls back to ``iw dev`` output parsing.
    """
    wifi_ifaces = []
    # Method 1: sysfs — any interface with a 'wireless' subdir is WiFi
    try:
        net_dir = Path("/sys/class/net")
        if net_dir.is_dir():
            for iface_dir in net_dir.iterdir():
                if (iface_dir / "wireless").is_dir():
                    wifi_ifaces.append(iface_dir.name)
    except Exception:
        pass

    if wifi_ifaces:
        return sorted(wifi_ifaces)

    # Method 2: parse 'iw dev' output
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    name = line.split(None, 1)[1]
                    if name not in wifi_ifaces:
                        wifi_ifaces.append(name)
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
        logger.debug(f"iw dev fallback failed: {e}")

    if wifi_ifaces:
        logger.debug(f"WiFi interfaces: {', '.join(sorted(wifi_ifaces))}")
    else:
        logger.debug("No WiFi interfaces detected")
    return sorted(wifi_ifaces)


def freq_to_channel(freq_mhz: int) -> int:
    """Convert a WiFi frequency in MHz to a channel number."""
    if 2412 <= freq_mhz <= 2484:
        if freq_mhz == 2484:
            return 14
        return (freq_mhz - 2407) // 5
    if 5170 <= freq_mhz <= 5825:
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:  # WiFi 6E
        return (freq_mhz - 5950) // 5
    return 0


def freq_to_band(freq_mhz: int) -> str:
    """Return '2.4GHz', '5GHz', or '6GHz' for a given frequency."""
    if 2400 <= freq_mhz <= 2500:
        return "2.4GHz"
    if 5100 <= freq_mhz <= 5900:
        return "5GHz"
    if 5925 <= freq_mhz <= 7200:
        return "6GHz"
    return "Unknown"


def signal_quality(dbm: int) -> str:
    """Human-readable signal quality from dBm value."""
    if dbm >= -50:
        return "Excellent"
    if dbm >= -60:
        return "Good"
    if dbm >= -70:
        return "Fair"
    return "Weak"
