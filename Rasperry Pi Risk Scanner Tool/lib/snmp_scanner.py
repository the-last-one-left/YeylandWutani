#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
snmp_scanner.py - SNMP v2c/v3 Network Equipment Audit

Collects sysDescr, sysName, ifTable, ipAddrTable, and vendor-specific
firmware version strings (Cisco, Fortinet, Aruba) via pysnmp.
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

_SNMP_TIMEOUT = 5
_SNMP_RETRIES = 1


def scan_host_snmp(ip: str, credential_profile: dict) -> dict:
    """
    Perform SNMP scan of a network device.
    Returns dict with sysDescr, firmware, interfaces, etc.
    """
    result = {
        "ip": ip,
        "snmp_success": False,
        "snmp_version": None,
        "sys_descr": None,
        "sys_name": None,
        "sys_contact": None,
        "sys_location": None,
        "firmware_version": None,
        "vendor": None,
        "model": None,
        "interfaces": [],
        "arp_table": [],
        "security_flags": [],
        "error": None,
    }

    cred_type = profile_type = credential_profile.get("type", "snmp_v2c")
    community = credential_profile.get("snmp_community", "public")

    logger.info(f"SNMP scan: {ip} (type={cred_type})")

    try:
        from pysnmp.hlapi import (
            getCmd, nextCmd, bulkCmd,
            SnmpEngine, CommunityData, UsmUserData,
            UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity,
        )
    except ImportError:
        logger.error("pysnmp not installed — SNMP scan unavailable")
        result["error"] = "pysnmp not installed"
        return result

    engine = SnmpEngine()

    if cred_type == "snmp_v2c":
        auth = CommunityData(community, mpModel=1)
        result["snmp_version"] = "v2c"
        # Flag: default community string
        if community in ("public", "private"):
            result["security_flags"].append({
                "type": "snmp_default_community",
                "severity": "HIGH",
                "description": f"SNMP default community string '{community}' accepted on {ip}",
            })
        # Flag: v2c in use (recommend v3)
        result["security_flags"].append({
            "type": "snmp_v2c_in_use",
            "severity": "MEDIUM",
            "description": f"SNMP v2c in use on {ip} — upgrade to v3 for authentication/encryption",
        })
    elif cred_type == "snmp_v3":
        from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol
        auth = UsmUserData(
            credential_profile.get("username", ""),
            authKey=credential_profile.get("snmp_auth_key", ""),
            privKey=credential_profile.get("snmp_priv_key", ""),
            authProtocol=usmHMACSHAAuthProtocol,
            privProtocol=usmAesCfb128Protocol,
        )
        result["snmp_version"] = "v3"
    else:
        result["error"] = f"Unknown SNMP cred type: {cred_type}"
        return result

    transport = UdpTransportTarget((ip, 161), timeout=_SNMP_TIMEOUT, retries=_SNMP_RETRIES)

    def snmp_get(oid_name: str, mib: str = "SNMPv2-MIB") -> Optional[str]:
        """GET a single OID value."""
        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    engine, auth, transport, ContextData(),
                    ObjectType(ObjectIdentity(mib, oid_name, 0)),
                )
            )
            if error_indication or error_status:
                return None
            return str(var_binds[0][1])
        except Exception as e:
            logger.debug(f"SNMP GET {oid_name} failed on {ip}: {e}")
            return None

    def snmp_get_raw(oid: str) -> Optional[str]:
        """GET a raw OID string."""
        try:
            from pysnmp.hlapi import ObjectType, ObjectIdentity
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    engine, auth, transport, ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                )
            )
            if error_indication or error_status:
                return None
            return str(var_binds[0][1])
        except Exception as e:
            logger.debug(f"SNMP GET OID {oid} failed on {ip}: {e}")
            return None

    # ── System base OIDs ──────────────────────────────────────────────────
    sys_descr = snmp_get("sysDescr")
    if not sys_descr:
        # Try v1 community
        if cred_type == "snmp_v2c":
            auth_v1 = CommunityData(community, mpModel=0)
            try:
                error_indication, error_status, _, var_binds = next(
                    getCmd(engine, auth_v1, transport, ContextData(),
                           ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)))
                )
                if not error_indication and not error_status:
                    sys_descr = str(var_binds[0][1])
                    result["snmp_version"] = "v1"
                    result["security_flags"].insert(0, {
                        "type": "snmp_v1_in_use",
                        "severity": "HIGH",
                        "description": f"SNMP v1 in use on {ip} — insecure, no authentication",
                    })
            except Exception:
                pass

    if not sys_descr:
        result["error"] = "SNMP not responding or wrong credentials"
        logger.info(f"SNMP scan failed: {ip} — no sysDescr response")
        return result

    result["snmp_success"] = True
    result["sys_descr"] = sys_descr
    result["sys_name"] = snmp_get("sysName")
    result["sys_contact"] = snmp_get("sysContact")
    result["sys_location"] = snmp_get("sysLocation")

    logger.info(f"SNMP: {ip} sysDescr={sys_descr[:80]}")

    # ── Vendor / firmware detection ───────────────────────────────────────
    descr_lower = sys_descr.lower()
    vendor, model, firmware = _parse_vendor_firmware(descr_lower, sys_descr)
    result["vendor"] = vendor
    result["model"] = model

    # Vendor-specific extended OIDs
    if "cisco" in descr_lower:
        ios_ver = snmp_get_raw("1.3.6.1.4.1.9.9.25.1.1.1.2.7")  # ciscoImageString
        if ios_ver:
            firmware = ios_ver.strip()
    elif "fortinet" in descr_lower or "fortigate" in descr_lower or "fortios" in descr_lower:
        forti_ver = snmp_get_raw("1.3.6.1.4.1.12356.1.5.0")  # fnSysVersion
        if forti_ver:
            firmware = forti_ver.strip()
    elif "aruba" in descr_lower or "arubaos" in descr_lower:
        aruba_ver = snmp_get_raw("1.3.6.1.4.1.14823.2.2.1.1.1.4.0")  # wlsxSystemSoftwareVersion
        if aruba_ver:
            firmware = aruba_ver.strip()

    if firmware:
        result["firmware_version"] = firmware

    # ── Interface table (ifTable) ─────────────────────────────────────────
    try:
        ifaces = _walk_iftable(engine, auth, transport)
        result["interfaces"] = ifaces
    except Exception as e:
        logger.debug(f"SNMP ifTable walk failed on {ip}: {e}")

    # ── ARP table enrichment ───────────────────────────────────────────────
    try:
        arp = _walk_arp_table(engine, auth, transport)
        result["arp_table"] = arp
    except Exception as e:
        logger.debug(f"SNMP ARP table walk failed on {ip}: {e}")

    logger.info(
        f"SNMP scan complete: {ip} — vendor={result['vendor']}, "
        f"firmware={result['firmware_version']}, {len(result['interfaces'])} interfaces"
    )
    return result


def _parse_vendor_firmware(descr_lower: str, descr_raw: str) -> tuple:
    """Extract vendor, model, firmware from sysDescr string."""
    vendor = "Unknown"
    model = None
    firmware = None

    # Extract firmware version (common patterns)
    # Cisco: "IOS Software, Version 15.2(4)M3"
    m = re.search(r'version\s+([\d\.()a-zA-Z]+)', descr_raw, re.IGNORECASE)
    if m:
        firmware = m.group(1)

    if "cisco" in descr_lower:
        vendor = "Cisco"
    elif "fortinet" in descr_lower or "fortios" in descr_lower or "fortigate" in descr_lower:
        vendor = "Fortinet"
    elif "aruba" in descr_lower or "arubaos" in descr_lower:
        vendor = "Aruba Networks"
    elif "ubiquiti" in descr_lower or "edgeos" in descr_lower or "unifi" in descr_lower:
        vendor = "Ubiquiti"
    elif "juniper" in descr_lower or "junos" in descr_lower:
        vendor = "Juniper"
    elif "mikrotik" in descr_lower or "routeros" in descr_lower:
        vendor = "MikroTik"
    elif "sonicwall" in descr_lower:
        vendor = "SonicWall"
    elif "palo alto" in descr_lower or "pan-os" in descr_lower:
        vendor = "Palo Alto"
    elif "hp" in descr_lower or "hewlett" in descr_lower or "procurve" in descr_lower:
        vendor = "HP/Aruba"
    elif "netgear" in descr_lower:
        vendor = "Netgear"
    elif "linux" in descr_lower:
        vendor = "Linux"
        m = re.search(r'linux\s+([\d\.]+)', descr_raw, re.IGNORECASE)
        if m:
            firmware = m.group(1)

    return vendor, model, firmware


def _walk_iftable(engine, auth, transport) -> list:
    """Walk ifTable and return list of interface dicts."""
    from pysnmp.hlapi import nextCmd, ObjectType, ObjectIdentity, ContextData

    interfaces = {}

    oid_map = {
        "1.3.6.1.2.1.2.2.1.2": "ifDescr",
        "1.3.6.1.2.1.2.2.1.5": "ifSpeed",
        "1.3.6.1.2.1.2.2.1.8": "ifOperStatus",
        "1.3.6.1.2.1.2.2.1.14": "ifInErrors",
        "1.3.6.1.2.1.2.2.1.20": "ifOutErrors",
    }

    for base_oid, field_name in oid_map.items():
        try:
            for error_indication, error_status, error_index, var_binds in nextCmd(
                engine, auth, transport, ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False,
                maxRows=100,
            ):
                if error_indication or error_status:
                    break
                for oid, val in var_binds:
                    oid_str = str(oid)
                    if not oid_str.startswith(base_oid):
                        break
                    idx = oid_str.split(".")[-1]
                    if idx not in interfaces:
                        interfaces[idx] = {"index": idx}
                    interfaces[idx][field_name] = str(val)
        except Exception:
            pass

    return list(interfaces.values())[:50]


def _walk_arp_table(engine, auth, transport) -> list:
    """Walk ipNetToMediaTable for ARP entries."""
    from pysnmp.hlapi import nextCmd, ObjectType, ObjectIdentity, ContextData

    arp_entries = []
    try:
        for error_indication, error_status, _, var_binds in nextCmd(
            engine, auth, transport, ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.22.1.3")),  # ipNetToMediaNetAddress
            lexicographicMode=False,
            maxRows=200,
        ):
            if error_indication or error_status:
                break
            for oid, val in var_binds:
                if not str(oid).startswith("1.3.6.1.2.1.4.22.1.3"):
                    break
                arp_entries.append({"ip": str(val)})
    except Exception:
        pass

    return arp_entries[:100]
