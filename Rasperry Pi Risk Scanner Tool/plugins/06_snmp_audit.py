#!/usr/bin/env python3
"""
Plugin: SNMP Enumeration  (Phase 6)
Query each live host via SNMP v1/v2c/v3 to gather system info,
interfaces, ARP table, running processes, and installed software.
"""

from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_SNMP

log = logging.getLogger("plugin.snmp_audit")

# Common SNMP OIDs
_OID_SYSNAME    = "1.3.6.1.2.1.1.5.0"
_OID_SYSDESC    = "1.3.6.1.2.1.1.1.0"
_OID_SYSLOC     = "1.3.6.1.2.1.1.6.0"
_OID_SYSCONTACT = "1.3.6.1.2.1.1.4.0"
_OID_UPTIME     = "1.3.6.1.2.1.1.3.0"
_OID_IF_TABLE   = "1.3.6.1.2.1.2.2"
_OID_ARP_TABLE  = "1.3.6.1.2.1.4.22"
_OID_PROC_TABLE = "1.3.6.1.2.1.25.4.2"
_OID_SW_TABLE   = "1.3.6.1.2.1.25.6.3"


def _find_snmp_cred(ip: str, credentials: list) -> dict | None:
    for cred in credentials:
        if cred.get("type") != "snmp":
            continue
        if ip in cred.get("hosts", []):
            return cred
    for cred in credentials:
        if cred.get("type") != "snmp":
            continue
        if not cred.get("hosts") or "*" in cred.get("hosts", []):
            return cred
    return None


def _snmp_get(ip: str, oid: str, community: str, port: int = 161, version: str = "2c", timeout: int = 5) -> str:
    """Perform a single SNMP GET using the pysnmp library."""
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
        error_ind, error_status, _, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0 if version == "1" else 1),
                UdpTransportTarget((ip, port), timeout=timeout, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
            )
        )
        if error_ind or error_status:
            return ""
        return str(var_binds[0][1]) if var_binds else ""
    except ImportError:
        log.warning("pysnmp not installed. Run: pip install pysnmp")
        return ""
    except Exception:
        return ""


def _snmp_walk(ip: str, oid: str, community: str, port: int = 161, version: str = "2c", timeout: int = 10) -> list[tuple[str, str]]:
    """SNMP WALK, return list of (oid_suffix, value) tuples."""
    rows: list[tuple[str, str]] = []
    try:
        from pysnmp.hlapi import (
            nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
        )
        for (error_ind, error_status, _, var_binds) in nextCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=0 if version == "1" else 1),
            UdpTransportTarget((ip, port), timeout=timeout, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False,
        ):
            if error_ind or error_status:
                break
            for vb in var_binds:
                rows.append((str(vb[0]), str(vb[1])))
    except ImportError:
        pass
    except Exception as exc:
        log.debug(f"{ip} SNMP walk {oid}: {exc}")
    return rows


def _audit_host(ip: str, cred: dict, timeout: int) -> dict:
    community = cred.get("community", "public")
    version   = cred.get("version", "2c")
    port      = int(cred.get("port", 161))

    result: dict = {
        "success":    False,
        "community":  community,
        "version":    version,
        "sysname":    "",
        "sysdesc":    "",
        "sysloc":     "",
        "syscontact": "",
        "uptime":     "",
        "interfaces": [],
        "arp_table":  [],
        "processes":  [],
        "software":   [],
    }

    # Quick reachability check with sysName GET
    sysname = _snmp_get(ip, _OID_SYSNAME, community, port, version, timeout)
    if not sysname:
        log.debug(f"{ip}: SNMP unreachable or wrong community string.")
        return result

    result["success"]    = True
    result["sysname"]    = sysname
    result["sysdesc"]    = _snmp_get(ip, _OID_SYSDESC, community, port, version, timeout)
    result["sysloc"]     = _snmp_get(ip, _OID_SYSLOC, community, port, version, timeout)
    result["syscontact"] = _snmp_get(ip, _OID_SYSCONTACT, community, port, version, timeout)
    result["uptime"]     = _snmp_get(ip, _OID_UPTIME, community, port, version, timeout)

    # Interfaces
    iface_rows = _snmp_walk(ip, _OID_IF_TABLE, community, port, version, timeout)
    ifaces: dict = {}
    for oid_s, val in iface_rows:
        parts = oid_s.rsplit(".", 1)
        if len(parts) == 2:
            idx = parts[1]
            ifaces.setdefault(idx, {})
            if ".2.2.1.2." in oid_s:
                ifaces[idx]["description"] = val
            elif ".2.2.1.5." in oid_s:
                ifaces[idx]["speed"] = val
            elif ".2.2.1.6." in oid_s:
                ifaces[idx]["mac"] = val
            elif ".2.2.1.8." in oid_s:
                ifaces[idx]["status"] = val
    result["interfaces"] = list(ifaces.values())[:50]

    # Installed software (hrSWInstalledTable)
    sw_rows = _snmp_walk(ip, _OID_SW_TABLE, community, port, version, timeout)
    sw_names: list[str] = []
    for oid_s, val in sw_rows:
        if ".25.6.3.1.2." in oid_s and val not in sw_names:
            sw_names.append(val)
    result["software"] = sw_names[:500]

    # Running processes (hrSWRunTable)
    proc_rows = _snmp_walk(ip, _OID_PROC_TABLE, community, port, version, timeout)
    procs: list[str] = []
    for oid_s, val in proc_rows:
        if ".25.4.2.1.2." in oid_s and val not in procs:
            procs.append(val)
    result["processes"] = procs[:200]

    log.debug(
        f"{ip}: SNMP ok — {len(result['interfaces'])} ifaces, "
        f"{len(result['software'])} sw entries, {len(result['processes'])} procs"
    )
    return result


class SNMPAuditPlugin(ScanPlugin):
    plugin_id   = "snmp_audit"
    name        = "SNMP Enumeration"
    category    = CAT_SNMP
    phase       = 6
    description = (
        "Query live hosts via SNMP v1/v2c/v3 to gather system description, "
        "interfaces, ARP table, running processes, and installed software."
    )
    version     = "1.0.0"
    author      = "AWN"
    requires    = ["host_discovery"]

    def run(self, ctx: PluginContext) -> None:
        if not ctx.hosts:
            log.warning("No hosts — skipping SNMP audit.")
            return

        scan_cfg = ctx.config.get("scan", {})
        timeout  = int(ctx.get_policy_value("timeout_per_host", scan_cfg.get("host_timeout", 10)))
        parallel = int(ctx.get_policy_value("max_parallel", scan_cfg.get("max_parallel_hosts", 20)))

        def _try_host(host: dict):
            ip   = host["ip"]
            cred = _find_snmp_cred(ip, ctx.credentials)
            if cred is None:
                cred = {"type": "snmp", "community": "public", "version": "2c"}
            result = _audit_host(ip, cred, timeout)
            host["snmp"] = result
            if result["success"]:
                ctx.coverage["snmp_success"].append(ip)
            else:
                ctx.coverage["snmp_failed"].append(ip)

        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futures = {ex.submit(_try_host, h): h["ip"] for h in ctx.hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    fut.result()
                except Exception as exc:
                    log.error(f"SNMP future error for {ip}: {exc}")

        ctx.sync_hosts()
        success = len(ctx.coverage["snmp_success"])
        log.info(f"SNMP audit complete: {success} host(s) responded.")
