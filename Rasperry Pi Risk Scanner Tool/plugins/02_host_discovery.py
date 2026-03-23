#!/usr/bin/env python3
"""
Plugin: Host Discovery  (Phase 2)
Ping-sweep / ARP-scan to enumerate live hosts on each subnet.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_DISCOVERY
from network_utils import reverse_dns, classify_device, get_mac_vendor

log = logging.getLogger("plugin.host_discovery")


def _nmap_ping_sweep(subnet: str, timeout: int = 30) -> list[dict]:
    """Run nmap -sn against a subnet and return basic host dicts."""
    hosts: list[dict] = []
    try:
        result = subprocess.run(
            ["nmap", "-sn", "--host-timeout", f"{timeout}s", "-oX", "-", subnet],
            capture_output=True, text=True, timeout=timeout + 15,
        )
        import xml.etree.ElementTree as ET
        root = ET.fromstring(result.stdout or "<nmaprun/>")
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            mac_el = host_el.find("address[@addrtype='mac']")
            mac    = (mac_el.get("addr", "") if mac_el is not None else "").upper()
            vendor = mac_el.get("vendor", "") if mac_el is not None else ""
            hostname_el = host_el.find(".//hostname[@type='PTR']")
            hostname = hostname_el.get("name", "") if hostname_el is not None else ""
            hosts.append({
                "ip":       ip,
                "hostname": hostname,
                "mac":      mac,
                "vendor":   vendor or get_mac_vendor(mac),
                "subnet":   subnet,
                "status":   "up",
                "ports":    [],
                "services": [],
                "os_guess": "",
                "ssh":      {},
                "wmi":      {},
                "snmp":     {},
                "cves":     [],
                "compliance": {},
                "risk_score": 0,
                "risk_level": "LOW",
                "tags":     [],
            })
    except FileNotFoundError:
        log.error("nmap not found. Install nmap to enable host discovery.")
    except Exception as exc:
        log.error(f"ping sweep of {subnet} failed: {exc}")
    return hosts


class HostDiscoveryPlugin(ScanPlugin):
    plugin_id    = "host_discovery"
    name         = "Host Discovery"
    category     = CAT_DISCOVERY
    phase        = 2
    description  = "Ping-sweep and ARP-scan all configured subnets to enumerate live hosts."
    version      = "1.0.0"
    author       = "AWN"
    requires     = ["reconnaissance"]
    requires_root = True

    def run(self, ctx: PluginContext) -> None:
        recon   = ctx.scan_results.get("reconnaissance", {})
        subnets = recon.get("subnets", [])
        if not subnets:
            log.warning("No subnets from reconnaissance — nothing to discover.")
            return

        scan_cfg    = ctx.config.get("scan", {})
        timeout     = ctx.get_policy_value("timeout_per_host", scan_cfg.get("host_timeout", 30))
        excluded    = set(scan_cfg.get("excluded_hosts", []))

        all_hosts: list[dict] = []
        seen_ips:  set[str]   = set()

        for subnet in subnets:
            log.info(f"Discovering hosts on {subnet} ...")
            hosts = _nmap_ping_sweep(subnet, timeout=int(timeout))
            for h in hosts:
                if h["ip"] in seen_ips or h["ip"] in excluded:
                    continue
                # Enrich hostname via PTR if missing
                if not h["hostname"]:
                    h["hostname"] = reverse_dns(h["ip"]) or ""
                # Classify device type
                h["device_type"] = classify_device(h)
                # Attach subnet label from recon if available
                labels = recon.get("subnet_labels", {})
                h["subnet_label"] = labels.get(subnet, "")
                seen_ips.add(h["ip"])
                all_hosts.append(h)

        ctx.hosts = all_hosts
        ctx.scan_results["hosts"] = all_hosts
        log.info(f"Host discovery complete: {len(all_hosts)} live host(s) found.")
