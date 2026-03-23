#!/usr/bin/env python3
"""
Plugin: Reconnaissance  (Phase 1)
Gather network topology: subnets, default gateway, DNS servers, public IP.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import ssl
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_DISCOVERY
from network_utils import (
    get_subnets_from_interfaces,
    get_default_gateway,
    get_dns_servers,
)

log = logging.getLogger("plugin.reconnaissance")


def _get_public_ip_info() -> dict:
    """Query ipinfo.io for public IP and ASN/org data."""
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"Accept": "application/json", "User-Agent": "AWN-Scanner/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read().decode())
    except Exception as exc:
        log.warning(f"Public IP lookup failed: {exc}")
        return {}


class ReconnaissancePlugin(ScanPlugin):
    plugin_id   = "reconnaissance"
    name        = "Reconnaissance"
    category    = CAT_DISCOVERY
    phase       = 1
    description = "Gather network topology: subnets, default gateway, DNS servers, public IP geo-info."
    version     = "1.0.0"
    author      = "AWN"
    requires    = []

    def run(self, ctx: PluginContext) -> None:
        scan_cfg  = ctx.config.get("scan", {})
        overrides = scan_cfg.get("networks", [])

        # Policy can override target networks
        policy_nets = ctx.get_policy_value("networks", "")
        if policy_nets:
            overrides = [n.strip() for n in policy_nets.split(",") if n.strip()]

        if overrides:
            log.info(f"Using policy/config network overrides: {overrides}")
            subnets = overrides
        else:
            subnets = get_subnets_from_interfaces()
            log.info(f"Auto-detected subnets: {subnets}")

        gateway    = get_default_gateway()
        dns_srvs   = get_dns_servers()
        public_info = {}
        if scan_cfg.get("lookup_public_ip", True):
            public_info = _get_public_ip_info()

        # Build subnet labels from config
        subnet_labels: dict = scan_cfg.get("subnet_labels", {})

        recon = {
            "subnets":         subnets,
            "default_gateway": gateway,
            "dns_servers":     dns_srvs,
            "public_ip_info":  public_info,
            "subnet_labels":   subnet_labels,
        }

        ctx.scan_results["reconnaissance"] = recon
        log.info(
            f"Recon complete: {len(subnets)} subnet(s), gateway={gateway}, "
            f"dns={dns_srvs}, public_ip={public_info.get('ip', 'unknown')}"
        )
