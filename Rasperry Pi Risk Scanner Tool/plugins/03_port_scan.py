#!/usr/bin/env python3
"""
Plugin: Port Scan  (Phase 3)
Run nmap TCP/UDP port scans + OS fingerprinting against all live hosts.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_DISCOVERY
from network_utils import get_service_name

log = logging.getLogger("plugin.port_scan")


# ── Port range helpers ──────────────────────────────────────────────────

def _nmap_port_args(policy_range: str) -> list[str]:
    """Convert a policy port_range string to nmap -p arguments."""
    r = (policy_range or "top1000").strip().lower()
    if r == "top1000":
        return ["--top-ports", "1000"]
    if r == "top100":
        return ["--top-ports", "100"]
    if r in ("full", "all", "1-65535"):
        return ["-p", "1-65535"]
    # Treat anything else as a raw nmap port expression
    return ["-p", r]


# ── Per-host scan ─────────────────────────────────────────────────────

def _scan_host(ip: str, port_args: list[str], timeout: int, intensity: str) -> dict:
    """
    Run nmap SV + OS detection on a single host, return enriched host dict.
    """
    # Timing template: low=T2, normal=T3, high=T4
    timing = {"low": "T2", "normal": "T3", "high": "T4"}.get(intensity, "T3")

    cmd = [
        "nmap", "-sV", "-O", "--osscan-guess",
        f"-{timing}",
        "--host-timeout", f"{timeout}s",
        "-oX", "-",
    ] + port_args + [ip]

    ports: list[dict]   = []
    services: list[str] = []
    os_guess: str       = ""

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 30,
        )
        root = ET.fromstring(result.stdout or "<nmaprun/>")
        host_el = root.find("host")
        if host_el is None:
            return {"ip": ip, "ports": ports, "services": services, "os_guess": os_guess}

        # Ports
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid   = int(port_el.get("portid", 0))
            proto    = port_el.get("protocol", "tcp")
            svc_el   = port_el.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            product  = svc_el.get("product", "") if svc_el is not None else ""
            version  = svc_el.get("version", "") if svc_el is not None else ""
            extra    = svc_el.get("extrainfo", "") if svc_el is not None else ""
            svc_label = f"{product} {version} {extra}".strip() or get_service_name(portid)
            ports.append({
                "port":    portid,
                "proto":   proto,
                "state":   "open",
                "service": svc_name or get_service_name(portid),
                "banner":  svc_label,
            })
            if svc_name and svc_name not in services:
                services.append(svc_name)

        # OS guess
        for osmatch in host_el.findall(".//osmatch"):
            os_guess = osmatch.get("name", "")
            break  # Take highest-accuracy match only

    except FileNotFoundError:
        log.error("nmap not found. Cannot run port scan.")
    except subprocess.TimeoutExpired:
        log.warning(f"Port scan timed out for {ip}")
    except Exception as exc:
        log.error(f"Port scan error for {ip}: {exc}")

    return {"ip": ip, "ports": ports, "services": services, "os_guess": os_guess}


# ── Plugin ───────────────────────────────────────────────────────────────────
class PortScanPlugin(ScanPlugin):
    plugin_id    = "port_scan"
    name         = "Port Scan"
    category     = CAT_DISCOVERY
    phase        = 3
    description  = (
        "Nmap SYN/service-version scan with OS fingerprinting against all "
        "live hosts discovered in Phase 2."
    )
    version      = "1.0.0"
    author       = "AWN"
    requires     = ["host_discovery"]
    requires_root = True

    def run(self, ctx: PluginContext) -> None:
        if not ctx.hosts:
            log.warning("No hosts to scan — skipping port scan.")
            return

        scan_cfg   = ctx.config.get("scan", {})
        timeout    = int(ctx.get_policy_value("timeout_per_host", scan_cfg.get("host_timeout", 120)))
        intensity  = ctx.get_policy_value("intensity", scan_cfg.get("intensity", "normal"))
        parallel   = int(ctx.get_policy_value("max_parallel", scan_cfg.get("max_parallel_hosts", 10)))
        port_range = ctx.get_policy_value("port_range", scan_cfg.get("port_range", "top1000"))
        port_args  = _nmap_port_args(port_range)

        log.info(
            f"Port scanning {len(ctx.hosts)} host(s) | "
            f"range={port_range} intensity={intensity} parallel={parallel}"
        )

        # Build ip → host index for fast update
        host_index = {h["ip"]: h for h in ctx.hosts}

        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futures = {
                ex.submit(_scan_host, ip, port_args, timeout, intensity): ip
                for ip in host_index
            }
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    result = fut.result()
                    host_index[ip]["ports"]    = result["ports"]
                    host_index[ip]["services"] = result["services"]
                    host_index[ip]["os_guess"] = result["os_guess"]
                    log.debug(
                        f"{ip}: {len(result['ports'])} open port(s), OS='{result['os_guess']}'"
                    )
                except Exception as exc:
                    log.error(f"Port scan future error for {ip}: {exc}")

        ctx.sync_hosts()
        total_ports = sum(len(h.get("ports", [])) for h in ctx.hosts)
        log.info(f"Port scan complete: {total_ports} total open port(s) across {len(ctx.hosts)} host(s).")
