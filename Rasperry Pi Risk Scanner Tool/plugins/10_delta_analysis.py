#!/usr/bin/env python3
"""
Plugin: Delta / Trend Analysis  (Phase 10)
Compare the current scan results against the previous scan to identify
new hosts, resolved hosts, new CVEs, closed CVEs, and risk trend.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_DELTA

log = logging.getLogger("plugin.delta_analysis")

_LAST_SCAN_FILE = "last_scan.json"


def _load_last_scan(data_dir: str) -> dict | None:
    path = os.path.join(data_dir, _LAST_SCAN_FILE)
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        log.warning(f"Could not load last scan: {exc}")
        return None


def _host_cve_ids(host: dict) -> set[str]:
    return {c["cve_id"] for c in host.get("cves", [])}


def _compute_delta(current: dict, previous: dict) -> dict:
    """
    Compare current scan_results with the previous scan_results.
    Returns a delta dict with:
      new_hosts, resolved_hosts, changed_hosts,
      new_cves_total, resolved_cves_total,
      risk_delta (current_score - previous_score),
      per_host details
    """
    prev_hosts = {h["ip"]: h for h in previous.get("hosts", [])}
    curr_hosts = {h["ip"]: h for h in current.get("hosts", [])}

    prev_ips = set(prev_hosts)
    curr_ips = set(curr_hosts)

    new_hosts      = sorted(curr_ips - prev_ips)
    resolved_hosts = sorted(prev_ips - curr_ips)
    common_ips     = curr_ips & prev_ips

    new_cves_total  = 0
    res_cves_total  = 0
    changed_hosts: list[dict] = []

    for ip in common_ips:
        c_host = curr_hosts[ip]
        p_host = prev_hosts[ip]

        c_cves = _host_cve_ids(c_host)
        p_cves = _host_cve_ids(p_host)

        new_cves = sorted(c_cves - p_cves)
        res_cves = sorted(p_cves - c_cves)

        c_score = c_host.get("risk_score", 0)
        p_score = p_host.get("risk_score", 0)
        risk_delta = round(c_score - p_score, 1)

        new_cves_total += len(new_cves)
        res_cves_total += len(res_cves)

        if new_cves or res_cves or risk_delta != 0:
            changed_hosts.append({
                "ip":          ip,
                "new_cves":    new_cves,
                "resolved_cves": res_cves,
                "risk_delta":  risk_delta,
                "prev_score":  p_score,
                "curr_score":  c_score,
            })

    prev_net = previous.get("risk", {}).get("score", 0)
    curr_net = current.get("risk", {}).get("score", 0)
    net_risk_delta = round(curr_net - prev_net, 1)

    return {
        "previous_scan_start": previous.get("scan_start", ""),
        "new_hosts":           new_hosts,
        "resolved_hosts":      resolved_hosts,
        "new_cves_total":      new_cves_total,
        "resolved_cves_total": res_cves_total,
        "changed_hosts":       changed_hosts,
        "network_risk_delta":  net_risk_delta,
        "prev_network_score":  prev_net,
        "curr_network_score":  curr_net,
    }


class DeltaAnalysisPlugin(ScanPlugin):
    plugin_id   = "delta_analysis"
    name        = "Delta / Trend Analysis"
    category    = CAT_DELTA
    phase       = 10
    description = (
        "Compare the current scan against the previous one to highlight "
        "new/resolved hosts, new/closed CVEs, and risk score trends."
    )
    version     = "1.0.0"
    author      = "AWN"
    requires    = ["host_discovery", "risk_scoring"]

    def run(self, ctx: PluginContext) -> None:
        previous = _load_last_scan(ctx.data_dir)
        if previous is None:
            log.info("No previous scan found — delta analysis skipped (first run).")
            ctx.scan_results["delta"] = {"first_run": True}
            return

        delta = _compute_delta(ctx.scan_results, previous)
        ctx.scan_results["delta"] = delta

        log.info(
            f"Delta analysis: +{len(delta['new_hosts'])} new hosts, "
            f"-{len(delta['resolved_hosts'])} resolved, "
            f"+{delta['new_cves_total']} new CVEs, "
            f"-{delta['resolved_cves_total']} resolved CVEs, "
            f"net risk delta={delta['network_risk_delta']:+.1f}"
        )
