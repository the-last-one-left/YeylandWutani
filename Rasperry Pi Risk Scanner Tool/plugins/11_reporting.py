#!/usr/bin/env python3
"""
Plugin: Reporting  (Phase 11)
Persist the completed scan results to disk (JSON + human-readable summary),
rotate old scan archives, and dispatch findings to SOAR / ticketing systems.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_REPORTING

log = logging.getLogger("plugin.reporting")

_LAST_SCAN_FILE   = "last_scan.json"
_HISTORY_DIR      = "history"
_MAX_HISTORY_RUNS = 30
_SUMMARY_FILE     = "latest_summary.txt"


def _severity_bar(count: int, total: int, width: int = 20) -> str:
    if total == 0:
        return "[" + " " * width + "] 0%"
    filled = int(round(count / total * width))
    return "[" + "#" * filled + "-" * (width - filled) + f"] {count}/{total}"


def _write_summary(results: dict, path: str) -> None:
    """Write a human-readable plain-text summary of the scan."""
    hosts   = results.get("hosts", [])
    risk    = results.get("risk", {})
    delta   = results.get("delta", {})
    vdb     = results.get("vuln_db_stats", {})
    cover   = results.get("credential_coverage", {})

    lines = [
        "=" * 70,
        " Yeyland Wutani - Risk Scanner Tool",
        f" Scan Completed : {results.get('scan_end', 'unknown')}",
        f" Policy         : {results.get('policy_name') or 'Default'}",
        "=" * 70,
        "",
        "[ NETWORK RISK ]",
        f"  Overall Score : {risk.get('score', 0):.1f}  ({risk.get('level', 'UNKNOWN')})",
        f"  CRITICAL hosts: {risk.get('breakdown', {}).get('CRITICAL', 0)}",
        f"  HIGH hosts    : {risk.get('breakdown', {}).get('HIGH', 0)}",
        f"  MEDIUM hosts  : {risk.get('breakdown', {}).get('MEDIUM', 0)}",
        f"  LOW hosts     : {risk.get('breakdown', {}).get('LOW', 0)}",
        "",
        "[ HOSTS ]",
        f"  Live hosts     : {len(hosts)}",
        f"  SSH success    : {len(cover.get('ssh_success', []))}",
        f"  WMI success    : {len(cover.get('wmi_success', []))}",
        f"  SNMP success   : {len(cover.get('snmp_success', []))}",
        f"  No credential  : {len(cover.get('no_credential', []))}",
        "",
        "[ VULNERABILITY FINDINGS ]",
        f"  Total CVE matches : {vdb.get('total_cves_matched', 0)}",
        f"  CISA KEV hits     : {vdb.get('kev_hits', 0)}",
        f"  Critical findings : {vdb.get('critical_findings', 0)}",
        "",
    ]

    # Delta section
    if delta and not delta.get("first_run"):
        lines += [
            "[ CHANGES SINCE LAST SCAN ]",
            f"  New hosts      : {len(delta.get('new_hosts', []))}",
            f"  Resolved hosts : {len(delta.get('resolved_hosts', []))}",
            f"  New CVEs       : +{delta.get('new_cves_total', 0)}",
            f"  Resolved CVEs  : -{delta.get('resolved_cves_total', 0)}",
            f"  Risk delta     : {delta.get('network_risk_delta', 0):+.1f}",
            "",
        ]

    # Per-host summary (top 10 by risk score)
    sorted_hosts = sorted(hosts, key=lambda h: h.get("risk_score", 0), reverse=True)
    lines.append("[ TOP HOSTS BY RISK SCORE ]")
    lines.append(f"  {'IP':<18} {'Hostname':<30} {'Score':>7}  Level")
    lines.append("  " + "-" * 64)
    for h in sorted_hosts[:10]:
        lines.append(
            f"  {h['ip']:<18} {(h.get('hostname') or ''):<30} "
            f"{h.get('risk_score', 0):>7.1f}  {h.get('risk_level', 'LOW')}"
        )
    lines.append("")
    lines.append("=" * 70)

    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as exc:
        log.warning(f"Could not write summary: {exc}")


def _rotate_history(data_dir: str, max_runs: int) -> None:
    """Keep only the most recent max_runs history files."""
    hist_dir = Path(data_dir) / _HISTORY_DIR
    if not hist_dir.exists():
        return
    runs = sorted(hist_dir.glob("scan_*.json"), key=lambda p: p.stat().st_mtime)
    for old in runs[:-max_runs]:
        try:
            old.unlink()
            log.debug(f"Rotated old scan archive: {old.name}")
        except Exception:
            pass


def _dispatch_soar(results: dict, config: dict, data_dir: str) -> None:
    """Dispatch findings to SOAR/ticketing systems if configured."""
    soar_cfg = config.get("soar", {})
    if not soar_cfg.get("enabled", False):
        log.debug("SOAR integration not enabled — skipping dispatch.")
        return
    try:
        from soar_connector import dispatch_findings  # type: ignore
        summary = dispatch_findings(results, soar_cfg, data_dir=data_dir)
        log.info(
            f"SOAR dispatch: {summary['total_findings']} findings, "
            f"{summary['notifications_sent']} sent, "
            f"{summary['deduped']} deduped, "
            f"{summary['errors']} errors"
        )
    except ImportError:
        log.error("soar_connector module not found in lib/ — skipping SOAR dispatch.")
    except Exception as exc:
        log.error(f"SOAR dispatch failed: {exc}")


class ReportingPlugin(ScanPlugin):
    plugin_id   = "reporting"
    name        = "Reporting"
    category    = CAT_REPORTING
    phase       = 11
    description = (
        "Persist scan results to data/last_scan.json and data/history/, "
        "write a plain-text summary, rotate old archives, and dispatch "
        "findings to SOAR / ticketing systems (Jira, ServiceNow, Webhook)."
    )
    version     = "1.1.0"
    author      = "AWN"
    requires    = ["risk_scoring"]

    def run(self, ctx: PluginContext) -> None:
        data_dir  = ctx.data_dir
        results   = ctx.scan_results

        # Stamp scan end time
        results["scan_end"] = datetime.now(timezone.utc).isoformat()

        # ─ Save last_scan.json ────────────────────────────────────────────────
        last_path = os.path.join(data_dir, _LAST_SCAN_FILE)
        os.makedirs(data_dir, exist_ok=True)
        with open(last_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        log.info(f"Scan results saved to {last_path}")

        # ─ Archive to history/ ───────────────────────────────────────────────
        hist_dir  = Path(data_dir) / _HISTORY_DIR
        hist_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        arch_path = hist_dir / f"scan_{ts}.json"
        with open(arch_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        log.info(f"Scan archived to {arch_path}")

        # ─ Rotate old history ───────────────────────────────────────────────
        cfg_max = ctx.config.get("reporting", {}).get("max_history_runs", _MAX_HISTORY_RUNS)
        _rotate_history(data_dir, cfg_max)

        # ─ Plain-text summary ──────────────────────────────────────────────
        summary_path = os.path.join(data_dir, _SUMMARY_FILE)
        _write_summary(results, summary_path)
        log.info(f"Summary written to {summary_path}")

        # ─ SOAR / ticketing dispatch ──────────────────────────────────────────
        _dispatch_soar(results, ctx.config, data_dir)

        # ─ Log final summary ────────────────────────────────────────────────
        risk = results.get("risk", {})
        log.info(
            f"Scan complete: score={risk.get('score', 0):.1f} "
            f"level={risk.get('level', '?')} "
            f"hosts={len(results.get('hosts', []))} "
            f"cves={results.get('vuln_db_stats', {}).get('total_cves_matched', 0)}"
        )
