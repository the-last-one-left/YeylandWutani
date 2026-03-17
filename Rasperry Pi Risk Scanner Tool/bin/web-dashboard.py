#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Pi
web-dashboard.py - Lightweight web dashboard and control panel

Runs on port 8080, no Flask/Django — stdlib http.server + threading only.
All HTML/CSS/JS served as inline Python strings.

Install target: /opt/risk-scanner/
Service user:   risk-scanner
"""

import argparse
import gzip
import hashlib
import hmac
import http.cookies
import http.server
import json
import logging
import logging.handlers
import os
import secrets
import socketserver
import subprocess
import sys
import threading
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# ── bcrypt optional import ────────────────────────────────────────────────────
try:
    import bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = Path("/opt/risk-scanner")
CONFIG_PATH = BASE_DIR / "config" / "config.json"
DASHBOARD_CONFIG_PATH = BASE_DIR / "config" / "dashboard.json"
LOG_FILE = BASE_DIR / "logs" / "risk-scanner-web.log"
SCANNER_LOG_FILE = BASE_DIR / "logs" / "risk-scanner.log"
HISTORY_DIR = BASE_DIR / "data" / "history"

logger = logging.getLogger("risk-scanner-web")

# ── Session store (in-memory) ─────────────────────────────────────────────────
_sessions: dict[str, datetime] = {}
_sessions_lock = threading.Lock()
SESSION_DURATION_HOURS = 8
COOKIE_NAME = "rs_session"


# ── Password helpers ──────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    if _BCRYPT_AVAILABLE:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    # Fallback: HMAC-SHA256 with a random salt encoded in the hash string
    salt = secrets.token_hex(16)
    digest = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    return f"hmac:{salt}:{digest}"


def _verify_password(password: str, stored_hash: str) -> bool:
    if not stored_hash:
        return False
    try:
        if stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$"):
            if _BCRYPT_AVAILABLE:
                return bcrypt.checkpw(password.encode(), stored_hash.encode())
            return False
        if stored_hash.startswith("hmac:"):
            parts = stored_hash.split(":", 2)
            if len(parts) != 3:
                return False
            _, salt, expected = parts
            digest = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(digest, expected)
    except Exception:
        pass
    return False


def _load_password_hash() -> str:
    try:
        with open(DASHBOARD_CONFIG_PATH) as f:
            data = json.load(f)
        return data.get("password_hash", "")
    except Exception:
        return ""


# ── Session helpers ───────────────────────────────────────────────────────────

def _create_session() -> str:
    token = secrets.token_hex(32)
    expires = datetime.now() + timedelta(hours=SESSION_DURATION_HOURS)
    with _sessions_lock:
        _sessions[token] = expires
    return token


def _validate_session(token: str) -> bool:
    if not token:
        return False
    with _sessions_lock:
        expires = _sessions.get(token)
        if expires is None:
            return False
        if datetime.now() > expires:
            del _sessions[token]
            return False
    return True


def _delete_session(token: str) -> None:
    with _sessions_lock:
        _sessions.pop(token, None)


def _get_session_cookie(headers) -> str:
    cookie_header = headers.get("Cookie", "")
    if not cookie_header:
        return ""
    try:
        c = http.cookies.SimpleCookie()
        c.load(cookie_header)
        if COOKIE_NAME in c:
            return c[COOKIE_NAME].value
    except Exception:
        pass
    return ""


# ── Main config ───────────────────────────────────────────────────────────────

def _load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


# ── Scan summary helper ───────────────────────────────────────────────────────

def _get_last_scan_summary() -> Optional[dict]:
    try:
        history = sorted(HISTORY_DIR.glob("*.json.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not history:
            return None
        latest = history[0]
        with gzip.open(latest, "rt", encoding="utf-8") as f:
            data = json.load(f)

        hosts_raw = data.get("hosts", [])
        hosts = []
        for h in hosts_raw:
            kev_list = h.get("kev_cves", []) or []
            hosts.append({
                "ip": h.get("ip", ""),
                "hostname": h.get("hostname", ""),
                "os_guess": h.get("os_guess", "Unknown"),
                "risk_score": h.get("risk_score", 0),
                "risk_level": h.get("risk_level", "LOW"),
                "kev_cves": len(kev_list) if isinstance(kev_list, list) else kev_list,
                "credentialed": bool(h.get("credentialed", False)),
                "open_ports": len(h.get("open_ports", [])),
                "cves": h.get("cves", []),
                "security_findings": h.get("security_findings", []),
            })

        hosts.sort(key=lambda x: x["risk_score"], reverse=True)

        return {
            "hosts": hosts,
            "env_score": data.get("env_risk_score", 0),
            "env_level": data.get("env_risk_level", "LOW"),
            "scan_time": data.get("scan_time", ""),
            "delta": data.get("delta", {}),
            "credentialed_count": sum(1 for h in hosts if h["credentialed"]),
            "kev_cve_count": sum(h["kev_cves"] for h in hosts),
            "critical_hosts": sum(1 for h in hosts if h["risk_level"] == "CRITICAL"),
            "high_hosts": sum(1 for h in hosts if h["risk_level"] == "HIGH"),
        }
    except Exception as e:
        logger.warning("Could not load last scan summary: %s", e)
        return None


# ── Status helper ─────────────────────────────────────────────────────────────

def _get_status() -> dict:
    summary = _get_last_scan_summary()

    # Determine if service is active
    service_active = False
    try:
        r = subprocess.run(
            ["systemctl", "is-active", "risk-scanner-daily.service"],
            capture_output=True, text=True, timeout=5
        )
        service_active = r.stdout.strip() in ("active", "activating")
    except Exception:
        pass

    # Determine scan_in_progress via lock file
    scan_in_progress = (BASE_DIR / "data" / ".scanner.lock").exists()

    # Next scan from timer
    next_scan = ""
    try:
        r = subprocess.run(
            ["systemctl", "show", "risk-scanner-daily.timer", "--property=NextElapseUSecRealtime"],
            capture_output=True, text=True, timeout=5
        )
        val = r.stdout.strip()
        if "=" in val:
            usec = int(val.split("=")[1])
            if usec > 0:
                next_scan = datetime.fromtimestamp(usec / 1_000_000).strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        pass

    # NVD DB status
    nvd_path = BASE_DIR / "data" / "vuln-db" / "nvd-cache.json"
    nvd_last_updated = ""
    nvd_stale = True
    try:
        mtime = nvd_path.stat().st_mtime
        nvd_dt = datetime.fromtimestamp(mtime)
        nvd_last_updated = nvd_dt.strftime("%Y-%m-%dT%H:%M:%S")
        nvd_stale = (datetime.now() - nvd_dt).days >= 2
    except Exception:
        pass

    if summary:
        return {
            "service_active": service_active,
            "last_scan": summary.get("scan_time", ""),
            "next_scan": next_scan,
            "env_risk_score": summary.get("env_score", 0),
            "env_risk_level": summary.get("env_level", "LOW"),
            "host_count": len(summary.get("hosts", [])),
            "credentialed_count": summary.get("credentialed_count", 0),
            "kev_cve_count": summary.get("kev_cve_count", 0),
            "critical_hosts": summary.get("critical_hosts", 0),
            "high_hosts": summary.get("high_hosts", 0),
            "nvd_last_updated": nvd_last_updated,
            "nvd_stale": nvd_stale,
            "scan_in_progress": scan_in_progress,
        }
    else:
        return {
            "service_active": service_active,
            "last_scan": "",
            "next_scan": next_scan,
            "env_risk_score": 0,
            "env_risk_level": "LOW",
            "host_count": 0,
            "credentialed_count": 0,
            "kev_cve_count": 0,
            "critical_hosts": 0,
            "high_hosts": 0,
            "nvd_last_updated": nvd_last_updated,
            "nvd_stale": nvd_stale,
            "scan_in_progress": scan_in_progress,
        }


# ── systemctl helper ──────────────────────────────────────────────────────────

def _run_systemctl(action: str, service: str) -> dict:
    try:
        r = subprocess.run(
            ["systemctl", action, service],
            capture_output=True, text=True, timeout=10
        )
        if r.returncode == 0:
            return {"success": True, "message": f"{action} {service}: OK"}
        else:
            msg = r.stderr.strip() or r.stdout.strip() or f"Exit code {r.returncode}"
            return {"success": False, "message": msg}
    except subprocess.TimeoutExpired:
        return {"success": False, "message": "systemctl timed out"}
    except FileNotFoundError:
        return {"success": False, "message": "systemctl not found"}
    except Exception as e:
        return {"success": False, "message": str(e)}


# ── Log tail helper ───────────────────────────────────────────────────────────

def _get_log_lines(n: int = 100) -> list[str]:
    try:
        with open(SCANNER_LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        return [l.rstrip() for l in lines[-n:]]
    except Exception:
        return []


# ── HTML pages ────────────────────────────────────────────────────────────────

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #F5F5F5; color: #333; display: flex; min-height: 100vh; }

/* Sidebar */
.sidebar { width: 220px; min-height: 100vh; background: #2D2D2D; color: #CCC;
           flex-shrink: 0; display: flex; flex-direction: column; }
.sidebar-brand { padding: 20px 16px 12px; border-bottom: 1px solid #444; }
.sidebar-brand .company { font-size: 13px; color: #FF6600; font-weight: 700;
                           letter-spacing: 0.5px; text-transform: uppercase; }
.sidebar-brand .product { font-size: 18px; font-weight: 700; color: #FFF;
                           margin: 2px 0; }
.sidebar-brand .tagline { font-size: 10px; color: #888; font-style: italic; }
.sidebar nav { padding: 16px 0; flex: 1; }
.nav-item { display: block; padding: 10px 20px; color: #CCC; text-decoration: none;
            font-size: 14px; transition: background 0.15s, color 0.15s; cursor: pointer; }
.nav-item:hover, .nav-item.active { background: #3A3A3A; color: #FF6600; }
.nav-item.active { border-left: 3px solid #FF6600; padding-left: 17px; }
.nav-item svg { margin-right: 8px; vertical-align: middle; }

/* Main */
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.topbar { background: #FF6600; color: #FFF; padding: 14px 24px;
          display: flex; align-items: center; justify-content: space-between; }
.topbar h1 { font-size: 20px; font-weight: 700; }
.topbar .actions { display: flex; gap: 10px; align-items: center; }
.topbar a { color: #FFF; text-decoration: none; font-size: 13px;
            opacity: 0.85; transition: opacity 0.15s; }
.topbar a:hover { opacity: 1; }

.content { padding: 24px; flex: 1; overflow-y: auto; }

/* Cards */
.card { background: #FFF; border-radius: 8px; padding: 20px;
        box-shadow: 0 1px 4px rgba(0,0,0,0.08); margin-bottom: 20px; }
.card-title { font-size: 12px; font-weight: 600; text-transform: uppercase;
              letter-spacing: 0.8px; color: #888; margin-bottom: 16px; }

/* Status cards row */
.status-row { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 20px; }
.status-card { flex: 1; min-width: 160px; background: #FFF; border-radius: 8px;
               padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,0.08);
               text-align: center; }
.status-card .label { font-size: 11px; font-weight: 600; text-transform: uppercase;
                       letter-spacing: 0.8px; color: #888; margin-bottom: 8px; }
.status-card .value { font-size: 40px; font-weight: 800; line-height: 1; }
.status-card .sub { font-size: 12px; color: #888; margin-top: 6px; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
         font-size: 11px; font-weight: 700; text-transform: uppercase; margin-top: 6px; }

.risk-critical { color: #C0392B; }
.risk-high     { color: #E67E22; }
.risk-medium   { color: #D4AC0D; }
.risk-low      { color: #27AE60; }
.badge-critical { background: #FDECEA; color: #C0392B; }
.badge-high     { background: #FEF0E6; color: #E67E22; }
.badge-medium   { background: #FEFDE6; color: #B7950B; }
.badge-low      { background: #E9F7EF; color: #27AE60; }
.badge-ok       { background: #E9F7EF; color: #27AE60; }
.badge-warn     { background: #FEF0E6; color: #E67E22; }
.badge-err      { background: #FDECEA; color: #C0392B; }
.badge-blue     { background: #EBF5FB; color: #1A5276; }

/* Action buttons */
.action-row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
.btn { padding: 10px 20px; border: none; border-radius: 6px; font-size: 14px;
       font-weight: 600; cursor: pointer; transition: opacity 0.15s, transform 0.1s;
       display: inline-flex; align-items: center; gap: 8px; }
.btn:hover { opacity: 0.88; }
.btn:active { transform: scale(0.97); }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-orange { background: #FF6600; color: #FFF; }
.btn-blue   { background: #2980B9; color: #FFF; }
.btn-grey   { background: #7F8C8D; color: #FFF; }
.spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid rgba(255,255,255,0.4);
           border-top-color: #FFF; border-radius: 50%; animation: spin 0.7s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }

/* Toast */
#toast { position: fixed; bottom: 24px; right: 24px; padding: 12px 20px;
         border-radius: 8px; font-size: 14px; font-weight: 600; color: #FFF;
         z-index: 9999; opacity: 0; transition: opacity 0.3s;
         box-shadow: 0 4px 12px rgba(0,0,0,0.2); pointer-events: none; }
#toast.show { opacity: 1; }
#toast.success { background: #27AE60; }
#toast.error   { background: #C0392B; }
#toast.info    { background: #2980B9; }

/* Quick stats */
.stats-grid { display: flex; gap: 12px; flex-wrap: wrap; }
.stat-item { background: #F8F8F8; border-radius: 6px; padding: 12px 16px;
             min-width: 140px; flex: 1; }
.stat-item .s-label { font-size: 11px; color: #888; text-transform: uppercase;
                       letter-spacing: 0.6px; margin-bottom: 4px; }
.stat-item .s-value { font-size: 22px; font-weight: 700; }

/* Log box */
.log-box { background: #1E1E1E; border-radius: 6px; padding: 14px;
           font-family: 'Courier New', monospace; font-size: 12px;
           color: #D4D4D4; max-height: 260px; overflow-y: auto;
           white-space: pre-wrap; word-break: break-all; }
.log-box .log-err  { color: #F48771; }
.log-box .log-warn { color: #CE9178; }
.log-box .log-info { color: #9CDCFE; }

/* Host table */
.host-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.host-table th { text-align: left; padding: 10px 12px; background: #F0F0F0;
                  font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px;
                  color: #666; border-bottom: 1px solid #DDD; }
.host-table td { padding: 10px 12px; border-bottom: 1px solid #F0F0F0; vertical-align: top; }
.host-table tr:last-child td { border-bottom: none; }
.host-table tr.row-critical { background: #FFF5F5; }
.host-table tr.row-high     { background: #FFF8F0; }
.host-table tr.row-medium   { background: #FFFDE6; }
.host-table tr.row-low      { background: #F0FFF4; }
.host-table tr.row-critical:hover { background: #FFE8E8; }
.host-table tr.row-high:hover     { background: #FFF0DC; }
.host-table tr.row-medium:hover   { background: #FFFBD0; }
.host-table tr.row-low:hover      { background: #E0FFE8; }
.host-table tr.expandable { cursor: pointer; }
.expand-row { display: none; }
.expand-row td { padding: 8px 12px 16px 32px; background: inherit; }
.expand-content { background: #F8F8F8; border-radius: 6px; padding: 12px;
                   font-size: 12px; color: #555; }
.expand-content strong { display: block; margin-bottom: 6px; color: #333; }

/* Login page */
.login-wrap { display: flex; align-items: center; justify-content: center;
              min-height: 100vh; background: #2D2D2D; width: 100%; }
.login-box { background: #FFF; border-radius: 10px; padding: 40px 36px;
             width: 100%; max-width: 380px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); }
.login-logo { text-align: center; margin-bottom: 28px; }
.login-logo .co { font-size: 12px; color: #FF6600; font-weight: 700;
                   text-transform: uppercase; letter-spacing: 1px; }
.login-logo .prod { font-size: 24px; font-weight: 800; color: #333; margin: 4px 0; }
.login-logo .tag { font-size: 11px; color: #AAA; font-style: italic; }
.login-box label { display: block; font-size: 12px; font-weight: 600;
                    text-transform: uppercase; letter-spacing: 0.6px;
                    color: #888; margin-bottom: 6px; margin-top: 18px; }
.login-box input[type=password] {
    width: 100%; padding: 10px 14px; border: 1px solid #DDD; border-radius: 6px;
    font-size: 15px; outline: none; transition: border-color 0.2s; }
.login-box input[type=password]:focus { border-color: #FF6600; }
.login-btn { width: 100%; margin-top: 24px; padding: 12px;
             background: #FF6600; color: #FFF; border: none; border-radius: 6px;
             font-size: 16px; font-weight: 700; cursor: pointer;
             transition: opacity 0.15s; }
.login-btn:hover { opacity: 0.88; }
.login-err { color: #C0392B; font-size: 13px; text-align: center;
              margin-top: 12px; font-weight: 600; }

/* Responsive */
@media (max-width: 700px) {
    .sidebar { width: 52px; overflow: hidden; }
    .sidebar-brand .product, .sidebar-brand .company,
    .sidebar-brand .tagline, .nav-item span { display: none; }
    .nav-item { padding: 12px; text-align: center; }
    .status-row { flex-direction: column; }
    .action-row { flex-direction: column; }
}
"""

_JS_COMMON = r"""
function showToast(msg, type) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'show ' + (type||'info');
    clearTimeout(window._toastTimer);
    window._toastTimer = setTimeout(() => { t.className = ''; }, 3500);
}

async function apiPost(url, btnId, spinId) {
    const btn = document.getElementById(btnId);
    const spin = document.getElementById(spinId);
    if (btn) btn.disabled = true;
    if (spin) spin.style.display = 'inline-block';
    try {
        const r = await fetch(url, {method:'POST'});
        const d = await r.json();
        if (d.success) {
            showToast(d.message || 'Done', 'success');
        } else {
            showToast(d.message || 'Error', 'error');
        }
    } catch(e) {
        showToast('Request failed: ' + e.message, 'error');
    } finally {
        if (btn) btn.disabled = false;
        if (spin) spin.style.display = 'none';
    }
}

function relTime(isoStr) {
    if (!isoStr) return 'Never';
    const d = new Date(isoStr);
    if (isNaN(d)) return isoStr;
    const diff = Math.floor((Date.now() - d.getTime()) / 1000);
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    return Math.floor(diff/86400) + 'd ago';
}

function riskClass(level) {
    return {CRITICAL:'risk-critical', HIGH:'risk-high',
            MEDIUM:'risk-medium', LOW:'risk-low'}[level] || 'risk-low';
}
function badgeClass(level) {
    return {CRITICAL:'badge-critical', HIGH:'badge-high',
            MEDIUM:'badge-medium', LOW:'badge-low'}[level] || 'badge-low';
}
function rowClass(level) {
    return {CRITICAL:'row-critical', HIGH:'row-high',
            MEDIUM:'row-medium', LOW:'row-low'}[level] || 'row-low';
}

async function refreshStatus() {
    try {
        const r = await fetch('/api/status');
        if (!r.ok) return;
        const d = await r.json();
        const score = d.env_risk_score || 0;
        const level = d.env_risk_level || 'LOW';

        const scoreEl = document.getElementById('risk-score');
        const levelEl = document.getElementById('risk-level');
        if (scoreEl) { scoreEl.textContent = score; scoreEl.className = 'value ' + riskClass(level); }
        if (levelEl) { levelEl.textContent = level; levelEl.className = 'badge ' + badgeClass(level); }

        const hostCount = document.getElementById('host-count');
        const credCount = document.getElementById('cred-count');
        if (hostCount) hostCount.textContent = d.host_count || 0;
        if (credCount) credCount.textContent = d.credentialed_count || 0;

        const kevEl = document.getElementById('kev-count');
        if (kevEl) {
            kevEl.textContent = d.kev_cve_count || 0;
            kevEl.className = 'value ' + ((d.kev_cve_count||0) > 0 ? 'risk-critical' : 'risk-low');
        }

        const lastEl = document.getElementById('last-scan');
        if (lastEl) lastEl.textContent = relTime(d.last_scan);

        const critEl = document.getElementById('crit-hosts');
        const highEl = document.getElementById('high-hosts');
        if (critEl) critEl.textContent = d.critical_hosts || 0;
        if (highEl) highEl.textContent = d.high_hosts || 0;

        const nvdEl = document.getElementById('nvd-badge');
        if (nvdEl) {
            if (d.nvd_stale) {
                nvdEl.textContent = 'STALE';
                nvdEl.className = 'badge badge-err';
            } else if (!d.nvd_last_updated) {
                nvdEl.textContent = 'MISSING';
                nvdEl.className = 'badge badge-err';
            } else {
                nvdEl.textContent = 'CURRENT';
                nvdEl.className = 'badge badge-ok';
            }
        }

        const scanBtn = document.getElementById('btn-scan');
        if (scanBtn) scanBtn.disabled = d.scan_in_progress;
        const progEl = document.getElementById('scan-progress');
        if (progEl) progEl.style.display = d.scan_in_progress ? 'inline' : 'none';

    } catch(e) {}
}

async function refreshLogs() {
    try {
        const r = await fetch('/api/logs');
        if (!r.ok) return;
        const d = await r.json();
        const box = document.getElementById('log-box');
        if (!box) return;
        box.innerHTML = '';
        const lines = d.lines || [];
        lines.forEach(line => {
            const span = document.createElement('span');
            const lower = line.toLowerCase();
            if (lower.includes('error') || lower.includes('critical') || lower.includes('exception')) {
                span.className = 'log-err';
            } else if (lower.includes('warn')) {
                span.className = 'log-warn';
            } else {
                span.className = 'log-info';
            }
            span.textContent = line + '\n';
            box.appendChild(span);
        });
        box.scrollTop = box.scrollHeight;
    } catch(e) {}
}

function initExpandRows() {
    document.querySelectorAll('.expandable').forEach(row => {
        row.addEventListener('click', () => {
            const next = row.nextElementSibling;
            if (next && next.classList.contains('expand-row')) {
                next.style.display = next.style.display === 'table-row' ? 'none' : 'table-row';
            }
        });
    });
}
"""

_SIDEBAR_HTML = """
<div class="sidebar">
  <div class="sidebar-brand">
    <div class="company">Yeyland Wutani</div>
    <div class="product">Risk Scanner</div>
    <div class="tagline">Building Better Systems</div>
  </div>
  <nav>
    <a class="nav-item {cls_dashboard}" href="/dashboard">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M2 2h5v5H2V2zm7 0h5v5H9V2zM2 9h5v5H2V9zm7 0h5v5H9V9z"/>
      </svg><span>Dashboard</span>
    </a>
    <a class="nav-item {cls_detail}" href="/dashboard?view=detail">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M0 2h16v2H0V2zm0 4h16v2H0V6zm0 4h10v2H0v-2z"/>
      </svg><span>Scan Detail</span>
    </a>
    <a class="nav-item {cls_logs}" href="/dashboard?view=logs">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M1 2h14v1H1V2zm0 3h14v1H1V5zm0 3h10v1H1V8zm0 3h12v1H1v-1z"/>
      </svg><span>Logs</span>
    </a>
    <a class="nav-item {cls_settings}" href="/dashboard?view=settings">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M7.5 10a2.5 2.5 0 1 1 0-5 2.5 2.5 0 0 1 0 5zm5.6-2.25-.9-.52a4.98 4.98 0 0 0 0-1.46l.9-.52-.75-1.3-.9.52A4.97 4.97 0 0 0 10.2 4V3h-1.5v1a4.97 4.97 0 0 0-1.26.47l-.9-.52-.75 1.3.9.52a4.98 4.98 0 0 0 0 1.46l-.9.52.75 1.3.9-.52c.38.21.8.37 1.26.47v1h1.5v-1c.46-.1.88-.26 1.26-.47l.9.52.75-1.3z"/>
      </svg><span>Settings</span>
    </a>
  </nav>
</div>
"""


def _dashboard_page(view: str = "main") -> str:
    cls = {"main": "", "detail": "", "logs": "", "settings": ""}
    if view == "detail":
        cls["detail"] = "active"
    elif view == "logs":
        cls["logs"] = "active"
    elif view == "settings":
        cls["settings"] = "active"
    else:
        cls["main"] = "active"

    sidebar = _SIDEBAR_HTML.format(
        cls_dashboard=cls["main"],
        cls_detail=cls["detail"],
        cls_logs=cls["logs"],
        cls_settings=cls["settings"],
    )

    if view == "detail":
        content = _detail_content()
    elif view == "logs":
        content = _logs_content()
    elif view == "settings":
        content = _settings_content()
    else:
        content = _main_content()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Risk Scanner — Yeyland Wutani</title>
<style>{_CSS}</style>
</head>
<body>
{sidebar}
<div class="main">
  <div class="topbar">
    <h1>Risk Scanner Dashboard</h1>
    <div class="actions">
      <a href="/logout">Sign Out</a>
    </div>
  </div>
  <div class="content" id="main-content">
    {content}
  </div>
</div>
<div id="toast"></div>
<script>
{_JS_COMMON}
{_js_for_view(view)}
</script>
</body>
</html>"""


def _js_for_view(view: str) -> str:
    if view == "main":
        return r"""
document.addEventListener('DOMContentLoaded', () => {
    refreshStatus();
    refreshLogs();
    setInterval(refreshStatus, 60000);
    setInterval(refreshLogs, 30000);
});
"""
    elif view == "detail":
        return r"""
async function loadDetail() {
    const tbody = document.getElementById('host-tbody');
    if (!tbody) return;
    try {
        const r = await fetch('/api/scan-detail');
        if (!r.ok) { tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#888">No scan data available</td></tr>'; return; }
        const d = await r.json();
        const hosts = d.hosts || [];
        if (!hosts.length) { tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#888">No hosts found</td></tr>'; return; }
        tbody.innerHTML = '';
        hosts.forEach((h, i) => {
            const rc = rowClass(h.risk_level);
            const bc = badgeClass(h.risk_level);
            const cred = h.credentialed ? '<span class="badge badge-ok">YES</span>' : '<span class="badge badge-err">NO</span>';
            const kevBadge = h.kev_cves > 0 ? `<span class="badge badge-critical">${h.kev_cves}</span>` : '0';
            const scoreClass = riskClass(h.risk_level);
            const tr = document.createElement('tr');
            tr.className = rc + ' expandable';
            tr.innerHTML = `
                <td><strong>${h.ip||''}</strong></td>
                <td>${h.hostname||''}</td>
                <td>${h.os_guess||''}</td>
                <td><span class="${scoreClass}" style="font-weight:700">${h.risk_score||0}</span></td>
                <td><span class="badge ${bc}">${h.risk_level||''}</span></td>
                <td>${kevBadge}</td>
                <td>${cred}</td>
                <td>${h.open_ports||0}</td>
            `;
            tbody.appendChild(tr);

            // Expand row
            const expTr = document.createElement('tr');
            expTr.className = 'expand-row';
            const cves = (h.cves||[]).slice(0,10).join(', ') || 'None';
            const findings = (h.security_findings||[]).slice(0,5).join('; ') || 'None';
            expTr.innerHTML = `<td colspan="8"><div class="expand-content">
                <strong>CVEs (top 10):</strong> ${cves}
                <strong style="margin-top:8px">Security Findings:</strong> ${findings}
            </div></td>`;
            tbody.appendChild(expTr);
        });
        initExpandRows();
    } catch(e) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#C0392B">Error loading data</td></tr>';
    }
}
document.addEventListener('DOMContentLoaded', loadDetail);
"""
    elif view == "logs":
        return r"""
document.addEventListener('DOMContentLoaded', () => {
    refreshLogs();
    setInterval(refreshLogs, 15000);
});
"""
    elif view == "settings":
        return ""
    return ""


def _main_content() -> str:
    return """
<div class="status-row">
  <div class="status-card">
    <div class="label">Risk Score</div>
    <div class="value risk-low" id="risk-score">—</div>
    <div><span class="badge badge-low" id="risk-level">LOW</span></div>
  </div>
  <div class="status-card">
    <div class="label">Hosts</div>
    <div class="value" id="host-count">—</div>
    <div class="sub"><span id="cred-count">—</span> credentialed</div>
  </div>
  <div class="status-card">
    <div class="label">KEV CVEs</div>
    <div class="value risk-low" id="kev-count">—</div>
    <div class="sub">Known Exploited</div>
  </div>
  <div class="status-card">
    <div class="label">Last Scan</div>
    <div class="value" style="font-size:22px;padding-top:8px" id="last-scan">—</div>
  </div>
</div>

<div class="action-row">
  <button class="btn btn-orange" id="btn-scan"
          onclick="apiPost('/api/scan','btn-scan','spin-scan')">
    <span class="spinner" id="spin-scan" style="display:none"></span>
    Run Scan Now
  </button>
  <button class="btn btn-blue" id="btn-report"
          onclick="apiPost('/api/report','btn-report','spin-report')">
    <span class="spinner" id="spin-report" style="display:none"></span>
    Send Report
  </button>
  <button class="btn btn-grey" id="btn-reconfig"
          onclick="apiPost('/api/reconfigure','btn-reconfig','spin-reconfig')">
    <span class="spinner" id="spin-reconfig" style="display:none"></span>
    Reconfigure
  </button>
  <span id="scan-progress" style="display:none;font-size:13px;color:#E67E22;
        align-self:center;font-weight:600">&#9654; Scan in progress…</span>
</div>

<div class="card">
  <div class="card-title">Quick Stats</div>
  <div class="stats-grid">
    <div class="stat-item">
      <div class="s-label">Critical Hosts</div>
      <div class="s-value risk-critical" id="crit-hosts">—</div>
    </div>
    <div class="stat-item">
      <div class="s-label">High Risk Hosts</div>
      <div class="s-value risk-high" id="high-hosts">—</div>
    </div>
    <div class="stat-item">
      <div class="s-label">NVD Database</div>
      <div class="s-value"><span class="badge badge-low" id="nvd-badge">—</span></div>
    </div>
  </div>
</div>

<div class="card">
  <div class="card-title">Recent Activity
    <span style="float:right;font-size:11px;color:#BBB;font-weight:400">
      auto-refresh 30s
    </span>
  </div>
  <div class="log-box" id="log-box">Loading…</div>
</div>
"""


def _detail_content() -> str:
    return """
<div class="card">
  <div class="card-title">Host Risk Detail — click a row to expand</div>
  <div style="overflow-x:auto">
  <table class="host-table">
    <thead>
      <tr>
        <th>IP</th>
        <th>Hostname</th>
        <th>OS</th>
        <th>Score</th>
        <th>Level</th>
        <th>KEV CVEs</th>
        <th>Credentialed</th>
        <th>Open Ports</th>
      </tr>
    </thead>
    <tbody id="host-tbody">
      <tr><td colspan="8" style="text-align:center;color:#888;padding:24px">Loading…</td></tr>
    </tbody>
  </table>
  </div>
</div>
"""


def _logs_content() -> str:
    return """
<div class="card">
  <div class="card-title">Scanner Logs
    <span style="float:right;font-size:11px;color:#BBB;font-weight:400">
      auto-refresh 15s
    </span>
  </div>
  <div class="log-box" style="max-height:600px" id="log-box">Loading…</div>
</div>
"""


def _settings_content() -> str:
    return """
<div class="card">
  <div class="card-title">Settings</div>
  <p style="color:#555;font-size:14px;line-height:1.6">
    To change the dashboard password, run the following command on the Pi:
  </p>
  <pre style="background:#F0F0F0;padding:12px;border-radius:6px;margin-top:12px;
              font-size:13px;color:#333">sudo /opt/risk-scanner/bin/set-dashboard-password.sh</pre>
  <p style="color:#555;font-size:14px;line-height:1.6;margin-top:16px">
    To reconfigure scan targets, reporting, and schedule:
  </p>
  <pre style="background:#F0F0F0;padding:12px;border-radius:6px;margin-top:12px;
              font-size:13px;color:#333">sudo /opt/risk-scanner/bin/update-config.sh</pre>
  <p style="color:#555;font-size:14px;line-height:1.6;margin-top:16px">
    Or click <strong>Reconfigure</strong> from the Dashboard view to trigger the
    configuration wizard remotely (requires the Pi to have a console session).
  </p>
</div>
<div class="card" style="margin-top:0">
  <div class="card-title">Service Actions</div>
  <div class="action-row" style="margin-bottom:0">
    <button class="btn btn-orange" onclick="apiPost('/api/scan','','')">Run Scan Now</button>
    <button class="btn btn-blue"   onclick="apiPost('/api/report','','')">Send Report</button>
  </div>
</div>
"""


def _login_page(error: str = "") -> str:
    err_html = f'<div class="login-err">{error}</div>' if error else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Risk Scanner Login — Yeyland Wutani</title>
<style>{_CSS}</style>
</head>
<body>
<div class="login-wrap">
  <div class="login-box">
    <div class="login-logo">
      <div class="co">Yeyland Wutani</div>
      <div class="prod">Risk Scanner</div>
      <div class="tag">Building Better Systems</div>
    </div>
    <form method="POST" action="/login" autocomplete="off">
      <label for="password">Password</label>
      <input type="password" id="password" name="password"
             autofocus autocomplete="current-password" required>
      <button type="submit" class="login-btn">Sign In</button>
    </form>
    {err_html}
  </div>
</div>
</body>
</html>"""


# ── Request handler ───────────────────────────────────────────────────────────

class DashboardHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        logger.debug("HTTP %s - %s", self.address_string(), fmt % args)

    def _send_response(self, code: int, content_type: str, body: str | bytes):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, code: int, html: str):
        self._send_response(code, "text/html; charset=utf-8", html)

    def _send_json(self, code: int, data: dict):
        self._send_response(code, "application/json", json.dumps(data))

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _set_session_cookie(self, token: str):
        self.send_response(302)
        self.send_header("Location", "/dashboard")
        expires = (datetime.now() + timedelta(hours=SESSION_DURATION_HOURS)).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        self.send_header(
            "Set-Cookie",
            f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Expires={expires}"
        )
        self.end_headers()

    def _clear_session_cookie(self):
        self.send_response(302)
        self.send_header("Location", "/login")
        self.send_header(
            "Set-Cookie",
            f"{COOKIE_NAME}=; Path=/; HttpOnly; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
        )
        self.end_headers()

    def _is_authed(self) -> bool:
        token = _get_session_cookie(self.headers)
        return _validate_session(token)

    def _require_auth_json(self) -> bool:
        if not self._is_authed():
            self._send_json(401, {"error": "Unauthorized"})
            return False
        return True

    def _parse_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        ct = self.headers.get("Content-Type", "")
        if "application/json" in ct:
            try:
                return json.loads(raw)
            except Exception:
                return {}
        # application/x-www-form-urlencoded
        return dict(urllib.parse.parse_qsl(raw))

    def _parsed_path(self):
        parsed = urllib.parse.urlparse(self.path)
        return parsed.path, urllib.parse.parse_qs(parsed.query)

    # ── GET ──────────────────────────────────────────────────────────────────

    def do_GET(self):
        path, qs = self._parsed_path()

        if path == "/":
            if self._is_authed():
                self._redirect("/dashboard")
            else:
                self._redirect("/login")
            return

        if path == "/login":
            self._send_html(200, _login_page())
            return

        if path == "/logout":
            token = _get_session_cookie(self.headers)
            if token:
                _delete_session(token)
            self._clear_session_cookie()
            return

        if path == "/dashboard":
            if not self._is_authed():
                self._redirect("/login")
                return
            view = qs.get("view", ["main"])[0]
            self._send_html(200, _dashboard_page(view))
            return

        if path == "/api/status":
            if not self._require_auth_json():
                return
            self._send_json(200, _get_status())
            return

        if path == "/api/scan-detail":
            if not self._require_auth_json():
                return
            summary = _get_last_scan_summary()
            if summary is None:
                self._send_json(404, {"error": "No scan data available"})
            else:
                self._send_json(200, summary)
            return

        if path == "/api/logs":
            if not self._require_auth_json():
                return
            lines = _get_log_lines(100)
            self._send_json(200, {"lines": lines})
            return

        self._send_html(404, "<h1>404 Not Found</h1>")

    # ── POST ─────────────────────────────────────────────────────────────────

    def do_POST(self):
        path, _ = self._parsed_path()

        if path == "/login":
            body = self._parse_body()
            password = body.get("password", "")
            stored = _load_password_hash()
            if not stored:
                # No password set yet — deny
                self._send_html(200, _login_page("Dashboard password not configured. "
                                                  "Run set-dashboard-password.sh on the Pi."))
                return
            if _verify_password(password, stored):
                token = _create_session()
                self._set_session_cookie(token)
            else:
                self._send_html(200, _login_page("Invalid password."))
            return

        if path == "/api/scan":
            if not self._require_auth_json():
                return
            result = _run_systemctl("start", "risk-scanner-daily.service")
            self._send_json(200, result)
            return

        if path == "/api/report":
            if not self._require_auth_json():
                return
            result = _run_systemctl("start", "risk-scanner-report.service")
            self._send_json(200, result)
            return

        if path == "/api/reconfigure":
            if not self._require_auth_json():
                return
            try:
                subprocess.Popen(
                    ["sudo", "/opt/risk-scanner/bin/update-config.sh"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                self._send_json(200, {"success": True,
                                      "message": "Reconfigure triggered (check Pi console)."})
            except Exception as e:
                self._send_json(200, {"success": False, "message": str(e)})
            return

        self._send_json(404, {"error": "Not found"})


# ── Server ────────────────────────────────────────────────────────────────────

class _ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def _setup_logging(log_file: Path):
    log_file.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s — %(message)s")

    handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    handler.setFormatter(fmt)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    root.addHandler(console)


def main():
    parser = argparse.ArgumentParser(description="Yeyland Wutani Risk Scanner Web Dashboard")
    parser.add_argument("--config", default=str(CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--port", type=int, default=8080, help="Listening port (default 8080)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    args = parser.parse_args()

    global CONFIG_PATH
    CONFIG_PATH = Path(args.config)

    _setup_logging(LOG_FILE)
    logger.info("Starting Risk Scanner Web Dashboard")

    if not _BCRYPT_AVAILABLE:
        logger.warning("bcrypt not available — using HMAC-SHA256 password fallback")

    server = _ReusableTCPServer((args.host, args.port), DashboardHandler)
    print(f"Dashboard running at http://{args.host}:{args.port}")
    logger.info("Dashboard running at http://%s:%d", args.host, args.port)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Dashboard shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
