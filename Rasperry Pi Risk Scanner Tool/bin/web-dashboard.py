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
CREDS_PATH = BASE_DIR / "config" / "credentials.enc"
LOG_FILE = BASE_DIR / "logs" / "risk-scanner-web.log"
SCANNER_LOG_FILE = BASE_DIR / "logs" / "risk-scanner.log"
HISTORY_DIR = BASE_DIR / "data" / "history"

# ── credential_store import (optional — may not be available before first install) ──
sys.path.insert(0, str(BASE_DIR / "lib"))
try:
    from credential_store import (
        load_credentials, save_credentials, add_credential,
        validate_profile, _mask_sensitive, CRED_TYPES, SCOPE_TYPES,
    )
    _CRED_STORE_AVAILABLE = True
except ImportError:
    _CRED_STORE_AVAILABLE = False

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

_SECRET_MASK = "••••••••"


def _load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _load_config_safe() -> dict:
    """Load config with secret fields replaced by mask for safe transmission to browser."""
    import copy
    cfg = copy.deepcopy(_load_config())
    if cfg.get("graph_api", {}).get("client_secret"):
        cfg.setdefault("graph_api", {})["client_secret"] = _SECRET_MASK
    if cfg.get("hatz_ai", {}).get("api_key"):
        cfg.setdefault("hatz_ai", {})["api_key"] = _SECRET_MASK
    # Mask vault secrets
    for _vf in ("token", "secret_id", "client_secret"):
        if cfg.get("vault", {}).get(_vf):
            cfg.setdefault("vault", {})[_vf] = _SECRET_MASK
    # Flatten networks list to comma string for form field
    networks = cfg.get("scanning", {}).get("networks", [])
    if isinstance(networks, list):
        cfg.setdefault("scanning", {})["networks"] = ", ".join(networks)
    return cfg


def _save_config(body: dict) -> dict:
    """Validate and save config fields from a POST body dict."""
    import re
    VALID_TIME = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')
    VALID_DAYS = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}

    try:
        cfg = _load_config()

        # ── Identity / Reporting ──────────────────────────────────────────────
        rep = cfg.setdefault("reporting", {})
        for field in ("client_name", "site_name", "sender_email", "report_to"):
            if field in body and body[field] is not None:
                rep[field] = str(body[field]).strip()

        # ── Graph API ─────────────────────────────────────────────────────────
        graph = cfg.setdefault("graph_api", {})
        for field in ("tenant_id", "client_id"):
            if field in body and body[field] is not None:
                graph[field] = str(body[field]).strip()
        secret = body.get("client_secret", "")
        if secret and secret != _SECRET_MASK:
            graph["client_secret"] = secret

        # ── Scanning ──────────────────────────────────────────────────────────
        scan = cfg.setdefault("scanning", {})
        if "networks" in body and body["networks"] is not None:
            scan["networks"] = [n.strip() for n in str(body["networks"]).split(",") if n.strip()]

        # ── Schedule ──────────────────────────────────────────────────────────
        sched = cfg.setdefault("schedule", {})
        sched_changed = False
        scan_time   = str(body.get("scan_time",   sched.get("scan_time",   "02:00"))).strip()
        report_time = str(body.get("report_time", sched.get("report_time", "06:00"))).strip()
        report_day  = str(body.get("report_day",  sched.get("report_day",  "Mon"))).strip().capitalize()
        if "scan_time" in body:
            if not VALID_TIME.match(scan_time):
                return {"success": False, "message": f"Invalid scan_time: {scan_time!r} — use HH:MM (24-hour)"}
            if sched.get("scan_time") != scan_time:
                sched["scan_time"] = scan_time
                sched_changed = True
        if "report_time" in body:
            if not VALID_TIME.match(report_time):
                return {"success": False, "message": f"Invalid report_time: {report_time!r} — use HH:MM (24-hour)"}
            if sched.get("report_time") != report_time:
                sched["report_time"] = report_time
                sched_changed = True
        if "report_day" in body:
            if report_day not in VALID_DAYS:
                return {"success": False, "message": f"Invalid report_day: {report_day!r} — use Mon/Tue/Wed/Thu/Fri/Sat/Sun"}
            if sched.get("report_day") != report_day:
                sched["report_day"] = report_day
                sched_changed = True

        # ── Hatz AI ───────────────────────────────────────────────────────────
        hatz = cfg.setdefault("hatz_ai", {})
        if "hatz_enabled" in body:
            hatz["enabled"] = bool(body["hatz_enabled"])
        if "hatz_model" in body and body["hatz_model"] is not None:
            hatz["model"] = str(body["hatz_model"]).strip()
        hatz_key = body.get("hatz_api_key", "")
        if hatz_key and hatz_key != _SECRET_MASK:
            hatz["api_key"] = hatz_key

        # ── Write ─────────────────────────────────────────────────────────────
        # ── Vault / PAM integration ───────────────────────────────────────────────
        if "vault_enabled" in body:
            vault = cfg.setdefault("vault", {})
            en = body.get("vault_enabled")
            vault["enabled"]    = en is True or str(en).lower() == "true"
            vault["provider"]   = str(body.get("vault_provider", "hashicorp")).strip()
            vault["url"]        = str(body.get("vault_url", "")).strip()
            tls = body.get("vault_tls", True)
            vault["tls_verify"] = tls is not False and str(tls).lower() != "false"
            provider = vault["provider"]
            if provider == "hashicorp":
                vault["auth_method"] = str(body.get("vault_auth", "token")).strip()
                vault["mount"]       = str(body.get("vault_mount", "secret")).strip() or "secret"
                vault["kv_version"]  = int(body.get("vault_kv_version", 2))
                vault["paths"]       = [p.strip() for p in str(body.get("vault_paths", "")).split(",") if p.strip()]
                vault["role_id"]     = str(body.get("vault_role_id", "")).strip()
                tok = body.get("vault_token", "")
                if tok and tok != _SECRET_MASK:
                    vault["token"] = tok
                sid = body.get("vault_secret_id", "")
                if sid and sid != _SECRET_MASK:
                    vault["secret_id"] = sid
            elif provider == "cyberark":
                vault["app_id"]    = str(body.get("vault_app_id", "")).strip()
                vault["safe"]      = str(body.get("vault_safe", "")).strip()
                vault["objects"]   = [o.strip() for o in str(body.get("vault_objects", "")).split(",") if o.strip()]
                vault["cert_path"] = str(body.get("vault_cert", "")).strip()
                vault["key_path"]  = str(body.get("vault_key", "")).strip()
            elif provider in ("azure_keyvault", "azure"):
                vault["vault_name"]    = str(body.get("vault_akv_name", "")).strip()
                vault["tenant_id"]     = str(body.get("vault_tenant", "")).strip()
                vault["client_id"]     = str(body.get("vault_client_id", "")).strip()
                vault["secrets"]       = [s.strip() for s in str(body.get("vault_secrets", "")).split(",") if s.strip()]
                asec = body.get("vault_akv_secret", "")
                if asec and asec != _SECRET_MASK:
                    vault["client_secret"] = asec

        # ── SOAR / Ticketing ────────────────────────────────────────────────────
        if "soar_enabled" in body:
            soar = cfg.setdefault("soar", {})
            soar["enabled"]      = body.get("soar_enabled") is True or str(body.get("soar_enabled","")).lower() == "true"
            soar["min_severity"] = str(body.get("soar_min_sev", "HIGH")).upper()
            soar["on_kev_only"]  = body.get("soar_kev_only") is True or str(body.get("soar_kev_only","")).lower() == "true"
            soar["deduplicate"]  = body.get("soar_dedup") is not False and str(body.get("soar_dedup","true")).lower() != "false"
            providers = []
            # Jira
            jira_p = {"type": "jira", "name": "Jira",
                      "enabled":     body.get("jira_enabled") is True or str(body.get("jira_enabled","")).lower() == "true",
                      "url":         str(body.get("jira_url",         "")).strip(),
                      "email":       str(body.get("jira_email",       "")).strip(),
                      "project_key": str(body.get("jira_project",    "")).strip(),
                      "issue_type":  str(body.get("jira_issue_type",  "Bug")).strip()}
            tok = body.get("jira_token", "")
            if tok and tok != _SECRET_MASK: jira_p["api_token"] = tok
            elif cfg.get("soar", {}).get("providers"):
                old_j = next((p for p in cfg["soar"]["providers"] if p.get("type")=="jira"), {})
                if old_j.get("api_token"): jira_p["api_token"] = old_j["api_token"]
            providers.append(jira_p)
            # ServiceNow
            snow_p = {"type": "servicenow", "name": "ServiceNow",
                      "enabled":          body.get("snow_enabled") is True or str(body.get("snow_enabled","")).lower() == "true",
                      "url":              str(body.get("snow_url",   "")).strip(),
                      "username":         str(body.get("snow_user",  "")).strip(),
                      "table":            str(body.get("snow_table", "incident")).strip(),
                      "assignment_group": str(body.get("snow_group", "")).strip()}
            sp = body.get("snow_pass", "")
            if sp and sp != _SECRET_MASK: snow_p["password"] = sp
            elif cfg.get("soar", {}).get("providers"):
                old_s = next((p for p in cfg["soar"]["providers"] if p.get("type")=="servicenow"), {})
                if old_s.get("password"): snow_p["password"] = old_s["password"]
            providers.append(snow_p)
            # Webhook
            wh_p = {"type": "webhook", "name": "Webhook",
                    "enabled":     body.get("wh_enabled") is True or str(body.get("wh_enabled","")).lower() == "true",
                    "url":         str(body.get("wh_url",         "")).strip(),
                    "template":    str(body.get("wh_template",    "slack")).strip(),
                    "routing_key": str(body.get("wh_routing_key", "")).strip()}
            providers.append(wh_p)
            soar["providers"] = providers

        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")

        msg = "Settings saved."
        if sched_changed:
            apply = _run_systemctl("start", "risk-scanner-apply-schedule.service")
            if apply["success"]:
                msg += " Schedule update applied."
            else:
                msg += f" Schedule saved but timer update failed: {apply['message']}"

        return {"success": True, "message": msg}

    except PermissionError:
        return {"success": False, "message": "Permission denied writing config — check ReadWritePaths in risk-scanner-web.service"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _change_password(body: dict) -> dict:
    """Change the dashboard password.  Requires current password verification."""
    current  = body.get("current_password", "")
    new_pw   = body.get("new_password", "")
    confirm  = body.get("confirm_password", "")

    stored = _load_password_hash()
    if not stored:
        return {"success": False, "message": "No password configured on this Pi"}
    if not _verify_password(current, stored):
        return {"success": False, "message": "Current password is incorrect"}
    if not new_pw:
        return {"success": False, "message": "New password cannot be empty"}
    if len(new_pw) < 8:
        return {"success": False, "message": "New password must be at least 8 characters"}
    if new_pw != confirm:
        return {"success": False, "message": "Passwords do not match"}

    new_hash = _hash_password(new_pw)
    try:
        DASHBOARD_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(DASHBOARD_CONFIG_PATH) as f:
                data = json.load(f)
        except Exception:
            data = {}
        data["password_hash"] = new_hash
        with open(DASHBOARD_CONFIG_PATH, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        return {"success": True, "message": "Password changed successfully."}
    except PermissionError:
        return {"success": False, "message": "Permission denied — check ReadWritePaths in risk-scanner-web.service"}
    except Exception as e:
        return {"success": False, "message": str(e)}


# ── Scan summary helper ───────────────────────────────────────────────────────

def _get_last_scan_summary() -> Optional[dict]:
    try:
        import scan_history as _sh
        data = _sh.load_latest_scan()
        if data is None:
            return None

        hosts_raw = data.get("hosts", [])
        hosts = []
        for h in hosts_raw:
            cve_matches = h.get("cve_matches", []) or []
            kev_count   = sum(1 for c in cve_matches if c.get("kev"))

            # Flatten CVE matches to summary dicts the dashboard JS can render
            cve_list = [
                {
                    "cve_id":      c.get("cve_id", ""),
                    "cvss":        c.get("cvss_v3_score") or c.get("cvss_score") or 0,
                    "severity":    c.get("severity", ""),
                    "kev":         bool(c.get("kev")),
                    "description": (c.get("description") or "")[:120],
                }
                for c in cve_matches[:20]
            ]

            # security_flags is a list of {severity, description} dicts
            flags = [
                {
                    "severity":    f.get("severity", ""),
                    "description": f.get("description", ""),
                }
                for f in (h.get("security_flags") or [])
            ]

            # Services: {port, name, product, version}
            services = [
                {
                    "port":    s.get("port", ""),
                    "name":    s.get("name", ""),
                    "product": s.get("product", ""),
                    "version": s.get("version", ""),
                }
                for s in (h.get("services") or [])
            ]

            hosts.append({
                "ip":                   h.get("ip", ""),
                "hostname":             h.get("hostname", ""),
                "mac":                  h.get("mac", ""),
                "vendor":               h.get("vendor", ""),
                "category":             h.get("category", ""),
                "os_guess":             h.get("os_guess") or h.get("os_version", ""),
                "domain":               h.get("domain", ""),
                "manufacturer":         h.get("manufacturer", ""),
                "model":                h.get("model", ""),
                "last_boot":            h.get("last_boot", ""),
                "risk_score":           int(h.get("risk_score") or 0),
                "risk_level":           h.get("risk_level", "LOW"),
                "kev_cves":             kev_count,
                "total_cves":           len(cve_matches),
                "credentialed":         h.get("credential_type", "none") != "none",
                "credential_type":      h.get("credential_type", "none"),
                "credential_attempted": bool(h.get("credential_attempted", False)),
                "credential_error":     h.get("credential_error", ""),
                "auth_ports":           h.get("auth_ports", []),
                "wmi_method":           h.get("wmi_method", ""),
                "open_ports":           len(h.get("open_ports", [])),
                "cve_matches":          cve_list,
                "security_flags":       flags,
                "services":             services,
            })

        hosts.sort(key=lambda x: x["risk_score"], reverse=True)

        # scan-engine stores the score under results["risk"]["score"] and the
        # timestamp under results["scan_start"] — fall back to legacy key names
        # for any older archives that used different conventions.
        _risk = data.get("risk") or {}
        return {
            "hosts":             hosts,
            "env_score":         _risk.get("score") or data.get("env_risk_score", 0),
            "env_level":         _risk.get("level") or data.get("env_risk_level", "LOW"),
            "scan_time":         data.get("scan_start") or data.get("scan_time", ""),
            "total_cves":        sum(h["total_cves"] for h in hosts),
            "delta":             data.get("_delta") or data.get("delta", {}),
            "credentialed_count":sum(1 for h in hosts if h["credentialed"]),
            "kev_cve_count":     sum(h["kev_cves"] for h in hosts),
            "critical_hosts":    sum(1 for h in hosts if h["risk_level"] == "CRITICAL"),
            "high_hosts":        sum(1 for h in hosts if h["risk_level"] == "HIGH"),
            "ai_insights":       data.get("ai_insights") or "",
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


# ── Credential helpers ────────────────────────────────────────────────────────

def _list_credentials() -> list:
    """Return masked credential profiles, or [] if unavailable."""
    if not _CRED_STORE_AVAILABLE:
        return []
    try:
        profiles = load_credentials(CREDS_PATH)
        return [_mask_sensitive(p) for p in profiles]
    except Exception as e:
        logger.warning("Could not load credentials: %s", e)
        return []


def _save_credential(profile: dict) -> dict:
    """Validate and upsert a single credential profile."""
    if not _CRED_STORE_AVAILABLE:
        return {"success": False, "message": "credential_store library not available"}
    errors = validate_profile(profile)
    if errors:
        return {"success": False, "message": "; ".join(errors)}
    try:
        add_credential(profile, CREDS_PATH)
        return {"success": True, "message": f"Profile '{profile.get('profile_name')}' saved."}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _delete_credential(profile_name: str) -> dict:
    """Remove a credential profile by name."""
    if not _CRED_STORE_AVAILABLE:
        return {"success": False, "message": "credential_store library not available"}
    try:
        profiles = load_credentials(CREDS_PATH)
        new_profiles = [p for p in profiles if p.get("profile_name") != profile_name]
        if len(new_profiles) == len(profiles):
            return {"success": False, "message": f"Profile '{profile_name}' not found"}
        save_credentials(new_profiles, CREDS_PATH)
        return {"success": True, "message": f"Profile '{profile_name}' deleted."}
    except Exception as e:
        return {"success": False, "message": str(e)}


# ── HTML pages ────────────────────────────────────────────────────────────────


# ── Policies persistence ─────────────────────────────────────────────────────

def _policies_path() -> str:
    import os
    return os.path.join(BASE_DIR, 'config', 'scan_policies.json')




# ── Plugin registry helper ────────────────────────────────────────────────

def _get_plugin_registry_safe() -> list:
    """Load plugin registry, return empty list on error."""
    try:
        import sys
        from pathlib import Path
        lib_dir = str(Path(__file__).parent.parent / "lib")
        if lib_dir not in sys.path:
            sys.path.insert(0, lib_dir)
        from plugin_loader import get_plugin_registry
        plugin_dir = str(Path(__file__).parent.parent / "plugins")
        return get_plugin_registry(plugin_dir)
    except Exception as exc:
        return [{"error": str(exc)}]


def _plugins_content() -> str:
    return """
<div class="card">
  <div class="card-title">Installed Scan Plugins
    <span id="plugin-count" style="float:right;font-size:12px;color:#888;font-weight:400">Loading...</span>
  </div>
  <p style="color:#888;font-size:13px;margin-bottom:14px">
    Plugins are auto-discovered from the <code>plugins/</code> directory at scan time.
    Each plugin maps to a scan category that can be enabled or disabled per
    <a href="/dashboard?view=policies" style="color:#e67e22">Scan Policy</a>.
  </p>
  <div style="overflow-x:auto">
  <table class="cred-table" id="plugin-table">
    <thead>
      <tr>
        <th>Phase</th><th>Plugin Name</th><th>ID</th><th>Category</th>
        <th>Description</th><th>Version</th><th>Requires</th>
      </tr>
    </thead>
    <tbody id="plugin-tbody">
      <tr><td colspan="7" style="text-align:center;color:#888;padding:20px">Loading&#8230;</td></tr>
    </tbody>
  </table>
  </div>
</div>

<div class="card">
  <div class="card-title">Compliance Check Files</div>
  <p style="color:#888;font-size:13px;margin-bottom:14px">
    Compliance checks are defined as YAML files in <code>config/compliance_checks/</code>.
    Add your own <code>*.yaml</code> file to extend the audit coverage.
  </p>
  <div id="compliance-files" style="color:#888;font-size:13px">Loading...</div>
</div>
"""

def _list_policies() -> list:
    import json, os
    p = _policies_path()
    if not os.path.exists(p):
        return []
    try:
        with open(p, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_policy(body: dict) -> dict:
    import json, os
    name = (body.get('name') or '').strip()
    if not name:
        return {'success': False, 'message': 'Policy name is required.'}
    edit_name = (body.get('edit_name') or '').strip() or None
    policies = _list_policies()
    # Prevent duplicate names (unless editing the same entry)
    existing_names = {p['name'] for p in policies}
    if name in existing_names and name != edit_name:
        return {'success': False, 'message': f'A policy named "{name}" already exists.'}
    # Remove old entry when renaming
    if edit_name:
        policies = [p for p in policies if p['name'] != edit_name]
    # Also remove if same name (update)
    policies = [p for p in policies if p['name'] != name]
    policy = {
        'name':             name,
        'scan_type':        body.get('scan_type',        'credentialed'),
        'intensity':        body.get('intensity',        'normal'),
        'networks':         body.get('networks',         ''),
        'modules':          body.get('modules',          []),
        'max_parallel':     int(body.get('max_parallel',     10)),
        'port_range':       body.get('port_range',       'top1000'),
        'timeout_per_host': int(body.get('timeout_per_host', 120)),
        'notes':            body.get('notes',            ''),
    }
    policies.append(policy)
    p = _policies_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(policies, f, indent=2)
    return {'success': True, 'message': f'Policy "{name}" saved.'}


def _delete_policy(name: str) -> dict:
    import json, os
    if not name:
        return {'success': False, 'message': 'name required'}
    policies = _list_policies()
    new_list = [p for p in policies if p['name'] != name]
    if len(new_list) == len(policies):
        return {'success': False, 'message': f'Policy "{name}" not found.'}
    p = _policies_path()
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(new_list, f, indent=2)
    return {'success': True, 'message': f'Policy "{name}" deleted.'}


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

/* Form inputs */
.form-group { margin-bottom: 14px; }
.form-group label { display: block; font-size: 12px; font-weight: 600;
                     text-transform: uppercase; letter-spacing: 0.6px;
                     color: #888; margin-bottom: 5px; }
.form-group input[type=text], .form-group input[type=password],
.form-group select {
    width: 100%; padding: 9px 12px; border: 1px solid #DDD; border-radius: 6px;
    font-size: 14px; outline: none; transition: border-color 0.2s;
    background: #FAFAFA; }
.form-group input:focus, .form-group select:focus { border-color: #FF6600; background:#FFF; }
.form-row { display: flex; gap: 16px; }
.form-row .form-group { flex: 1; }
.cred-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.cred-table th { text-align: left; padding: 8px 12px; background: #F0F0F0;
                  font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px;
                  color: #666; border-bottom: 1px solid #DDD; }
.cred-table td { padding: 9px 12px; border-bottom: 1px solid #F0F0F0; vertical-align: middle; }
.cred-table tr:last-child td { border-bottom: none; }
.cred-table tr:hover td { background: #FAFAFA; }
.btn-sm { padding: 5px 12px; font-size: 12px; border: none; border-radius: 4px;
          font-weight: 600; cursor: pointer; transition: opacity 0.15s; }
.btn-sm:hover { opacity: 0.8; }
.btn-sm-red { background: #FDECEA; color: #C0392B; }
.btn-sm-blue { background: #EBF5FB; color: #1A5276; }

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
    <a class="nav-item {cls_creds}" href="/dashboard?view=credentials">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M10 1a4 4 0 0 1 4 4c0 1.5-.83 2.8-2.05 3.49L12 13H9l-.5-1H8l-.5 1H4l.05-4.51A4 4 0 1 1 10 1zm0 2a2 2 0 1 0 0 4 2 2 0 0 0 0-4z"/>
      </svg><span>Credentials</span>
    </a>
    <a class="nav-item {cls_plugins}" href="/dashboard?view=plugins">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M6 1H1v4h1V2h3V1zM1 10H0V1h1v9zm14-9h-5v1h4v3h1V1zm0 9V1h1v9h-1zM6 14H2v-3H1v4h5v-1zm4 0v1h5v-4h-1v3h-4zM6 4H2v8h8V4H6zm7 4v1H9V4h1V3H6V2h1V1H6v1H5v1H4V2H3v1H2V2H1v1h1v1H1v1h1V4h1v1H2v6h8V4H9V3H8V2H7v1H6V2H7V1h2v1h1v1h1V2h1v1h1V2h1v1zm-2 6H3V5h8v5z"/>
      </svg><span>Plugins</span>
    </a>
    <a class="nav-item {cls_policies}" href="/dashboard?view=policies">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
        <path d="M14 2H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM6 3h8a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z"/>
      </svg><span>Policies</span>
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
    cls = {"main": "", "detail": "", "logs": "", "creds": "", "settings": "", "policies": "", "plugins": ""}
    if view == "detail":
        cls["detail"] = "active"
    elif view == "logs":
        cls["logs"] = "active"
    elif view == "credentials":
        cls["creds"] = "active"
    elif view == "settings":
        cls["settings"] = "active"
    elif view == "policies":
        cls["policies"] = "active"
    elif view == "plugins":
        cls["plugins"] = "active"
    else:
        cls["main"] = "active"

    sidebar = _SIDEBAR_HTML.format(
        cls_dashboard=cls["main"],
        cls_detail=cls["detail"],
        cls_logs=cls["logs"],
        cls_creds=cls["creds"],
        cls_settings=cls["settings"],
        cls_policies=cls["policies"],
        cls_plugins=cls["plugins"],
    )

    if view == "detail":
        content = _detail_content()
    elif view == "logs":
        content = _logs_content()
    elif view == "credentials":
        content = _credentials_content()
    elif view == "settings":
        content = _settings_content()
    elif view == "policies":
        content = _policies_content()
    elif view == "plugins":
        content = _plugins_content()
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
function escHtml(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function cvssClass(score) {
    if (score >= 9) return 'badge-critical';
    if (score >= 7) return 'badge-high';
    if (score >= 4) return 'badge-medium';
    return 'badge-low';
}
function flagClass(sev) {
    const s = (sev||'').toUpperCase();
    if (s === 'CRITICAL') return 'badge-critical';
    if (s === 'HIGH')     return 'badge-high';
    if (s === 'MEDIUM')   return 'badge-medium';
    return 'badge-low';
}

async function loadDetail() {
    const tbody = document.getElementById('host-tbody');
    if (!tbody) return;
    try {
        const r = await fetch('/api/scan-detail');
        if (!r.ok) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:#888;padding:24px">No scan data available yet — run a scan first.</td></tr>';
            return;
        }
        const d = await r.json();

        // AI insights card
        if (d.ai_insights) {
            const card = document.getElementById('ai-insights-card');
            const body = document.getElementById('ai-insights-body');
            if (card && body) { body.textContent = d.ai_insights; card.style.display = ''; }
        }

        const hosts = d.hosts || [];
        if (!hosts.length) {
            tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:#888;padding:24px">No hosts found in last scan.</td></tr>';
            return;
        }
        tbody.innerHTML = '';

        hosts.forEach((h) => {
            const rc  = rowClass(h.risk_level);
            const bc  = badgeClass(h.risk_level);
            const sc  = riskClass(h.risk_level);
            const cred = h.credentialed
                ? '<span class="badge badge-ok">YES</span>'
                : '<span class="badge badge-warn">NO</span>';
            const kevBadge = h.kev_cves > 0
                ? `<span class="badge badge-critical">${h.kev_cves} KEV</span>`
                : '<span style="color:#AAA">—</span>';
            const hn   = escHtml(h.hostname || h.vendor || '');
            const cat  = escHtml(h.category || '');
            const os   = escHtml(h.os_guess || '');

            const tr = document.createElement('tr');
            tr.className = rc + ' expandable';
            tr.innerHTML = `
                <td><strong>${escHtml(h.ip||'')}</strong></td>
                <td>${hn}</td>
                <td><span style="color:#888;font-size:11px">${cat}</span>${cat&&os?' · ':''}${os}</td>
                <td><span class="${sc}" style="font-weight:700;font-size:18px">${h.risk_score||0}</span></td>
                <td><span class="badge ${bc}">${h.risk_level||''}</span></td>
                <td style="font-weight:600">${h.total_cves||0}</td>
                <td>${kevBadge}</td>
                <td>${cred}</td>
                <td>${h.open_ports||0}</td>
            `;
            tbody.appendChild(tr);

            // ── Expand row ────────────────────────────────────────────────────
            // Services
            const svcRows = (h.services||[]).map(s =>
                `<tr><td style="font-weight:600;color:#333">${escHtml(String(s.port))}</td>
                     <td>${escHtml(s.name||'')}</td>
                     <td>${escHtml((s.product||'') + (s.version ? ' ' + s.version : ''))}</td></tr>`
            ).join('') || '<tr><td colspan="3" style="color:#AAA">No open ports detected</td></tr>';

            // CVEs
            const cveRows = (h.cve_matches||[]).map(c => {
                const kev = c.kev ? '<span class="badge badge-critical" style="margin-right:4px">KEV</span>' : '';
                const cvssScore = parseFloat(c.cvss||0).toFixed(1);
                return `<tr>
                    <td style="white-space:nowrap">${kev}<strong>${escHtml(c.cve_id||'')}</strong></td>
                    <td><span class="badge ${cvssClass(c.cvss)}">${escHtml(c.severity||'')}</span></td>
                    <td style="font-weight:600">${cvssScore}</td>
                    <td style="font-size:12px;color:#555">${escHtml(c.description||'')}</td>
                </tr>`;
            }).join('') || '<tr><td colspan="4" style="color:#AAA">No CVEs detected</td></tr>';

            // Security flags
            const flagRows = (h.security_flags||[]).map(f =>
                `<tr><td><span class="badge ${flagClass(f.severity)}">${escHtml(f.severity||'')}</span></td>
                     <td style="font-size:12px">${escHtml(f.description||'')}</td></tr>`
            ).join('') || '<tr><td colspan="2" style="color:#AAA">None</td></tr>';

            // ── Auth status panel ─────────────────────────────────────────────
            const credType  = h.credential_type  || 'none';
            const attempted = h.credential_attempted;
            const credErr   = h.credential_error  || '';
            const wmiMethod = h.wmi_method        || '';
            const authPorts = h.auth_ports        || [];

            let authStatusHtml = '';
            if (credType !== 'none') {
                const methodTag = wmiMethod ? ` <span style="font-size:10px;opacity:.8">(${escHtml(wmiMethod)})</span>` : '';
                authStatusHtml = `<span class="badge badge-ok">&#10003; ${escHtml(credType.toUpperCase())} authenticated${methodTag}</span>`;
            } else if (attempted) {
                authStatusHtml = `<span class="badge badge-err">&#10007; Auth failed</span>`
                    + (credErr ? `<span style="font-size:11px;color:#C0392B;margin-left:6px">${escHtml(credErr)}</span>` : '');
            } else if (authPorts.length) {
                authStatusHtml = `<span class="badge badge-warn">No credential configured</span>`;
            } else {
                authStatusHtml = `<span style="color:#AAA;font-size:12px">No auth-capable ports detected</span>`;
            }

            const authPortsHtml = authPorts.length
                ? authPorts.map(p => `<span class="badge badge-blue" style="margin-right:4px">${escHtml(String(p.port))}/${escHtml(p.label||'')}</span>`).join('')
                : '<span style="color:#AAA;font-size:12px">—</span>';

            // Quick "Add Credential" button — shown when auth-capable ports exist but no cred configured
            let quickCredBtn = '';
            if (authPorts.length && credType === 'none') {
                const suggestType = authPorts.some(p => p.port === 22) ? 'ssh' : 'wmi';
                const encIp   = encodeURIComponent(h.ip || '');
                const encType = encodeURIComponent(suggestType);
                quickCredBtn = `<a href="/dashboard?view=credentials&add=1&ip=${encIp}&type=${encType}"
                    class="btn-sm btn-sm-blue" style="text-decoration:none;display:inline-block;margin-left:10px">
                    + Add Credential for this host</a>`;
            }

            // ── Identity info panel ───────────────────────────────────────────
            const identParts = [];
            if (h.mac)          identParts.push(`<span><b>MAC</b> ${escHtml(h.mac)}</span>`);
            if (h.hostname)     identParts.push(`<span><b>Hostname</b> ${escHtml(h.hostname)}</span>`);
            if (h.domain)       identParts.push(`<span><b>Domain</b> ${escHtml(h.domain)}</span>`);
            if (h.os_guess)     identParts.push(`<span><b>OS</b> ${escHtml(h.os_guess)}</span>`);
            if (h.manufacturer) identParts.push(`<span><b>Make</b> ${escHtml(h.manufacturer)}</span>`);
            if (h.model)        identParts.push(`<span><b>Model</b> ${escHtml(h.model)}</span>`);
            if (h.last_boot)    identParts.push(`<span><b>Last Boot</b> ${escHtml(h.last_boot)}</span>`);
            if (h.vendor)       identParts.push(`<span><b>NIC Vendor</b> ${escHtml(h.vendor)}</span>`);
            const identHtml = identParts.length
                ? identParts.join('<span style="color:#CCC;margin:0 4px">|</span>')
                : '<span style="color:#AAA;font-size:12px">No identity data available</span>';

            const expTr = document.createElement('tr');
            expTr.className = 'expand-row';
            expTr.innerHTML = `<td colspan="9"><div class="expand-content">

                <div style="background:#F9F9F9;border-radius:6px;padding:8px 14px;margin-bottom:10px;font-size:12px;color:#444;flex-wrap:wrap;display:flex;gap:6px;align-items:center">
                  ${identHtml}
                </div>

                <div style="background:#F0F4FF;border-radius:6px;padding:10px 14px;margin-bottom:12px;display:flex;align-items:center;flex-wrap:wrap;gap:16px">
                  <div>
                    <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#888">Auth Status&nbsp;&nbsp;</span>
                    ${authStatusHtml}${quickCredBtn}
                  </div>
                  <div>
                    <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;color:#888">Auth-Capable Ports&nbsp;&nbsp;</span>
                    ${authPortsHtml}
                  </div>
                </div>

                <div style="display:flex;gap:24px;flex-wrap:wrap">
                  <div style="flex:1;min-width:220px">
                    <div style="font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#888;margin-bottom:6px">Services</div>
                    <table style="width:100%;font-size:12px;border-collapse:collapse">
                      <thead><tr>
                        <th style="text-align:left;color:#888;padding:2px 8px 4px 0">Port</th>
                        <th style="text-align:left;color:#888;padding:2px 8px 4px 0">Service</th>
                        <th style="text-align:left;color:#888;padding:2px 0 4px 0">Product / Version</th>
                      </tr></thead>
                      <tbody>${svcRows}</tbody>
                    </table>
                  </div>
                  <div style="flex:1;min-width:220px">
                    <div style="font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#888;margin-bottom:6px">Security Findings</div>
                    <table style="width:100%;font-size:12px;border-collapse:collapse">
                      <tbody>${flagRows}</tbody>
                    </table>
                  </div>
                </div>
                <div style="margin-top:14px">
                  <div style="font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#888;margin-bottom:6px">
                    CVEs (${(h.cve_matches||[]).length} shown${h.total_cves > (h.cve_matches||[]).length ? ' of ' + h.total_cves : ''})
                  </div>
                  <table style="width:100%;font-size:12px;border-collapse:collapse">
                    <thead><tr>
                      <th style="text-align:left;color:#888;padding:2px 8px 4px 0;white-space:nowrap">CVE ID</th>
                      <th style="text-align:left;color:#888;padding:2px 8px 4px 0">Severity</th>
                      <th style="text-align:left;color:#888;padding:2px 8px 4px 0">CVSS</th>
                      <th style="text-align:left;color:#888;padding:2px 0 4px 0">Description</th>
                    </tr></thead>
                    <tbody>${cveRows}</tbody>
                  </table>
                </div>
            </div></td>`;
            tbody.appendChild(expTr);
        });

        initExpandRows();
    } catch(e) {
        const tbody = document.getElementById('host-tbody');
        if (tbody) tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:#C0392B;padding:24px">Error loading scan detail: ${escHtml(e.message)}</td></tr>`;
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
    elif view == "credentials":
        return r"""
async function loadCredentials() {
    const tbody = document.getElementById('cred-tbody');
    try {
        const r = await fetch('/api/credentials');
        if (!r.ok) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#C0392B">Failed to load credentials</td></tr>'; return; }
        const d = await r.json();
        const profiles = d.profiles || [];
        if (!profiles.length) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#888;padding:20px">No credential profiles configured. Click <strong>+ Add Profile</strong> to add one.</td></tr>';
            return;
        }
        tbody.innerHTML = '';
        profiles.forEach(p => {
            const targets = (p.targets || []).join(', ') || '—';
            const username = p.username || '—';
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${esc(p.profile_name||'')}</strong></td>
                <td><span class="badge badge-blue">${esc(p.type||'')}</span></td>
                <td>${esc(p.scope||'')}</td>
                <td style="font-size:12px;color:#666">${esc(targets)}</td>
                <td>${esc(username)}</td>
                <td>
                  <button class="btn-sm btn-sm-blue" onclick='editCred(${JSON.stringify(p)})'>Edit</button>
                  &nbsp;
                  <button class="btn-sm btn-sm-red" onclick="deleteCred('${esc(p.profile_name||'')}')">Delete</button>
                </td>`;
            tbody.appendChild(tr);
        });
    } catch(e) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:#C0392B">Error: ${e.message}</td></tr>`;
    }
}

function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showCredForm() {
    document.getElementById('cred-form-card').style.display = '';
    document.getElementById('cred-form-title').textContent = 'Add Credential Profile';
    document.getElementById('cred-form').reset();
    onTypeChange();
    onScopeChange();
    window.scrollTo(0, document.getElementById('cred-form-card').offsetTop - 20);
}

function hideCredForm() {
    document.getElementById('cred-form-card').style.display = 'none';
}

function editCred(p) {
    showCredForm();
    document.getElementById('cred-form-title').textContent = 'Edit Credential Profile';
    document.getElementById('f-name').value = p.profile_name || '';
    document.getElementById('f-type').value = p.type || 'ssh';
    document.getElementById('f-scope').value = p.scope || 'global';
    document.getElementById('f-targets').value = (p.targets||[]).join(', ');
    onTypeChange();
    onScopeChange();
    if (p.type === 'ssh' || p.type === 'wmi') {
        document.getElementById('f-username').value = p.username || '';
        if (p.type === 'ssh') document.getElementById('f-sshkey').value = p.ssh_key_path || '';
    } else if (p.type === 'snmp_v3') {
        document.getElementById('f-snmpuser').value = p.username || '';
    }
    // Passwords/keys are never pre-filled — user must re-enter to change
}

function onTypeChange() {
    const t = document.getElementById('f-type').value;
    const ssh  = t === 'ssh';
    const wmi  = t === 'wmi';
    const v2c  = t === 'snmp_v2c';
    const v3   = t === 'snmp_v3';
    document.getElementById('fg-userpass').style.display    = (ssh||wmi) ? '' : 'none';
    document.getElementById('fg-sshkey').style.display      = ssh ? '' : 'none';
    document.getElementById('fg-community').style.display   = v2c ? '' : 'none';
    document.getElementById('fg-snmpv3').style.display      = v3  ? '' : 'none';
}

function onScopeChange() {
    const s = document.getElementById('f-scope').value;
    document.getElementById('fg-targets').style.display = (s === 'global') ? 'none' : '';
}

async function submitCredForm(e) {
    e.preventDefault();
    const btn  = document.getElementById('btn-cred-save');
    const spin = document.getElementById('spin-cred');
    btn.disabled = true;
    spin.style.display = 'inline-block';

    const type  = document.getElementById('f-type').value;
    const scope = document.getElementById('f-scope').value;
    const targRaw = document.getElementById('f-targets').value.trim();

    const profile = {
        profile_name: document.getElementById('f-name').value.trim(),
        type: type,
        scope: scope,
    };
    if (scope !== 'global' && targRaw) {
        profile.targets = targRaw.split(',').map(s => s.trim()).filter(Boolean);
    }
    if (type === 'ssh' || type === 'wmi') {
        profile.username = document.getElementById('f-username').value.trim();
        const pw = document.getElementById('f-password').value;
        if (pw) profile.password = pw;
        if (type === 'ssh') {
            const sk = document.getElementById('f-sshkey').value.trim();
            if (sk) profile.ssh_key_path = sk;
        }
    } else if (type === 'snmp_v2c') {
        const comm = document.getElementById('f-community').value;
        if (comm) profile.snmp_community = comm;
    } else if (type === 'snmp_v3') {
        profile.username = document.getElementById('f-snmpuser').value.trim();
        const ak = document.getElementById('f-authkey').value;
        const pk = document.getElementById('f-privkey').value;
        if (ak) profile.snmp_auth_key = ak;
        if (pk) profile.snmp_priv_key = pk;
    }

    try {
        const r = await fetch('/api/credentials/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(profile),
        });
        const d = await r.json();
        if (d.success) {
            showToast(d.message, 'success');
            hideCredForm();
            loadCredentials();
        } else {
            showToast(d.message || 'Save failed', 'error');
        }
    } catch(err) {
        showToast('Request failed: ' + err.message, 'error');
    } finally {
        btn.disabled = false;
        spin.style.display = 'none';
    }
}

async function deleteCred(name) {
    if (!confirm(`Delete credential profile "${name}"?`)) return;
    try {
        const r = await fetch('/api/credentials/delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({profile_name: name}),
        });
        const d = await r.json();
        if (d.success) {
            showToast(d.message, 'success');
            loadCredentials();
        } else {
            showToast(d.message || 'Delete failed', 'error');
        }
    } catch(err) {
        showToast('Request failed: ' + err.message, 'error');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    loadCredentials();
    onTypeChange();
    onScopeChange();

    // Pre-fill add form from URL params when arriving via host detail quick-add button
    const params = new URLSearchParams(window.location.search);
    if (params.get('add') === '1') {
        showCredForm();
        const ip   = params.get('ip')   || '';
        const type = params.get('type') || 'wmi';
        const typeEl = document.getElementById('f-type');
        if (typeEl && type) { typeEl.value = type; onTypeChange(); }
        if (ip) {
            const scopeEl = document.getElementById('f-scope');
            if (scopeEl) { scopeEl.value = 'host'; onScopeChange(); }
            const targEl = document.getElementById('f-targets');
            if (targEl) targEl.value = ip;
            const nameEl = document.getElementById('f-name');
            if (nameEl) nameEl.value = type + '-' + ip.replace(/\./g, '-');
        }
    }
});
"""
    elif view == "settings":
        return r"""
async function loadSettings() {
    try {
        const r = await fetch('/api/config');
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const cfg = await r.json();

        const g = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
        const sel = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };

        // Identity / Reporting
        g('s-client-name',   (cfg.reporting  || {}).client_name   || '');
        g('s-site-name',     (cfg.reporting  || {}).site_name     || '');
        g('s-sender-email',  (cfg.reporting  || {}).sender_email  || '');
        g('s-report-to',     (cfg.reporting  || {}).report_to     || '');

        // Graph API
        g('s-tenant-id',     (cfg.graph_api  || {}).tenant_id     || '');
        g('s-client-id',     (cfg.graph_api  || {}).client_id     || '');
        g('s-client-secret', (cfg.graph_api  || {}).client_secret || '');

        // Scanning
        g('s-networks',      (cfg.scanning   || {}).networks      || '');

        // Schedule
        g('s-scan-time',     (cfg.schedule   || {}).scan_time     || '02:00');
        g('s-report-time',   (cfg.schedule   || {}).report_time   || '06:00');
        sel('s-report-day',  (cfg.schedule   || {}).report_day    || 'Mon');

        // Hatz AI
        sel('s-hatz-enabled', String((cfg.hatz_ai || {}).enabled !== false));
        g('s-hatz-model',    (cfg.hatz_ai    || {}).model         || '');
        g('s-hatz-api-key',  (cfg.hatz_ai    || {}).api_key       || '');

        // Vault settings
        const v = cfg.vault || {};
        sel('s-vault-enabled',  String(v.enabled === true));
        sel('s-vault-provider', v.provider     || 'hashicorp');
        g('s-vault-url',        v.url          || '');
        sel('s-vault-tls',      String(v.tls_verify !== false));
        sel('s-vault-auth',     v.auth_method  || 'token');
        g('s-vault-mount',      v.mount        || 'secret');
        sel('s-vault-kv-version', String(v.kv_version || 2));
        g('s-vault-paths',      (v.paths       || []).join(', '));
        g('s-vault-role-id',    v.role_id      || '');
        g('s-vault-app-id',     v.app_id       || '');
        g('s-vault-safe',       v.safe         || '');
        g('s-vault-objects',    (v.objects     || []).join(', '));
        g('s-vault-cert',       v.cert_path    || '');
        g('s-vault-key',        v.key_path     || '');
        g('s-vault-akv-name',   v.vault_name   || '');
        g('s-vault-akv-tenant', v.tenant_id    || '');
        g('s-vault-akv-client-id', v.client_id || '');
        g('s-vault-akv-secrets',(v.secrets     || []).join(', '));
        onVaultProviderChange();

        // SOAR settings
        const soar = cfg.soar || {};
        sel('s-soar-enabled',  String(soar.enabled === true));
        sel('s-soar-min-sev',  soar.min_severity  || 'HIGH');
        sel('s-soar-kev-only', String(soar.on_kev_only === true));
        sel('s-soar-dedup',    String(soar.deduplicate !== false));
        const providers = soar.providers || [];
        const jira = providers.find(p => p.type === 'jira')        || {};
        const snow = providers.find(p => p.type === 'servicenow')  || {};
        const wh   = providers.find(p => p.type === 'webhook')     || {};
        sel('s-jira-enabled', String(jira.enabled === true));
        g('s-jira-url',       jira.url          || '');
        g('s-jira-email',     jira.email         || '');
        g('s-jira-project',   jira.project_key   || '');
        g('s-jira-issue-type',jira.issue_type     || 'Bug');
        sel('s-snow-enabled', String(snow.enabled === true));
        g('s-snow-url',       snow.url      || '');
        g('s-snow-user',      snow.username  || '');
        g('s-snow-table',     snow.table     || 'incident');
        g('s-snow-group',     snow.assignment_group || '');
        sel('s-wh-enabled',   String(wh.enabled === true));
        g('s-wh-url',         wh.url          || '');
        sel('s-wh-template',  wh.template     || 'slack');
        g('s-wh-routing-key', wh.routing_key  || '');

        document.getElementById('settings-loading').style.display = 'none';
        document.getElementById('settings-form').style.display = '';
    } catch(e) {
        document.getElementById('settings-loading').textContent = 'Failed to load settings: ' + e.message;
    }
}

async function saveSettings() {
    const btn  = document.getElementById('btn-save-settings');
    const spin = document.getElementById('spin-save');
    btn.disabled = true; spin.style.display = '';
    const g = id => document.getElementById(id)?.value || '';
    const body = {
        client_name:    g('s-client-name'),
        site_name:      g('s-site-name'),
        sender_email:   g('s-sender-email'),
        report_to:      g('s-report-to'),
        tenant_id:      g('s-tenant-id'),
        client_id:      g('s-client-id'),
        client_secret:  g('s-client-secret'),
        networks:       g('s-networks'),
        scan_time:      g('s-scan-time'),
        report_day:     g('s-report-day'),
        report_time:    g('s-report-time'),
        hatz_enabled:   document.getElementById('s-hatz-enabled')?.value === 'true',
        hatz_model:     g('s-hatz-model'),
        hatz_api_key:   g('s-hatz-api-key'),
        // Vault
        vault_enabled:  document.getElementById('s-vault-enabled')?.value === 'true',
        vault_provider: g('s-vault-provider'),
        vault_url:      g('s-vault-url'),
        vault_tls:      document.getElementById('s-vault-tls')?.value !== 'false',
        vault_auth:     g('s-vault-auth'),
        vault_token:    g('s-vault-token'),
        vault_role_id:  g('s-vault-role-id'),
        vault_secret_id: g('s-vault-secret-id'),
        vault_mount:    g('s-vault-mount'),
        vault_kv_version: parseInt(g('s-vault-kv-version')) || 2,
        vault_paths:    g('s-vault-paths'),
        vault_app_id:   g('s-vault-app-id'),
        vault_safe:     g('s-vault-safe'),
        vault_objects:  g('s-vault-objects'),
        vault_cert:     g('s-vault-cert'),
        vault_key:      g('s-vault-key'),
        vault_akv_name: g('s-vault-akv-name'),
        vault_tenant:   g('s-vault-akv-tenant'),
        vault_client_id: g('s-vault-akv-client-id'),
        vault_akv_secret: g('s-vault-akv-secret'),
        vault_secrets:  g('s-vault-akv-secrets'),
        // SOAR
        soar_enabled:    document.getElementById('s-soar-enabled')?.value === 'true',
        soar_min_sev:    g('s-soar-min-sev'),
        soar_kev_only:   document.getElementById('s-soar-kev-only')?.value === 'true',
        soar_dedup:      document.getElementById('s-soar-dedup')?.value !== 'false',
        jira_enabled:    document.getElementById('s-jira-enabled')?.value === 'true',
        jira_url:        g('s-jira-url'),
        jira_email:      g('s-jira-email'),
        jira_token:      g('s-jira-token'),
        jira_project:    g('s-jira-project'),
        jira_issue_type: g('s-jira-issue-type'),
        snow_enabled:    document.getElementById('s-snow-enabled')?.value === 'true',
        snow_url:        g('s-snow-url'),
        snow_user:       g('s-snow-user'),
        snow_pass:       g('s-snow-pass'),
        snow_table:      g('s-snow-table'),
        snow_group:      g('s-snow-group'),
        wh_enabled:      document.getElementById('s-wh-enabled')?.value === 'true',
        wh_url:          g('s-wh-url'),
        wh_template:     g('s-wh-template'),
        wh_routing_key:  g('s-wh-routing-key'),
    };
    try {
        const r = await fetch('/api/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body)
        });
        const d = await r.json();
        showToast(d.message, d.success ? 'success' : 'error');
        if (d.success) {
            // Re-mask secrets so stale values aren't left in the form
            loadSettings();
        }
    } catch(e) {
        showToast('Error saving settings: ' + e.message, 'error');
    } finally {
        btn.disabled = false; spin.style.display = 'none';
    }
}

async function changePassword() {
    const btn  = document.getElementById('btn-change-pw');
    const spin = document.getElementById('spin-pw');
    btn.disabled = true; spin.style.display = '';
    const body = {
        current_password:  document.getElementById('s-pw-current')?.value  || '',
        new_password:      document.getElementById('s-pw-new')?.value      || '',
        confirm_password:  document.getElementById('s-pw-confirm')?.value  || '',
    };
    try {
        const r = await fetch('/api/password', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body)
        });
        const d = await r.json();
        showToast(d.message, d.success ? 'success' : 'error');
        if (d.success) {
            document.getElementById('s-pw-current').value = '';
            document.getElementById('s-pw-new').value     = '';
            document.getElementById('s-pw-confirm').value = '';
        }
    } catch(e) {
        showToast('Error: ' + e.message, 'error');
    } finally {
        btn.disabled = false; spin.style.display = 'none';
    }
}

async function clearHistory() {
    if (!confirm('Delete ALL scan history and archive files? This cannot be undone.')) return;
    const btn  = document.getElementById('btn-clear-history');
    const spin = document.getElementById('spin-clear');
    btn.disabled = true; spin.style.display = '';
    try {
        const r = await fetch('/api/history/clear', { method: 'POST',
            headers: {'Content-Type': 'application/json'}, body: '{}' });
        const d = await r.json();
        showToast(d.message, d.success ? 'success' : 'error');
    } catch(e) {
        showToast('Error: ' + e.message, 'error');
    } finally {
        btn.disabled = false; spin.style.display = 'none';
    }
}

document.addEventListener('DOMContentLoaded', loadSettings);
"""
    elif view == "plugins":
        return r"""
async function loadPlugins() {
    const tbody = document.getElementById('plugin-tbody');
    const count = document.getElementById('plugin-count');
    if (!tbody) return;
    try {
        const r = await fetch('/api/plugins');
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const d = await r.json();
        const plugins = d.plugins || [];
        count.textContent = plugins.length + ' plugin(s) installed';
        if (!plugins.length) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#888;padding:20px">No plugins found in plugins/ directory.</td></tr>';
            return;
        }
        const catColors = {
            discovery:  '#3498db',
            ssh:        '#27ae60',
            wmi:        '#8e44ad',
            snmp:       '#16a085',
            cve:        '#e74c3c',
            compliance: '#e67e22',
            web:        '#2980b9',
            bruteforce: '#c0392b',
            risk:       '#d35400',
            delta:      '#7f8c8d',
            reporting:  '#2ecc71',
        };
        tbody.innerHTML = '';
        plugins.forEach(p => {
            if (p.error) {
                tbody.innerHTML += `<tr><td colspan="7" style="color:#c00">${p.error}</td></tr>`;
                return;
            }
            const col = catColors[p.category] || '#999';
            const reqs = (p.requires || []).join(', ') || '&mdash;';
            const badge = `<span style="background:${col};color:#fff;padding:2px 8px;border-radius:10px;font-size:11px">${p.category}</span>`;
            tbody.innerHTML += `
              <tr>
                <td style="text-align:center;font-weight:600">${p.phase}</td>
                <td><strong>${p.name}</strong>${p.requires_root ? ' <span title="Requires root/admin" style="color:#e74c3c;font-size:10px">★root</span>' : ''}</td>
                <td><code style="font-size:11px">${p.plugin_id}</code></td>
                <td>${badge}</td>
                <td style="font-size:12px;color:#555">${p.description}</td>
                <td style="font-size:12px">${p.version}</td>
                <td style="font-size:11px;color:#888">${reqs}</td>
              </tr>`;
        });
    } catch(e) {
        tbody.innerHTML = `<tr><td colspan="7" style="color:#c00;padding:16px">Failed to load plugins: ${e.message}</td></tr>`;
    }
}

document.addEventListener('DOMContentLoaded', loadPlugins);
"""
    elif view == "policies":
        return r"""
async function loadPolicies() {
    const tbody = document.getElementById('policy-tbody');
    if (!tbody) return;
    try {
        const r = await fetch('/api/policies');
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const d = await r.json();
        const policies = d.policies || [];
        if (!policies.length) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#888;padding:20px">No policies yet. Click &ldquo;+ New Policy&rdquo; to create one.</td></tr>';
            return;
        }
        tbody.innerHTML = '';
        policies.forEach(p => {
            const mods = (p.modules || []).join(', ') || '—';
            const nets = p.networks || '<span style="color:#aaa">Global</span>';
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${escPol(p.name)}</strong>${p.notes ? '<br><span style="color:#888;font-size:11px">' + escPol(p.notes) + '</span>' : ''}</td>
                <td><span class="badge badge-ok" style="text-transform:capitalize">${escPol(p.scan_type||'')}</span></td>
                <td style="font-size:12px;color:#555">${escPol(nets)}</td>
                <td style="font-size:12px;color:#555">${escPol(mods)}</td>
                <td><span class="badge ${p.intensity==='high'?'badge-warn':p.intensity==='low'?'badge-ok':'badge-medium'}" style="text-transform:capitalize">${escPol(p.intensity||'normal')}</span></td>
                <td>
                  <button class="btn btn-grey btn-sm" style="padding:3px 10px;font-size:12px"
                          onclick='editPolicy(${JSON.stringify(JSON.stringify(p))})'>Edit</button>
                  <button class="btn btn-sm" style="padding:3px 10px;font-size:12px;background:#c0392b;color:#fff"
                          onclick="deletePolicy('${escPol(p.name).replace(/'/g,'\'')}')" >Delete</button>
                </td>`;
            tbody.appendChild(tr);
        });
    } catch(e) {
        tbody.innerHTML = '<tr><td colspan="6" style="color:#c00;padding:16px">Failed to load policies: ' + e.message + '</td></tr>';
    }
}

function escPol(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showPolicyForm(title) {
    document.getElementById('policy-form-card').style.display = '';
    document.getElementById('policy-form-title').textContent = title || 'Create Scan Policy';
    document.getElementById('policy-form-card').scrollIntoView({behavior:'smooth',block:'start'});
}

function hidePolicyForm() {
    document.getElementById('policy-form-card').style.display = 'none';
    document.getElementById('policy-form').reset();
    document.getElementById('policy-form').removeAttribute('data-edit');
}

function getCheckedModules() {
    return Array.from(document.querySelectorAll('#p-modules input[type=checkbox]:checked'))
                .map(el => el.value);
}

function setCheckedModules(mods) {
    document.querySelectorAll('#p-modules input[type=checkbox]').forEach(el => {
        el.checked = mods.includes(el.value);
    });
}

function editPolicy(jsonStr) {
    const p = JSON.parse(jsonStr);
    document.getElementById('p-name').value      = p.name      || '';
    document.getElementById('p-type').value      = p.scan_type || 'credentialed';
    document.getElementById('p-intensity').value = p.intensity || 'normal';
    document.getElementById('p-networks').value  = p.networks  || '';
    document.getElementById('p-parallel').value  = p.max_parallel || 10;
    document.getElementById('p-ports').value     = p.port_range   || 'top1000';
    document.getElementById('p-timeout').value   = p.timeout_per_host || 120;
    document.getElementById('p-notes').value     = p.notes || '';
    setCheckedModules(p.modules || []);
    document.getElementById('policy-form').setAttribute('data-edit', p.name);
    showPolicyForm('Edit Policy: ' + p.name);
}

async function submitPolicyForm(e) {
    e.preventDefault();
    const btn  = document.getElementById('btn-policy-save');
    const spin = document.getElementById('spin-policy');
    btn.disabled = true; spin.style.display = '';
    const editName = document.getElementById('policy-form').getAttribute('data-edit') || null;
    const body = {
        name:             document.getElementById('p-name').value.trim(),
        scan_type:        document.getElementById('p-type').value,
        intensity:        document.getElementById('p-intensity').value,
        networks:         document.getElementById('p-networks').value.trim(),
        modules:          getCheckedModules(),
        max_parallel:     parseInt(document.getElementById('p-parallel').value) || 10,
        port_range:       document.getElementById('p-ports').value.trim() || 'top1000',
        timeout_per_host: parseInt(document.getElementById('p-timeout').value) || 120,
        notes:            document.getElementById('p-notes').value.trim(),
        edit_name:        editName,
    };
    try {
        const r = await fetch('/api/policies/save', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(body)
        });
        const d = await r.json();
        showToast(d.message, d.success ? 'success' : 'error');
        if (d.success) { hidePolicyForm(); loadPolicies(); }
    } catch(err) {
        showToast('Error: ' + err.message, 'error');
    } finally {
        btn.disabled = false; spin.style.display = 'none';
    }
}

async function deletePolicy(name) {
    if (!confirm('Delete policy "' + name + '"? This cannot be undone.')) return;
    try {
        const r = await fetch('/api/policies/delete', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({name})
        });
        const d = await r.json();
        showToast(d.message, d.success ? 'success' : 'error');
        if (d.success) loadPolicies();
    } catch(err) {
        showToast('Error: ' + err.message, 'error');
    }
}

document.addEventListener('DOMContentLoaded', loadPolicies);
"""
    return ""




def _policies_content() -> str:
    return """
<div class="card">
  <div class="card-title">Scan Policies
    <button class="btn btn-orange btn-sm" style="float:right;padding:5px 14px;font-size:12px"
            onclick="showPolicyForm()">+ New Policy</button>
  </div>
  <p style="color:#888;font-size:13px;margin-bottom:14px">
    Policies control which scan modules run, which targets are in scope, and how aggressively
    the scanner probes. Assign a policy when scheduling a scan run.
  </p>
  <div style="overflow-x:auto">
  <table class="cred-table" id="policy-table">
    <thead>
      <tr>
        <th>Policy Name</th><th>Scan Type</th><th>Target Networks</th><th>Modules</th><th>Intensity</th><th>Actions</th>
      </tr>
    </thead>
    <tbody id="policy-tbody">
      <tr><td colspan="6" style="text-align:center;color:#888;padding:20px">Loading&#8230;</td></tr>
    </tbody>
  </table>
  </div>
</div>

<div class="card" id="policy-form-card" style="display:none">
  <div class="card-title" id="policy-form-title">Create Scan Policy</div>
  <form id="policy-form" onsubmit="submitPolicyForm(event)">

    <div class="form-row">
      <div class="form-group">
        <label>Policy Name</label>
        <input type="text" id="p-name" placeholder="e.g. Full Credentialed Audit" required>
      </div>
      <div class="form-group">
        <label>Scan Type</label>
        <select id="p-type">
          <option value="discovery">Discovery (ping/port sweep only)</option>
          <option value="basic">Basic Network Scan</option>
          <option value="credentialed" selected>Credentialed Patch Audit</option>
          <option value="compliance">Compliance / Hardening Audit</option>
          <option value="full">Full Deep Scan</option>
        </select>
      </div>
      <div class="form-group">
        <label>Scan Intensity</label>
        <select id="p-intensity">
          <option value="low">Low (stealthy, slow)</option>
          <option value="normal" selected>Normal</option>
          <option value="high">High (aggressive, fast)</option>
        </select>
      </div>
    </div>

    <div class="form-group">
      <label>Target Networks (comma-separated CIDRs or IPs, blank = use global config)</label>
      <input type="text" id="p-networks" placeholder="e.g. 192.168.1.0/24, 10.0.0.0/8">
    </div>

    <div class="form-group">
      <label>Enabled Modules</label>
      <div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:6px" id="p-modules">
        <label style="font-weight:400;display:flex;align-items:center;gap:6px">
          <input type="checkbox" value="nmap" checked> Nmap Port Scan</label>
        <label style="font-weight:400;display:flex;align-items:center;gap:6px">
          <input type="checkbox" value="ssh" checked> SSH Credentialed Audit</label>
        <label style="font-weight:400;display:flex;align-items:center;gap:6px">
          <input type="checkbox" value="wmi" checked> WMI / WinRM Audit</label>
        <label style="font-weight:400;display:flex;align-items:center;gap:6px">
          <input type="checkbox" value="snmp" checked> SNMP Enumeration</label>
        <label style="font-weight:400;display:flex;align-items:center;gap:6px">
          <input type="checkbox" value="cve" checked> CVE Correlation (NVD/KEV)</label>
        <label style="font-weight:400;display:flex;align-items:center;gap:6px">
          <input type="checkbox" value="compliance"> Compliance / CIS Checks</label>
        <label style="font-weight:400;display:flex;align-items:center;gap:6px">
          <input type="checkbox" value="web"> Web Application Probing</label>
        <label style="font-weight:400;display:flex;align-items:center;gap:6px">
          <input type="checkbox" value="bruteforce"> Credential Brute-force Check</label>
      </div>
    </div>

    <div class="form-row">
      <div class="form-group">
        <label>Max Parallel Hosts</label>
        <input type="number" id="p-parallel" value="10" min="1" max="100">
      </div>
      <div class="form-group">
        <label>Port Range</label>
        <input type="text" id="p-ports" placeholder="e.g. 1-65535 or top1000" value="top1000">
      </div>
      <div class="form-group">
        <label>Timeout per Host (sec)</label>
        <input type="number" id="p-timeout" value="120" min="10" max="3600">
      </div>
    </div>

    <div class="form-group">
      <label>Notes / Description</label>
      <input type="text" id="p-notes" placeholder="Optional description">
    </div>

    <div style="display:flex;gap:12px;margin-top:8px">
      <button type="submit" class="btn btn-orange" id="btn-policy-save">
        <span class="spinner" id="spin-policy" style="display:none"></span>
        Save Policy
      </button>
      <button type="button" class="btn btn-grey" onclick="hidePolicyForm()">Cancel</button>
    </div>
  </form>
</div>
"""


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
          onclick="window.location.href='/dashboard?view=settings'">
    Settings
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
<div class="card" id="ai-insights-card" style="display:none">
  <div class="card-title" style="display:flex;align-items:center;gap:8px">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#FF6600" stroke-width="2">
      <circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/>
    </svg>
    AI Risk Insights
  </div>
  <div id="ai-insights-body" style="font-size:13px;line-height:1.7;color:#444;white-space:pre-wrap"></div>
</div>

<div class="card">
  <div class="card-title">Host Risk Detail — click a row to expand</div>
  <div style="overflow-x:auto">
  <table class="host-table">
    <thead>
      <tr>
        <th>IP</th>
        <th>Hostname / Vendor</th>
        <th>OS / Category</th>
        <th>Score</th>
        <th>Level</th>
        <th>CVEs</th>
        <th>KEV</th>
        <th>Cred</th>
        <th>Ports</th>
      </tr>
    </thead>
    <tbody id="host-tbody">
      <tr><td colspan="9" style="text-align:center;color:#888;padding:24px">Loading…</td></tr>
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


def _credentials_content() -> str:
    return """
<div class="card">
  <div class="card-title">Credential Profiles
    <button class="btn btn-orange btn-sm" style="float:right;padding:5px 14px;font-size:12px"
            onclick="showCredForm()">+ Add Profile</button>
  </div>
  <div style="overflow-x:auto">
  <table class="cred-table" id="cred-table">
    <thead>
      <tr>
        <th>Profile Name</th><th>Type</th><th>Scope</th><th>Targets</th><th>Username</th><th>Actions</th>
      </tr>
    </thead>
    <tbody id="cred-tbody">
      <tr><td colspan="6" style="text-align:center;color:#888;padding:20px">Loading…</td></tr>
    </tbody>
  </table>
  </div>
</div>

<div class="card" id="cred-form-card" style="display:none">
  <div class="card-title" id="cred-form-title">Add Credential Profile</div>
  <form id="cred-form" onsubmit="submitCredForm(event)">
    <div class="form-row">
      <div class="form-group">
        <label>Profile Name</label>
        <input type="text" id="f-name" placeholder="e.g. ssh-admin" required>
      </div>
      <div class="form-group">
        <label>Type</label>
        <select id="f-type" onchange="onTypeChange()">
          <option value="ssh">SSH</option>
          <option value="wmi">WMI / Windows</option>
          <option value="snmp_v2c">SNMP v2c</option>
          <option value="snmp_v3">SNMP v3</option>
        </select>
      </div>
      <div class="form-group">
        <label>Scope</label>
        <select id="f-scope" onchange="onScopeChange()">
          <option value="global">Global (all hosts)</option>
          <option value="subnet">Subnet</option>
          <option value="host">Specific Host</option>
        </select>
      </div>
    </div>

    <div class="form-group" id="fg-targets" style="display:none">
      <label>Targets (comma-separated IPs or CIDRs)</label>
      <input type="text" id="f-targets" placeholder="e.g. 192.168.1.0/24, 10.0.0.5">
    </div>

    <div id="fg-userpass">
      <div class="form-row">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="f-username" autocomplete="off"
               placeholder="user, DOMAIN\\user, or user@domain.local">
        </div>
        <div class="form-group">
          <label>Password</label>
          <input type="password" id="f-password" autocomplete="new-password"
                 placeholder="Leave blank to keep existing">
        </div>
      </div>
      <div class="form-group" id="fg-sshkey">
        <label>SSH Key Path (optional, overrides password)</label>
        <input type="text" id="f-sshkey" placeholder="/home/user/.ssh/id_rsa">
      </div>
    </div>

    <div class="form-group" id="fg-community" style="display:none">
      <label>SNMP Community String</label>
      <input type="password" id="f-community" autocomplete="new-password"
             placeholder="Leave blank to keep existing">
    </div>

    <div id="fg-snmpv3" style="display:none">
      <div class="form-row">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="f-snmpuser" autocomplete="off">
        </div>
        <div class="form-group">
          <label>Auth Key</label>
          <input type="password" id="f-authkey" autocomplete="new-password"
                 placeholder="Leave blank to keep existing">
        </div>
        <div class="form-group">
          <label>Priv Key</label>
          <input type="password" id="f-privkey" autocomplete="new-password"
                 placeholder="Leave blank to keep existing">
        </div>
      </div>
    </div>

    <div style="display:flex;gap:12px;margin-top:8px">
      <button type="submit" class="btn btn-orange" id="btn-cred-save">
        <span class="spinner" id="spin-cred" style="display:none"></span>
        Save Profile
      </button>
      <button type="button" class="btn btn-grey" onclick="hideCredForm()">Cancel</button>
    </div>
  </form>
</div>
"""


def _settings_content() -> str:
    return """
<div id="settings-loading" style="color:#888;font-size:14px;padding:8px 0">Loading settings…</div>
<div id="settings-form" style="display:none">

<!-- ── Identity ─────────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">Identity</div>
  <div class="form-row">
    <div class="form-group">
      <label>Client / Organization Name</label>
      <input id="s-client-name" type="text" placeholder="Acme Corp">
    </div>
    <div class="form-group">
      <label>Site Name / Location</label>
      <input id="s-site-name" type="text" placeholder="Main Office">
    </div>
  </div>
</div>

<!-- ── Reporting ─────────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">Reporting</div>
  <div class="form-row">
    <div class="form-group">
      <label>Sender Email (From)</label>
      <input id="s-sender-email" type="text" placeholder="scanner@example.com">
    </div>
    <div class="form-group">
      <label>Report Recipients (comma-separated)</label>
      <input id="s-report-to" type="text" placeholder="admin@example.com, ciso@example.com">
    </div>
  </div>
</div>

<!-- ── Graph API ──────────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">Microsoft Graph API</div>
  <div class="form-row">
    <div class="form-group">
      <label>Azure Tenant ID</label>
      <input id="s-tenant-id" type="text" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
    </div>
    <div class="form-group">
      <label>App Client ID</label>
      <input id="s-client-id" type="text" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
    </div>
  </div>
  <div class="form-group" style="max-width:420px">
    <label>Client Secret <span style="font-weight:400;text-transform:none;letter-spacing:0;color:#AAA">(leave blank to keep existing)</span></label>
    <input id="s-client-secret" type="password" placeholder="Enter new secret to change">
  </div>
</div>

<!-- ── Scanning ───────────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">Scanning</div>
  <div class="form-group">
    <label>Target Networks (comma-separated CIDRs)</label>
    <input id="s-networks" type="text" placeholder="192.168.1.0/24, 10.0.0.0/16">
  </div>
</div>

<!-- ── Schedule ──────────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">Schedule</div>
  <div class="form-row">
    <div class="form-group">
      <label>Daily Scan Time (HH:MM 24-hour)</label>
      <input id="s-scan-time" type="text" placeholder="02:00" style="max-width:120px">
    </div>
    <div class="form-group">
      <label>Weekly Report Day</label>
      <select id="s-report-day" style="max-width:150px">
        <option value="Mon">Monday</option>
        <option value="Tue">Tuesday</option>
        <option value="Wed">Wednesday</option>
        <option value="Thu">Thursday</option>
        <option value="Fri">Friday</option>
        <option value="Sat">Saturday</option>
        <option value="Sun">Sunday</option>
      </select>
    </div>
    <div class="form-group">
      <label>Weekly Report Time (HH:MM 24-hour)</label>
      <input id="s-report-time" type="text" placeholder="06:00" style="max-width:120px">
    </div>
  </div>
</div>

<!-- ── Hatz AI ────────────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">Hatz AI Enrichment</div>
  <div class="form-row" style="align-items:flex-end">
    <div class="form-group" style="max-width:140px">
      <label>Enabled</label>
      <select id="s-hatz-enabled">
        <option value="true">Yes</option>
        <option value="false">No</option>
      </select>
    </div>
    <div class="form-group">
      <label>Model</label>
      <input id="s-hatz-model" type="text" placeholder="hatz-risk-v1" style="max-width:200px">
    </div>
    <div class="form-group" style="flex:2">
      <label>API Key <span style="font-weight:400;text-transform:none;letter-spacing:0;color:#AAA">(blank to keep existing)</span></label>
      <input id="s-hatz-api-key" type="password" placeholder="Enter new key to change">
    </div>
  </div>
</div>



<!-- ── SOAR / Ticketing Integration ──────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">SOAR / Ticketing Integration
    <span style="float:right;font-size:11px;color:#888;font-weight:400">
      Findings dispatched automatically after each scan
    </span>
  </div>
  <p style="color:#888;font-size:13px;margin-bottom:14px">
    Automatically create tickets or send alerts to Jira, ServiceNow, Slack,
    Teams, PagerDuty or any custom webhook when scan findings meet the
    configured severity threshold.
  </p>
  <div class="form-row" style="align-items:flex-end">
    <div class="form-group" style="max-width:140px">
      <label>Enabled</label>
      <select id="s-soar-enabled">
        <option value="false">Disabled</option>
        <option value="true">Enabled</option>
      </select>
    </div>
    <div class="form-group" style="max-width:180px">
      <label>Min. Severity</label>
      <select id="s-soar-min-sev">
        <option value="CRITICAL">Critical only</option>
        <option value="HIGH" selected>High &amp; above</option>
        <option value="MEDIUM">Medium &amp; above</option>
        <option value="LOW">All findings</option>
      </select>
    </div>
    <div class="form-group" style="max-width:180px">
      <label>KEV-only Mode</label>
      <select id="s-soar-kev-only">
        <option value="false">All findings</option>
        <option value="true">KEV findings only</option>
      </select>
    </div>
    <div class="form-group" style="max-width:160px">
      <label>Deduplicate</label>
      <select id="s-soar-dedup">
        <option value="true" selected>Yes (30-day window)</option>
        <option value="false">No (always send)</option>
      </select>
    </div>
  </div>

  <div style="font-size:13px;font-weight:600;color:#ccc;margin:10px 0 6px">Providers</div>

  <!-- Jira -->
  <details style="margin-bottom:10px">
    <summary style="cursor:pointer;font-size:13px;color:#e67e22;font-weight:600">Jira</summary>
    <div style="padding:10px 0 0 10px">
      <div class="form-row">
        <div class="form-group" style="max-width:120px">
          <label>Enabled</label>
          <select id="s-jira-enabled">
            <option value="false">No</option>
            <option value="true">Yes</option>
          </select>
        </div>
        <div class="form-group">
          <label>Jira URL</label>
          <input id="s-jira-url" type="text" placeholder="https://yourorg.atlassian.net">
        </div>
        <div class="form-group">
          <label>Email</label>
          <input id="s-jira-email" type="text" placeholder="scanner@yourorg.com">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group">
          <label>API Token <span style="color:#aaa;font-weight:400">(or JIRA_API_TOKEN env)</span></label>
          <input id="s-jira-token" type="password" placeholder="Leave blank to keep existing">
        </div>
        <div class="form-group" style="max-width:140px">
          <label>Project Key</label>
          <input id="s-jira-project" type="text" placeholder="SEC">
        </div>
        <div class="form-group" style="max-width:160px">
          <label>Issue Type</label>
          <input id="s-jira-issue-type" type="text" placeholder="Bug" value="Bug">
        </div>
      </div>
    </div>
  </details>

  <!-- ServiceNow -->
  <details style="margin-bottom:10px">
    <summary style="cursor:pointer;font-size:13px;color:#e67e22;font-weight:600">ServiceNow</summary>
    <div style="padding:10px 0 0 10px">
      <div class="form-row">
        <div class="form-group" style="max-width:120px">
          <label>Enabled</label>
          <select id="s-snow-enabled">
            <option value="false">No</option>
            <option value="true">Yes</option>
          </select>
        </div>
        <div class="form-group">
          <label>Instance URL</label>
          <input id="s-snow-url" type="text" placeholder="https://yourorg.service-now.com">
        </div>
        <div class="form-group">
          <label>Username</label>
          <input id="s-snow-user" type="text" placeholder="scanner-svc">
        </div>
        <div class="form-group">
          <label>Password <span style="color:#aaa;font-weight:400">(or SNOW_PASSWORD env)</span></label>
          <input id="s-snow-pass" type="password" placeholder="Leave blank to keep existing">
        </div>
      </div>
      <div class="form-row">
        <div class="form-group" style="max-width:160px">
          <label>Table</label>
          <input id="s-snow-table" type="text" placeholder="incident" value="incident">
        </div>
        <div class="form-group">
          <label>Assignment Group</label>
          <input id="s-snow-group" type="text" placeholder="Security Operations">
        </div>
      </div>
    </div>
  </details>

  <!-- Webhook (Slack / Teams / PagerDuty / Custom) -->
  <details style="margin-bottom:6px">
    <summary style="cursor:pointer;font-size:13px;color:#e67e22;font-weight:600">Webhook (Slack / Teams / PagerDuty / Custom)</summary>
    <div style="padding:10px 0 0 10px">
      <div class="form-row">
        <div class="form-group" style="max-width:120px">
          <label>Enabled</label>
          <select id="s-wh-enabled">
            <option value="false">No</option>
            <option value="true">Yes</option>
          </select>
        </div>
        <div class="form-group">
          <label>Webhook URL</label>
          <input id="s-wh-url" type="text" placeholder="https://hooks.slack.com/...">
        </div>
        <div class="form-group" style="max-width:200px">
          <label>Template</label>
          <select id="s-wh-template">
            <option value="slack">Slack</option>
            <option value="teams">Microsoft Teams</option>
            <option value="pagerduty">PagerDuty</option>
            <option value="default">Generic JSON</option>
          </select>
        </div>
      </div>
      <div class="form-group">
        <label>PagerDuty Routing Key <span style="color:#aaa;font-weight:400">(if using PagerDuty template)</span></label>
        <input id="s-wh-routing-key" type="text" placeholder="PagerDuty integration key">
      </div>
    </div>
  </details>
</div>

<!-- ── PAM / Vault Integration ────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">PAM / Secrets Vault Integration
    <span style="float:right;font-size:11px;color:#888;font-weight:400">
      Credentials fetched at scan time — never stored locally
    </span>
  </div>
  <p style="color:#888;font-size:13px;margin-bottom:14px">
    Connect to HashiCorp Vault, CyberArk CCP, or Azure Key Vault to dynamically
    fetch scan credentials at runtime instead of storing them on the device.
  </p>
  <div class="form-row" style="align-items:flex-end">
    <div class="form-group" style="max-width:140px">
      <label>Enabled</label>
      <select id="s-vault-enabled" onchange="onVaultProviderChange()">
        <option value="false">Disabled</option>
        <option value="true">Enabled</option>
      </select>
    </div>
    <div class="form-group" style="max-width:220px">
      <label>Provider</label>
      <select id="s-vault-provider" onchange="onVaultProviderChange()">
        <option value="hashicorp">HashiCorp Vault</option>
        <option value="cyberark">CyberArk CCP</option>
        <option value="azure_keyvault">Azure Key Vault</option>
      </select>
    </div>
    <div class="form-group" style="flex:2">
      <label>Vault URL</label>
      <input id="s-vault-url" type="text" placeholder="https://vault.example.com:8200">
    </div>
    <div class="form-group" style="max-width:100px">
      <label>TLS Verify</label>
      <select id="s-vault-tls">
        <option value="true">Yes</option>
        <option value="false">No</option>
      </select>
    </div>
  </div>

  <!-- HashiCorp fields -->
  <div id="vault-hashicorp" style="display:none">
    <div class="form-row">
      <div class="form-group" style="max-width:180px">
        <label>Auth Method</label>
        <select id="s-vault-auth">
          <option value="token">Token</option>
          <option value="approle">AppRole</option>
        </select>
      </div>
      <div class="form-group">
        <label>Token <span style="color:#aaa;font-weight:400">(or set VAULT_TOKEN env)</span></label>
        <input id="s-vault-token" type="password" placeholder="hvs.xxxxx">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>AppRole Role ID</label>
        <input id="s-vault-role-id" type="text" placeholder="role_id">
      </div>
      <div class="form-group">
        <label>AppRole Secret ID <span style="color:#aaa;font-weight:400">(or VAULT_SECRET_ID env)</span></label>
        <input id="s-vault-secret-id" type="password" placeholder="secret_id">
      </div>
      <div class="form-group" style="max-width:140px">
        <label>KV Mount</label>
        <input id="s-vault-mount" type="text" placeholder="secret" value="secret">
      </div>
      <div class="form-group" style="max-width:100px">
        <label>KV Version</label>
        <select id="s-vault-kv-version">
          <option value="2" selected>v2</option>
          <option value="1">v1</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <label>Secret Paths <span style="color:#aaa;font-weight:400">(comma-separated, e.g. creds/ssh-admin, creds/wmi-svc)</span></label>
      <input id="s-vault-paths" type="text" placeholder="creds/ssh-admin, creds/windows-svc">
    </div>
  </div>

  <!-- CyberArk fields -->
  <div id="vault-cyberark" style="display:none">
    <div class="form-row">
      <div class="form-group">
        <label>Application ID</label>
        <input id="s-vault-app-id" type="text" placeholder="ScannerApp">
      </div>
      <div class="form-group">
        <label>Safe Name</label>
        <input id="s-vault-safe" type="text" placeholder="ScannerSafe">
      </div>
    </div>
    <div class="form-group">
      <label>Object Names <span style="color:#aaa;font-weight:400">(comma-separated)</span></label>
      <input id="s-vault-objects" type="text" placeholder="ssh-root, win-svc-account">
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Client Certificate Path <span style="color:#aaa;font-weight:400">(optional)</span></label>
        <input id="s-vault-cert" type="text" placeholder="/etc/scanner/ccp-client.pem">
      </div>
      <div class="form-group">
        <label>Client Key Path <span style="color:#aaa;font-weight:400">(optional)</span></label>
        <input id="s-vault-key" type="text" placeholder="/etc/scanner/ccp-client.key">
      </div>
    </div>
  </div>

  <!-- Azure Key Vault fields -->
  <div id="vault-azure" style="display:none">
    <div class="form-row">
      <div class="form-group">
        <label>Vault Name</label>
        <input id="s-vault-akv-name" type="text" placeholder="my-keyvault">
      </div>
      <div class="form-group">
        <label>Tenant ID</label>
        <input id="s-vault-akv-tenant" type="text" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label>Client ID</label>
        <input id="s-vault-akv-client-id" type="text" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
      </div>
      <div class="form-group">
        <label>Client Secret <span style="color:#aaa;font-weight:400">(or AZURE_CLIENT_SECRET env)</span></label>
        <input id="s-vault-akv-secret" type="password" placeholder="Leave blank to keep existing">
      </div>
    </div>
    <div class="form-group">
      <label>Secret Names <span style="color:#aaa;font-weight:400">(comma-separated)</span></label>
      <input id="s-vault-akv-secrets" type="text" placeholder="ssh-admin-cred, win-svc-cred">
    </div>
  </div>
</div>

<!-- ── Save ───────────────────────────────────────────────────────────────── -->
<div class="action-row">
  <button class="btn btn-orange" id="btn-save-settings" onclick="saveSettings()">
    <span class="spinner" id="spin-save" style="display:none"></span>
    Save Settings
  </button>
</div>

<!-- ── Change Password ────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">Change Dashboard Password</div>
  <div class="form-row" style="max-width:580px">
    <div class="form-group">
      <label>Current Password</label>
      <input id="s-pw-current" type="password">
    </div>
  </div>
  <div class="form-row" style="max-width:580px">
    <div class="form-group">
      <label>New Password</label>
      <input id="s-pw-new" type="password">
    </div>
    <div class="form-group">
      <label>Confirm New Password</label>
      <input id="s-pw-confirm" type="password">
    </div>
  </div>
  <div class="action-row" style="margin-bottom:0">
    <button class="btn btn-blue" id="btn-change-pw" onclick="changePassword()">
      <span class="spinner" id="spin-pw" style="display:none"></span>
      Change Password
    </button>
  </div>
</div>

<!-- ── Service Actions ────────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-title">Service Actions</div>
  <div class="action-row" style="margin-bottom:0">
    <button class="btn btn-orange" onclick="apiPost('/api/scan','','')">Run Scan Now</button>
    <button class="btn btn-blue"   onclick="apiPost('/api/report','','')">Send Report</button>
    <button class="btn btn-grey"   onclick="clearHistory()" id="btn-clear-history">
      <span class="spinner" id="spin-clear" style="display:none"></span>
      Clear Scan History
    </button>
  </div>
</div>

</div><!-- #settings-form -->
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

        if path == "/api/credentials":
            if not self._require_auth_json():
                return
            self._send_json(200, {"profiles": _list_credentials()})
            return

        if path == "/api/config":
            if not self._require_auth_json():
                return
            self._send_json(200, _load_config_safe())
            return

        if path == "/api/policies":
            if not self._require_auth_json():
                return
            self._send_json(200, {"policies": _list_policies()})
            return

        if path == "/api/plugins":
            if not self._require_auth_json():
                return
            self._send_json(200, {"plugins": _get_plugin_registry_safe()})
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
            self._send_json(200, {
                "success": False,
                "message": "Use the Settings tab in the dashboard, or SSH to the Pi and run: "
                           "sudo /opt/risk-scanner/bin/update-config.sh",
            })
            return

        if path == "/api/credentials/add":
            if not self._require_auth_json():
                return
            body = self._parse_body()
            result = _save_credential(body)
            self._send_json(200, result)
            return

        if path == "/api/credentials/delete":
            if not self._require_auth_json():
                return
            body = self._parse_body()
            name = body.get("profile_name", "")
            if not name:
                self._send_json(400, {"success": False, "message": "profile_name required"})
                return
            result = _delete_credential(name)
            self._send_json(200, result)
            return

        if path == "/api/config":
            if not self._require_auth_json():
                return
            body = self._parse_body()
            result = _save_config(body)
            self._send_json(200, result)
            return

        if path == "/api/password":
            if not self._require_auth_json():
                return
            body = self._parse_body()
            result = _change_password(body)
            self._send_json(200, result)
            return

        if path == "/api/policies/save":
            if not self._require_auth_json():
                return
            body = self._parse_body()
            self._send_json(200, _save_policy(body))
            return

        if path == "/api/policies/delete":
            if not self._require_auth_json():
                return
            body = self._parse_body()
            name = body.get("name", "")
            if not name:
                self._send_json(400, {"success": False, "message": "name required"})
                return
            self._send_json(200, _delete_policy(name))
            return

        if path == "/api/history/clear":
            if not self._require_auth_json():
                return
            try:
                import scan_history as _sh
                stats = _sh.clear_all_scans()
                self._send_json(200, {
                    "success": True,
                    "message": f"Cleared {stats['deleted_runs']} scan run(s) and "
                               f"{stats['deleted_archives']} archive file(s).",
                })
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
    global CONFIG_PATH
    parser = argparse.ArgumentParser(description="Yeyland Wutani Risk Scanner Web Dashboard")
    parser.add_argument("--config", default=str(CONFIG_PATH), help="Path to config.json")
    parser.add_argument("--port", type=int, default=8080, help="Listening port (default 8080)")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0)")
    args = parser.parse_args()

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
