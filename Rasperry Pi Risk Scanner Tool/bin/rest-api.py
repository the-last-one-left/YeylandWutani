#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
bin/rest-api.py  --  Standalone REST API server

Exposes all scanner functionality over HTTP/JSON so that SOAR platforms,
ticketing systems, and scripts can integrate without using the web dashboard.

Endpoints
---------
GET  /api/v1/status                    Scanner health and version
GET  /api/v1/policies                  List scan policies
POST /api/v1/policies                  Create / update a policy
DEL  /api/v1/policies/<name>           Delete a policy
GET  /api/v1/plugins                   List installed plugins
GET  /api/v1/scans                     List scan history
GET  /api/v1/scans/latest              Latest completed scan results
GET  /api/v1/scans/<id>                Specific historical scan by ID
POST /api/v1/scans/trigger             Trigger a new scan (async)
GET  /api/v1/scans/running             Status of current running scan
GET  /api/v1/assets                    All hosts from latest scan (summary)
GET  /api/v1/assets/<ip>               Single host detail
GET  /api/v1/assets/<ip>/cves          CVE findings for a host
GET  /api/v1/assets/<ip>/compliance    Compliance results for a host
GET  /api/v1/vulns                     All CVE findings across all hosts
GET  /api/v1/vulns/critical            Only CRITICAL severity findings
GET  /api/v1/vulns/kev                 Only CISA KEV findings
GET  /api/v1/credentials               List credential profile names (no secrets)
POST /api/v1/auth/rotate-key           Set a new API key

Authentication
--------------
All endpoints require an API key:
  Header:  X-API-Key: <key>
  OR Query: ?api_key=<key>

The key hash is stored in config.json under ["api"]["key_hash"].
If no key is configured all requests are accepted (configure one immediately).

Usage
-----
  python bin/rest-api.py [--port 8081] [--config /opt/risk-scanner/config/config.json]
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.server
import json
import logging
import logging.handlers
import os
import socketserver
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).parent.parent
LIB_DIR     = BASE_DIR / "lib"
PLUGIN_DIR  = BASE_DIR / "plugins"
DATA_DIR    = BASE_DIR / "data"
LOG_FILE    = BASE_DIR / "logs" / "rest-api.log"

for _p in (str(LIB_DIR), str(Path(__file__).parent)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

API_VERSION     = "v1"
SCANNER_VERSION = "2.0.0"
DEFAULT_PORT    = 8081

logger = logging.getLogger("rest-api")

# Mutable config path (overridden by --config argument)
_config_path = BASE_DIR / "config" / "config.json"

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_config() -> dict:
    try:
        with open(_config_path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_config(cfg: dict) -> None:
    _config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(_config_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


# ---------------------------------------------------------------------------
# Policies helpers
# ---------------------------------------------------------------------------

_POLICIES_PATH = BASE_DIR / "config" / "scan_policies.json"


def _load_policies() -> list:
    if not _POLICIES_PATH.exists():
        return []
    try:
        with open(_POLICIES_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_policy(body: dict) -> dict:
    name = (body.get("name") or "").strip()
    if not name:
        return {"success": False, "message": "Policy name is required."}
    edit_name = (body.get("edit_name") or "").strip() or None
    policies  = _load_policies()
    existing  = {p["name"] for p in policies}
    if name in existing and name != edit_name:
        return {"success": False, "message": f'Policy "{name}" already exists.'}
    if edit_name:
        policies = [p for p in policies if p["name"] != edit_name]
    policies = [p for p in policies if p["name"] != name]
    policies.append({
        "name":             name,
        "scan_type":        body.get("scan_type",        "credentialed"),
        "intensity":        body.get("intensity",        "normal"),
        "networks":         body.get("networks",         ""),
        "modules":          body.get("modules",          []),
        "max_parallel":     int(body.get("max_parallel",     10)),
        "port_range":       body.get("port_range",       "top1000"),
        "timeout_per_host": int(body.get("timeout_per_host", 120)),
        "notes":            body.get("notes",            ""),
    })
    _POLICIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_POLICIES_PATH, "w", encoding="utf-8") as f:
        json.dump(policies, f, indent=2)
    return {"success": True, "message": f'Policy "{name}" saved.'}


def _delete_policy_by_name(name: str) -> dict:
    policies = _load_policies()
    new_list = [p for p in policies if p["name"] != name]
    if len(new_list) == len(policies):
        return {"success": False, "message": f'Policy "{name}" not found.'}
    with open(_POLICIES_PATH, "w", encoding="utf-8") as f:
        json.dump(new_list, f, indent=2)
    return {"success": True, "message": f'Policy "{name}" deleted.'}


# ---------------------------------------------------------------------------
# Plugin registry
# ---------------------------------------------------------------------------

def _get_plugins() -> list:
    try:
        from plugin_loader import get_plugin_registry  # type: ignore
        return get_plugin_registry(str(PLUGIN_DIR))
    except Exception as exc:
        return [{"error": str(exc)}]


# ---------------------------------------------------------------------------
# Scan history helpers
# ---------------------------------------------------------------------------

def _load_latest_scan() -> dict | None:
    p = DATA_DIR / "last_scan.json"
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _list_scan_history() -> list[dict]:
    hist_dir = DATA_DIR / "history"
    if not hist_dir.exists():
        return []
    runs: list[dict] = []
    for f in sorted(hist_dir.glob("scan_*.json"), reverse=True):
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
            runs.append({
                "id":         f.stem,
                "scan_start": data.get("scan_start", ""),
                "scan_end":   data.get("scan_end", ""),
                "policy":     data.get("policy_name", "default"),
                "hosts":      len(data.get("hosts", [])),
                "risk_score": data.get("risk", {}).get("score", 0),
                "risk_level": data.get("risk", {}).get("level", "UNKNOWN"),
            })
        except Exception:
            pass
    return runs


def _load_scan_by_id(scan_id: str) -> dict | None:
    p = DATA_DIR / "history" / f"{scan_id}.json"
    if not p.exists():
        return None
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Async scan trigger
# ---------------------------------------------------------------------------

_scan_lock: threading.Lock = threading.Lock()
_scan_status: dict = {"running": False, "started": None, "policy": None, "pid": None}


def _trigger_scan(policy_name: str | None) -> dict:
    with _scan_lock:
        if _scan_status["running"]:
            return {
                "success": False,
                "message": "A scan is already running.",
                "status":  _scan_status,
            }
        engine = str(BASE_DIR / "bin" / "scan-engine.py")
        if not os.path.exists(engine):
            return {"success": False, "message": "scan-engine.py not found."}
        cmd = [sys.executable, engine]
        if policy_name:
            cmd += ["--policy", policy_name]
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(BASE_DIR),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            _scan_status.update({
                "running": True,
                "started": datetime.now(timezone.utc).isoformat(),
                "policy":  policy_name,
                "pid":     proc.pid,
            })

            def _monitor(p: subprocess.Popen) -> None:
                p.wait()
                with _scan_lock:
                    _scan_status["running"] = False
                    _scan_status["pid"]     = None
                logger.info(f"Scan process exited (code {p.returncode})")

            threading.Thread(target=_monitor, args=(proc,), daemon=True).start()
            return {
                "success": True,
                "message": f"Scan started (PID {proc.pid}).",
                "status":  _scan_status,
            }
        except Exception as exc:
            return {"success": False, "message": str(exc)}


# ---------------------------------------------------------------------------
# Credential helpers  (names/types only — no secrets exposed)
# ---------------------------------------------------------------------------

def _list_credential_names() -> list[dict]:
    creds_dir = BASE_DIR / "config" / "credentials"
    if not creds_dir.exists():
        return []
    result: list[dict] = []
    for f in sorted(creds_dir.glob("*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                c = json.load(fh)
            result.append({
                "name":     c.get("name", f.stem),
                "type":     c.get("type", "unknown"),
                "username": c.get("username", ""),
                "hosts":    c.get("hosts", []),
            })
        except Exception:
            pass
    return result


# ---------------------------------------------------------------------------
# SOAR helpers
# ---------------------------------------------------------------------------

_soar_last_dispatch: dict = {}


def _dispatch_soar_now() -> dict:
    """Manually trigger SOAR dispatch on the latest scan results."""
    global _soar_last_dispatch
    scan = _load_latest_scan()
    if scan is None:
        return {"success": False, "message": "No scan results available."}
    cfg      = _load_config()
    soar_cfg = cfg.get("soar", {})
    if not soar_cfg.get("enabled", False):
        return {"success": False, "message": "SOAR integration is not enabled in config."}
    try:
        _lib = str(BASE_DIR / "lib")
        if _lib not in sys.path:
            sys.path.insert(0, _lib)
        from soar_connector import dispatch_findings
        summary = dispatch_findings(scan, soar_cfg, data_dir=str(DATA_DIR))
        summary["success"] = True
        _soar_last_dispatch = summary
        return summary
    except Exception as exc:
        return {"success": False, "message": str(exc)}


# ---------------------------------------------------------------------------
# API key authentication

# ---------------------------------------------------------------------------

def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _verify_api_key(provided: str) -> bool:
    key_hash = _load_config().get("api", {}).get("key_hash", "")
    if not key_hash:
        return True  # no key configured — open access
    return hmac.compare_digest(_hash_key(provided), key_hash)


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class APIHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP/1.1 handler for the REST API."""

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.debug(fmt % args)

    # ---- helpers ----

    def _get_api_key(self) -> str:
        key = self.headers.get("X-API-Key", "")
        if not key and "?" in self.path:
            for part in self.path.split("?", 1)[1].split("&"):
                if part.startswith("api_key="):
                    key = part[8:]
                    break
        return key

    def _auth(self) -> bool:
        if not _verify_api_key(self._get_api_key()):
            self._json(401, {"error": "Unauthorized. Provide a valid X-API-Key header."})
            return False
        return True

    def _json(self, code: int, data: Any) -> None:
        body = json.dumps(data, indent=2, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type",                "application/json")
        self.send_header("Content-Length",              str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        if n == 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode())
        except Exception:
            return {}

    def _path_parts(self) -> list[str]:
        return self.path.split("?", 1)[0].strip("/").split("/")

    # ---- CORS preflight ----

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin",  "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "X-API-Key, Content-Type")
        self.end_headers()

    # ---- GET ----

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth():
            return
        parts = self._path_parts()
        if len(parts) < 3 or parts[0] != "api" or parts[1] != API_VERSION:
            self._json(404, {"error": "Not found"})
            return

        resource = parts[2]
        rid  = parts[3] if len(parts) > 3 else None
        sub  = parts[4] if len(parts) > 4 else None

        if resource == "status":
            cfg = _load_config()
            self._json(200, {
                "status":       "ok",
                "version":      SCANNER_VERSION,
                "api_version":  API_VERSION,
                "client":       cfg.get("reporting", {}).get("client_name", "Unknown"),
                "timestamp":    datetime.now(timezone.utc).isoformat(),
                "scan_running": _scan_status["running"],
            })

        elif resource == "policies":
            self._json(200, {"policies": _load_policies()})

        elif resource == "plugins":
            self._json(200, {"plugins": _get_plugins()})

        elif resource == "scans":
            if rid == "latest":
                data = _load_latest_scan()
                self._json(404 if data is None else 200,
                           data or {"error": "No scan results found."})
            elif rid == "running":
                self._json(200, _scan_status)
            elif rid:
                data = _load_scan_by_id(rid)
                self._json(404 if data is None else 200,
                           data or {"error": f"Scan '{rid}' not found."})
            else:
                self._json(200, {"scans": _list_scan_history()})

        elif resource == "assets":
            scan = _load_latest_scan()
            if scan is None:
                self._json(404, {"error": "No scan results available."})
                return
            hosts = scan.get("hosts", [])
            if rid is None:
                self._json(200, {"assets": [{
                    "ip":         h["ip"],
                    "hostname":   h.get("hostname", ""),
                    "os_guess":   h.get("os_guess", ""),
                    "risk_score": h.get("risk_score", 0),
                    "risk_level": h.get("risk_level", "LOW"),
                    "open_ports": len(h.get("ports", [])),
                    "cve_count":  len(h.get("cves", [])),
                } for h in hosts]})
            else:
                ip   = rid.replace("-", ".")
                host = next((h for h in hosts if h["ip"] == ip), None)
                if host is None:
                    self._json(404, {"error": f"Host '{ip}' not in latest scan."})
                    return
                if sub == "cves":
                    self._json(200, {"ip": ip, "cves": host.get("cves", [])})
                elif sub == "compliance":
                    self._json(200, {"ip": ip, "compliance": host.get("compliance", {})})
                else:
                    self._json(200, host)

        elif resource == "vulns":
            scan = _load_latest_scan()
            if scan is None:
                self._json(404, {"error": "No scan results available."})
                return
            all_vulns: list[dict] = []
            for host in scan.get("hosts", []):
                for cve in host.get("cves", []):
                    all_vulns.append({**cve, "host_ip": host["ip"],
                                      "hostname": host.get("hostname", "")})
            if rid == "critical":
                all_vulns = [v for v in all_vulns if v.get("severity") == "CRITICAL"]
            elif rid == "kev":
                all_vulns = [v for v in all_vulns if v.get("kev")]
            all_vulns.sort(key=lambda v: v.get("score", 0), reverse=True)
            self._json(200, {"count": len(all_vulns), "vulnerabilities": all_vulns})

        elif resource == "credentials":
            self._json(200, {"credentials": _list_credential_names()})

        elif resource == "soar":
            if rid == "status":
                self._json(200, _soar_last_dispatch or {"message": "No dispatch run yet this session."})
            else:
                self._json(404, {"error": "Use /api/v1/soar/status"})

        else:
            self._json(404, {"error": f"Unknown resource: '{resource}'"})

    # ---- POST ----

    def do_POST(self) -> None:  # noqa: N802
        if not self._auth():
            return
        parts = self._path_parts()
        if len(parts) < 3 or parts[0] != "api" or parts[1] != API_VERSION:
            self._json(404, {"error": "Not found"})
            return

        resource = parts[2]
        sub      = parts[3] if len(parts) > 3 else None
        body     = self._read_body()

        if resource == "policies":
            self._json(200, _save_policy(body))

        elif resource == "scans" and sub == "trigger":
            self._json(202, _trigger_scan(body.get("policy")))

        elif resource == "soar" and sub == "dispatch":
            self._json(200, _dispatch_soar_now())

        elif resource == "auth" and sub == "rotate-key":
            new_key = body.get("new_key", "")
            if not new_key or len(new_key) < 16:
                self._json(400, {"error": "new_key must be at least 16 characters."})
                return
            cfg = _load_config()
            cfg.setdefault("api", {})["key_hash"] = _hash_key(new_key)
            _save_config(cfg)
            self._json(200, {"success": True, "message": "API key updated."})

        else:
            self._json(404, {"error": "Not found"})

    # ---- DELETE ----

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._auth():
            return
        parts = self._path_parts()
        if len(parts) < 4 or parts[0] != "api" or parts[1] != API_VERSION:
            self._json(404, {"error": "Not found"})
            return

        resource = parts[2]
        rid      = parts[3]

        if resource == "policies":
            self._json(200, _delete_policy_by_name(rid))

        elif resource == "credentials":
            cred_file = BASE_DIR / "config" / "credentials" / f"{rid}.json"
            if cred_file.exists():
                cred_file.unlink()
                self._json(200, {"success": True, "message": f"Credential '{rid}' deleted."})
            else:
                self._json(404, {"error": f"Credential '{rid}' not found."})

        else:
            self._json(404, {"error": "Not found"})


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------

class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


def _setup_logging() -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt     = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s — %(message)s")
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=3
    )
    handler.setFormatter(fmt)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    root.addHandler(console)


def main() -> None:
    global _config_path
    parser = argparse.ArgumentParser(description="Yeyland Wutani Risk Scanner REST API")
    parser.add_argument("--port",   type=int, default=DEFAULT_PORT,
                        help=f"Listening port (default {DEFAULT_PORT})")
    parser.add_argument("--host",   default="0.0.0.0",
                        help="Bind address (default 0.0.0.0)")
    parser.add_argument("--config", default=str(_config_path),
                        help="Path to config.json")
    args = parser.parse_args()

    _config_path = Path(args.config)

    _setup_logging()
    logger.info(f"Risk Scanner REST API v{SCANNER_VERSION} starting on {args.host}:{args.port}")

    server = _ThreadedTCPServer((args.host, args.port), APIHandler)
    print(f"REST API running at http://{args.host}:{args.port}/api/{API_VERSION}/")
    logger.info("REST API ready.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("REST API shutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
