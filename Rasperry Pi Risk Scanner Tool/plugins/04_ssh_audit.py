#!/usr/bin/env python3
"""
Plugin: SSH Credentialed Audit  (Phase 4)
Connect to each live host via SSH and run a credentialed software/patch audit.
"""

from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))

from plugin_base import ScanPlugin, PluginContext, CAT_SSH

log = logging.getLogger("plugin.ssh_audit")

# SSH port candidates (try in order)
_SSH_PORTS = [22, 2222, 22000]


def _find_cred_for_host(ip: str, credentials: list) -> dict | None:
    """Return the first SSH credential that targets this host (or a wildcard)."""
    # 1. Exact host match
    for cred in credentials:
        if cred.get("type") != "ssh":
            continue
        hosts = cred.get("hosts", [])
        if ip in hosts:
            return cred
    # 2. Wildcard / global credential
    for cred in credentials:
        if cred.get("type") != "ssh":
            continue
        hosts = cred.get("hosts", [])
        if not hosts or "*" in hosts:
            return cred
    return None


def _ssh_connect(ip: str, port: int, cred: dict, timeout: int = 20):
    """Attempt SSH connection; return (client, port) or (None, None)."""
    try:
        import paramiko
    except ImportError:
        log.error("paramiko not installed. Run: pip install paramiko")
        return None, None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        username   = cred.get("username", "root")
        password   = cred.get("password", "")
        key_path   = cred.get("key_path", "")
        passphrase = cred.get("passphrase", "")

        connect_kwargs: dict = {
            "hostname":          ip,
            "port":              port,
            "username":          username,
            "timeout":           timeout,
            "look_for_keys":     bool(key_path),
            "allow_agent":       False,
            "banner_timeout":    timeout,
            "auth_timeout":      timeout,
        }
        if key_path and Path(key_path).exists():
            pkey = paramiko.RSAKey.from_private_key_file(
                key_path, password=passphrase or None
            )
            connect_kwargs["pkey"] = pkey
        elif password:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        return client, port
    except Exception:
        client.close()
        return None, None


def _run_command(client, cmd: str) -> str:
    """Run a command on an SSH client and return stdout."""
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=30)
        return stdout.read().decode(errors="replace").strip()
    except Exception:
        return ""


def _audit_host(host: dict, cred: dict, timeout: int) -> dict:
    """Perform a credentialed SSH audit, return an ssh result dict."""
    ip = host["ip"]
    result: dict = {
        "success":        False,
        "port":           None,
        "username":       cred.get("username", ""),
        "os_info":        {},
        "packages":       [],
        "patch_level":    "",
        "users":          [],
        "sudoers":        [],
        "sshd_config":    {},
        "listening_ports": [],
        "cron_jobs":      [],
        "world_writable": [],
        "errors":         [],
    }

    client = None
    for port in _SSH_PORTS:
        # Only try port if it appears in discovered open ports (or no port data yet)
        open_ports = [p["port"] for p in host.get("ports", [])]
        if open_ports and port not in open_ports:
            continue
        client, used_port = _ssh_connect(ip, port, cred, timeout)
        if client:
            result["port"] = used_port
            break

    if client is None:
        log.debug(f"{ip}: SSH connection failed with credential '{cred.get('name', '?')}'")
        return result

    try:
        result["success"] = True

        # ── OS info ─────────────────────────────────────────────────────
        uname = _run_command(client, "uname -a")
        os_release = _run_command(client, "cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null")
        result["os_info"] = {"uname": uname, "os_release": os_release}

        # ── Kernel + patch level ───────────────────────────────────────────
        kernel = _run_command(client, "uname -r")
        result["patch_level"] = kernel

        # ── Installed packages (apt / rpm / apk) ───────────────────────────
        pkgs_raw = _run_command(
            client,
            "dpkg-query -W -f '${Package} ${Version}\n' 2>/dev/null "
            "|| rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null "
            "|| apk info -v 2>/dev/null",
        )
        packages = []
        for line in pkgs_raw.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                packages.append({"name": parts[0], "version": parts[1]})
            elif len(parts) == 1:
                packages.append({"name": parts[0], "version": ""})
        result["packages"] = packages[:2000]  # cap to avoid huge payloads

        # ── Local users ───────────────────────────────────────────────────────
        users_raw = _run_command(
            client, "getent passwd | awk -F: '{print $1, $3, $6, $7}'"
        )
        users = []
        for line in users_raw.splitlines():
            parts = line.strip().split(None, 3)
            if parts:
                users.append({
                    "username": parts[0] if len(parts) > 0 else "",
                    "uid":      parts[1] if len(parts) > 1 else "",
                    "home":     parts[2] if len(parts) > 2 else "",
                    "shell":    parts[3] if len(parts) > 3 else "",
                })
        result["users"] = users

        # ── Sudo rules ───────────────────────────────────────────────────────
        sudoers_raw = _run_command(
            client, "sudo cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'"
        )
        result["sudoers"] = sudoers_raw.splitlines()

        # ── sshd config highlights ───────────────────────────────────────────
        sshd_raw = _run_command(
            client, "sshd -T 2>/dev/null | grep -iE 'permitrootlogin|passwordauthentication|pubkeyauthentication|protocol|port|x11forwarding|permitemptypasswords'"
        )
        sshd_cfg: dict = {}
        for line in sshd_raw.splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                sshd_cfg[parts[0].lower()] = parts[1].strip()
        result["sshd_config"] = sshd_cfg

        # ── Listening ports ───────────────────────────────────────────────────
        lp_raw = _run_command(
            client,
            "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null",
        )
        result["listening_ports"] = [l for l in lp_raw.splitlines() if l.strip()]

        # ── World-writable files (limited scope) ────────────────────────────
        ww_raw = _run_command(
            client,
            "find /etc /usr /var -maxdepth 4 -type f -perm -o+w 2>/dev/null | head -50",
        )
        result["world_writable"] = [f for f in ww_raw.splitlines() if f.strip()]

    finally:
        client.close()

    log.debug(
        f"{ip}: SSH audit done — {len(result['packages'])} packages, "
        f"{len(result['users'])} users, {len(result['listening_ports'])} listening ports"
    )
    return result


class SSHAuditPlugin(ScanPlugin):
    plugin_id    = "ssh_audit"
    name         = "SSH Credentialed Audit"
    category     = CAT_SSH
    phase        = 4
    description  = (
        "Authenticate to each live host via SSH and collect installed packages, "
        "users, sshd config, listening ports and world-writable files."
    )
    version      = "1.0.0"
    author       = "AWN"
    requires     = ["host_discovery"]

    def run(self, ctx: PluginContext) -> None:
        if not ctx.hosts:
            log.warning("No hosts to audit — skipping SSH audit.")
            return

        scan_cfg  = ctx.config.get("scan", {})
        timeout   = int(ctx.get_policy_value("timeout_per_host", scan_cfg.get("host_timeout", 20)))
        parallel  = int(ctx.get_policy_value("max_parallel", scan_cfg.get("max_parallel_hosts", 10)))

        host_index = {h["ip"]: h for h in ctx.hosts}

        def _try_host(host: dict):
            ip   = host["ip"]
            cred = _find_cred_for_host(ip, ctx.credentials)
            if cred is None:
                log.debug(f"{ip}: No SSH credential available.")
                ctx.coverage["no_credential"].append(ip)
                return
            result = _audit_host(host, cred, timeout)
            host["ssh"] = result
            if result["success"]:
                ctx.coverage["ssh_success"].append(ip)
            else:
                ctx.coverage["ssh_failed"].append(ip)

        with ThreadPoolExecutor(max_workers=parallel) as ex:
            futures = {ex.submit(_try_host, h): h["ip"] for h in ctx.hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    fut.result()
                except Exception as exc:
                    log.error(f"SSH audit future error for {ip}: {exc}")

        ctx.sync_hosts()
        success = len(ctx.coverage["ssh_success"])
        failed  = len(ctx.coverage["ssh_failed"])
        no_cred = len(ctx.coverage["no_credential"])
        log.info(
            f"SSH audit complete: {success} success, {failed} failed, {no_cred} no-credential."
        )
