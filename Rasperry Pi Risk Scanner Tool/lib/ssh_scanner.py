#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
ssh_scanner.py - Credentialed SSH Host Interrogation

Connects via paramiko (SSH) and collects OS info, installed packages,
running services, SSH config audit, login history, and patch status.
All passwords/keys are masked in log output.
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

_CMD_TIMEOUT = 15  # seconds per command
_CONNECT_TIMEOUT = 15

# Mask pattern for log sanitization
_MASK = "***"


def scan_host_ssh(ip: str, credential_profile: dict) -> dict:
    """
    Perform credentialed SSH scan of a Linux/Unix host.
    Returns dict with collected OS info, packages, services, config, etc.
    Partial results are acceptable — skips and continues on command error.
    """
    result = {
        "ip": ip,
        "ssh_success": False,
        "os_version": None,
        "kernel_version": None,
        "distro": None,
        "installed_packages": [],
        "running_services": [],
        "listening_ports": [],
        "ssh_config_audit": {},
        "user_accounts": [],
        "patch_status": {},
        "cron_entries": [],
        "world_writable_tmp": [],
        "error": None,
    }

    username = credential_profile.get("username", "")
    password = credential_profile.get("password", "")
    key_path = credential_profile.get("ssh_key_path")

    masked_cred = f"user={username} key={'yes' if key_path else 'no'} pass={'set' if password else 'no'}"
    logger.info(f"SSH scan: {ip} ({masked_cred})")

    try:
        import paramiko
    except ImportError:
        logger.error("paramiko not installed — SSH scan unavailable")
        result["error"] = "paramiko not installed"
        return result

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs = {
            "hostname": ip,
            "username": username,
            "timeout": _CONNECT_TIMEOUT,
            "allow_agent": False,
            "look_for_keys": False,
            "banner_timeout": 30,
        }
        if key_path:
            connect_kwargs["key_filename"] = key_path
        else:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        result["ssh_success"] = True
        logger.info(f"SSH connected: {ip}")

    except Exception as e:
        err = str(e)
        # Mask any credentials that might appear in exception messages
        err = err.replace(password or "__no_pass__", _MASK)
        logger.warning(f"SSH connect failed: {ip} — {err}")
        result["error"] = f"Connection failed: {err}"
        return result

    def run_cmd(cmd: str) -> Optional[str]:
        """Run a command, return stdout or None on error."""
        try:
            _, stdout, stderr = client.exec_command(cmd, timeout=_CMD_TIMEOUT)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            return out if out else None
        except Exception as e:
            logger.debug(f"SSH cmd failed on {ip}: {cmd[:50]}... — {e}")
            return None

    try:
        # ── OS / kernel / distro ──────────────────────────────────────────
        uname = run_cmd("uname -r")
        if uname:
            result["kernel_version"] = uname

        os_release = run_cmd("cat /etc/os-release 2>/dev/null")
        if os_release:
            for line in os_release.splitlines():
                if line.startswith("PRETTY_NAME="):
                    result["os_version"] = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("ID="):
                    result["distro"] = line.split("=", 1)[1].strip().strip('"')

        uname_a = run_cmd("uname -a")
        if uname_a and not result["os_version"]:
            result["os_version"] = uname_a

        # ── Installed packages ────────────────────────────────────────────
        packages = []

        # Try dpkg (Debian/Ubuntu/Raspbian)
        dpkg_out = run_cmd("dpkg -l 2>/dev/null | awk '/^ii/{print $2, $3}' | head -500")
        if dpkg_out:
            for line in dpkg_out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    packages.append({"name": parts[0], "version": parts[1]})
        else:
            # Try rpm (RHEL/CentOS/Fedora)
            rpm_out = run_cmd("rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | head -500")
            if rpm_out:
                for line in rpm_out.splitlines():
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        packages.append({"name": parts[0], "version": parts[1]})
            else:
                # Try apk (Alpine)
                apk_out = run_cmd("apk list --installed 2>/dev/null | head -200")
                if apk_out:
                    for line in apk_out.splitlines():
                        m = re.match(r"^(\S+)-(\S+)\s", line)
                        if m:
                            packages.append({"name": m.group(1), "version": m.group(2)})

        result["installed_packages"] = packages

        # ── Running services ──────────────────────────────────────────────
        services = []
        systemctl_out = run_cmd(
            "systemctl list-units --state=running --no-pager --no-legend 2>/dev/null "
            "| awk '{print $1}' | grep '\\.service$' | head -100"
        )
        if systemctl_out:
            services = [s.replace(".service", "") for s in systemctl_out.splitlines() if s]
        else:
            # Fallback: ps
            ps_out = run_cmd("ps aux --no-header 2>/dev/null | awk '{print $11}' | sort -u | head -100")
            if ps_out:
                services = [s.split("/")[-1] for s in ps_out.splitlines() if s and not s.startswith("-")]

        result["running_services"] = services[:100]

        # ── Listening ports ───────────────────────────────────────────────
        ss_out = run_cmd("ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | grep -oP ':\\K[0-9]+' | sort -un | head -100")
        if ss_out:
            result["listening_ports"] = [int(p) for p in ss_out.splitlines() if p.isdigit()]

        # ── SSH config audit ──────────────────────────────────────────────
        sshd_conf = run_cmd("cat /etc/ssh/sshd_config 2>/dev/null")
        audit = {
            "permit_root_login": False,
            "password_auth": False,
            "weak_ciphers": [],
            "protocol_v1": False,
        }
        if sshd_conf:
            for line in sshd_conf.splitlines():
                line_stripped = line.strip()
                if line_stripped.startswith("#"):
                    continue
                lower = line_stripped.lower()
                if lower.startswith("permitrootlogin") and "yes" in lower:
                    audit["permit_root_login"] = True
                elif lower.startswith("passwordauthentication") and "yes" in lower:
                    audit["password_auth"] = True
                elif lower.startswith("protocol") and "1" in lower:
                    audit["protocol_v1"] = True
                elif lower.startswith("ciphers"):
                    weak = [c for c in ["arcfour", "3des", "blowfish", "rc4"] if c in lower]
                    audit["weak_ciphers"] = weak
        result["ssh_config_audit"] = audit

        # ── Recent logins ─────────────────────────────────────────────────
        last_out = run_cmd("last -n 20 2>/dev/null | head -20")
        if last_out:
            logins = []
            for line in last_out.splitlines():
                if line.startswith("reboot") or line.startswith("wtmp") or not line.strip():
                    continue
                parts = line.split()
                if parts:
                    logins.append({"username": parts[0], "raw": line[:80]})
            result["user_accounts"] = logins

        # ── Non-system local users ────────────────────────────────────────
        users_out = run_cmd("awk -F: '($3 >= 1000) && ($3 < 65534) {print $1}' /etc/passwd 2>/dev/null")
        if users_out:
            local_users = [{"username": u, "last_login": None} for u in users_out.splitlines() if u]
            if local_users:
                result["user_accounts"] = local_users

        # ── Patch status ──────────────────────────────────────────────────
        pending = None
        update_manager = None

        # apt (Debian/Ubuntu)
        apt_out = run_cmd("apt list --upgradable 2>/dev/null | grep -c upgradable || true")
        if apt_out and apt_out.isdigit():
            pending = max(0, int(apt_out) - 1)  # subtract header line
            update_manager = "apt"
        else:
            # yum/dnf
            yum_out = run_cmd("yum check-update --quiet 2>/dev/null | grep -c '^[a-zA-Z]' || true")
            if yum_out and yum_out.isdigit():
                pending = int(yum_out)
                update_manager = "yum"
            else:
                # apk
                apk_update_out = run_cmd("apk version 2>/dev/null | grep -c '<' || true")
                if apk_update_out and apk_update_out.isdigit():
                    pending = int(apk_update_out)
                    update_manager = "apk"

        # Last update timestamp
        last_update = None
        apt_history = run_cmd("stat -c %y /var/lib/apt/periodic/update-success-stamp 2>/dev/null | cut -d' ' -f1")
        if apt_history:
            last_update = apt_history
        else:
            rpm_log = run_cmd("rpm -qa --last 2>/dev/null | head -1 | awk '{print $3,$4,$5}'")
            if rpm_log:
                last_update = rpm_log

        days_since = None
        if last_update:
            try:
                from datetime import datetime as _dt
                import re as _re
                date_str = _re.sub(r'\s+', ' ', last_update).strip()
                dt = _dt.strptime(date_str, "%Y-%m-%d")
                days_since = (_dt.now() - dt).days
            except Exception:
                pass

        result["patch_status"] = {
            "last_update": last_update,
            "pending_updates": pending,
            "days_since_update": days_since,
            "update_manager": update_manager,
        }

        # ── Cron entries (suspicious check) ──────────────────────────────
        cron_out = run_cmd("ls /etc/cron.d/ 2>/dev/null")
        if cron_out:
            result["cron_entries"] = cron_out.splitlines()[:20]

        # ── World-writable temp dirs ──────────────────────────────────────
        ww_out = run_cmd(
            "find /tmp /var/tmp -perm -0002 -maxdepth 1 2>/dev/null | head -20"
        )
        if ww_out:
            result["world_writable_tmp"] = ww_out.splitlines()

        logger.info(
            f"SSH scan complete: {ip} — "
            f"OS: {result['os_version'] or 'unknown'}, "
            f"{len(result['installed_packages'])} packages, "
            f"{len(result['running_services'])} services"
        )

    except Exception as e:
        logger.warning(f"SSH scan error on {ip}: {e}")
        result["error"] = str(e)
    finally:
        try:
            client.close()
        except Exception:
            pass

    return result
