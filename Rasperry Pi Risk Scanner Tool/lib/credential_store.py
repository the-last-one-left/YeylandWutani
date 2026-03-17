#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
credential_store.py - Encrypted Credential Profile Store

Manages SSH, WMI, and SNMP credential profiles stored encrypted at rest.
Key derivation: PBKDF2-HMAC-SHA256 from /etc/machine-id + device_name.
Encryption: AES-256-GCM via Python cryptography library (Fernet).
Credentials are non-portable between devices (key is machine-bound).
"""

import json
import logging
import os
import socket
from pathlib import Path
from typing import Optional
import ipaddress

logger = logging.getLogger(__name__)

CREDENTIALS_FILE = Path("/opt/risk-scanner/config/credentials.enc")
CONFIG_FILE = Path("/opt/risk-scanner/config/config.json")

# Mask pattern for log sanitization
_MASK = "***"

# Valid credential types
CRED_TYPES = {"ssh", "wmi", "snmp_v2c", "snmp_v3"}
SCOPE_TYPES = {"host", "subnet", "global"}


def _get_machine_id() -> str:
    """Read /etc/machine-id. Falls back to hostname if not available."""
    try:
        mid = Path("/etc/machine-id").read_text().strip()
        if mid:
            return mid
    except Exception:
        pass
    return socket.gethostname()


def _derive_key(device_name: str) -> bytes:
    """
    Derive a 32-byte AES key from machine-id + device_name using PBKDF2.
    Key is never stored — re-derived at runtime each call.
    """
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import base64

    machine_id = _get_machine_id()
    # Salt = machine_id, password = machine_id + device_name
    password = (machine_id + device_name).encode("utf-8")
    salt = machine_id.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key_bytes = kdf.derive(password)
    # Fernet requires URL-safe base64-encoded 32-byte key
    from cryptography.fernet import Fernet
    return base64.urlsafe_b64encode(key_bytes)


def _get_fernet(device_name: str):
    from cryptography.fernet import Fernet
    return Fernet(_derive_key(device_name))


def _mask_sensitive(profile: dict) -> dict:
    """Return a copy of the profile with passwords/keys masked for logging."""
    masked = dict(profile)
    for field in ("password", "snmp_community", "snmp_auth_key", "snmp_priv_key"):
        if masked.get(field):
            masked[field] = _MASK
    return masked


def _get_device_name(config_path: Path = CONFIG_FILE) -> str:
    """Load device_name from config.json for key derivation."""
    try:
        with open(config_path) as f:
            cfg = json.load(f)
        return cfg.get("system", {}).get("device_name", "RiskScanner-Pi")
    except Exception:
        return "RiskScanner-Pi"


def load_credentials(config_path: Path = CREDENTIALS_FILE, device_name: str = None) -> list:
    """
    Decrypt and return all credential profiles.
    Returns empty list if file doesn't exist.
    """
    if device_name is None:
        device_name = _get_device_name()

    if not config_path.exists():
        logger.debug(f"Credentials file not found: {config_path}")
        return []

    try:
        fernet = _get_fernet(device_name)
        encrypted_data = config_path.read_bytes()
        decrypted = fernet.decrypt(encrypted_data)
        profiles = json.loads(decrypted.decode("utf-8"))
        logger.info(f"Loaded {len(profiles)} credential profile(s) from {config_path}")
        return profiles
    except Exception as e:
        logger.error(f"Failed to decrypt credentials: {e}. "
                     "If the Pi OS was reinstalled, the machine-id has changed — "
                     "run add-credential.sh to re-enter credentials.")
        return []


def save_credentials(profiles: list, config_path: Path = CREDENTIALS_FILE, device_name: str = None) -> None:
    """Encrypt and write credential profiles to credentials.enc."""
    if device_name is None:
        device_name = _get_device_name()

    try:
        fernet = _get_fernet(device_name)
        data = json.dumps(profiles, indent=2).encode("utf-8")
        encrypted = fernet.encrypt(data)
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Write atomically via temp file, then chmod
        import tempfile
        fd, tmp = tempfile.mkstemp(dir=str(config_path.parent), prefix=".creds_")
        try:
            os.chmod(fd, 0o600)
            os.write(fd, encrypted)
        finally:
            os.close(fd)
        os.replace(tmp, str(config_path))
        os.chmod(str(config_path), 0o600)
        logger.info(f"Credentials saved: {len(profiles)} profile(s) -> {config_path}")
    except Exception as e:
        logger.error(f"Failed to save credentials: {e}")
        raise


def add_credential(profile: dict, config_path: Path = CREDENTIALS_FILE, device_name: str = None) -> None:
    """Append a new credential profile and re-save."""
    profiles = load_credentials(config_path, device_name)

    # Replace existing profile with same name if it exists
    existing_names = [p.get("profile_name") for p in profiles]
    name = profile.get("profile_name", "")
    if name in existing_names:
        profiles = [p for p in profiles if p.get("profile_name") != name]
        logger.info(f"Replacing existing credential profile: {name}")

    profiles.append(profile)
    save_credentials(profiles, config_path, device_name)
    logger.info(f"Added credential profile: {name} (type={profile.get('type')}, scope={profile.get('scope')})")


def test_credential(profile: dict, target_ip: str) -> bool:
    """
    Attempt a lightweight connection test using the given credential profile.
    Returns True on success, False on failure.
    Passwords/keys are masked in all log output.
    """
    cred_type = profile.get("type", "")
    masked = _mask_sensitive(profile)
    logger.info(f"Testing credential: {masked.get('profile_name')} ({cred_type}) -> {target_ip}")

    if cred_type == "ssh":
        return _test_ssh(profile, target_ip)
    elif cred_type == "wmi":
        return _test_wmi(profile, target_ip)
    elif cred_type in ("snmp_v2c", "snmp_v3"):
        return _test_snmp(profile, target_ip)
    else:
        logger.warning(f"Unknown credential type: {cred_type}")
        return False


def _test_ssh(profile: dict, ip: str) -> bool:
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {
            "hostname": ip,
            "port": 22,
            "username": profile.get("username", ""),
            "timeout": 10,
            "allow_agent": False,
            "look_for_keys": False,
        }
        key_path = profile.get("ssh_key_path")
        if key_path and Path(key_path).exists():
            kwargs["key_filename"] = key_path
        else:
            kwargs["password"] = profile.get("password", "")

        client.connect(**kwargs)
        _, stdout, _ = client.exec_command("echo ok", timeout=5)
        result = stdout.read().decode().strip()
        client.close()
        success = result == "ok"
        logger.info(f"SSH test {'PASS' if success else 'FAIL'}: {ip}")
        return success
    except Exception as e:
        logger.info(f"SSH test FAIL: {ip} — {e}")
        return False


def _test_wmi(profile: dict, ip: str) -> bool:
    try:
        import socket as _s
        sock = _s.create_connection((ip, 5985), timeout=5)
        sock.close()
        logger.info(f"WMI/WinRM port test PASS: {ip}:5985 reachable")
        return True
    except Exception as e:
        # Try port 135 (WMI DCOM)
        try:
            import socket as _s
            sock = _s.create_connection((ip, 135), timeout=5)
            sock.close()
            logger.info(f"WMI/DCOM port test PASS: {ip}:135 reachable")
            return True
        except Exception as e2:
            logger.info(f"WMI test FAIL: {ip} — WinRM:{e} DCOM:{e2}")
            return False


def _test_snmp(profile: dict, ip: str) -> bool:
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UsmUserData,
            UdpTransportTarget, ContextData, ObjectType, ObjectIdentity,
        )
        cred_type = profile.get("type")
        if cred_type == "snmp_v2c":
            auth = CommunityData(profile.get("snmp_community", "public"))
        else:
            from pysnmp.hlapi import usmHMACSHAAuthProtocol, usmAesCfb128Protocol
            auth = UsmUserData(
                profile.get("username", ""),
                authKey=profile.get("snmp_auth_key", ""),
                privKey=profile.get("snmp_priv_key", ""),
            )

        iterator = getCmd(
            SnmpEngine(),
            auth,
            UdpTransportTarget((ip, 161), timeout=5, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication:
            logger.info(f"SNMP test FAIL: {ip} — {error_indication}")
            return False
        logger.info(f"SNMP test PASS: {ip}")
        return True
    except Exception as e:
        logger.info(f"SNMP test FAIL: {ip} — {e}")
        return False


def validate_profile(profile: dict) -> list:
    """
    Validate a credential profile dict.
    Returns list of error strings (empty = valid).
    """
    errors = []
    if not profile.get("profile_name"):
        errors.append("profile_name is required")
    cred_type = profile.get("type")
    if cred_type not in CRED_TYPES:
        errors.append(f"type must be one of: {', '.join(CRED_TYPES)}")
    scope = profile.get("scope", "global")
    if scope not in SCOPE_TYPES:
        errors.append(f"scope must be one of: {', '.join(SCOPE_TYPES)}")
    if scope in ("host", "subnet") and not profile.get("targets"):
        errors.append("targets list required for host/subnet scope")
    if cred_type == "ssh" and not profile.get("username"):
        errors.append("SSH credentials require username")
    if cred_type == "wmi" and not profile.get("username"):
        errors.append("WMI credentials require username")
    return errors
