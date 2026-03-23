#!/usr/bin/env python3
"""
Yeyland Wutani - Risk Scanner Tool
lib/vault_provider.py  --  PAM / Secrets Vault Integration

Supports fetching scan credentials at runtime from:
  - HashiCorp Vault  (KV v1/v2, AppRole + Token auth)
  - CyberArk Central Credential Provider (CCP REST API)
  - Azure Key Vault   (client-credentials OAuth2)

Credentials are NEVER cached to disk; they live only in memory for the
duration of a single scan run.

Configuration  (in config.json under ["vault"])
------------------------------------------------
  enabled        bool    Master on/off switch
  provider       str     "hashicorp" | "cyberark" | "azure_keyvault"
  url            str     Vault base URL
  tls_verify     bool    Verify TLS certificate (default True)
  timeout        int     HTTP timeout in seconds (default 15)

  HashiCorp-specific:
    auth_method    str    "token" | "approle"
    token          str    Vault token (auth_method=token)
    role_id        str    AppRole role_id
    secret_id      str    AppRole secret_id  (or set env VAULT_SECRET_ID)
    mount          str    KV secrets mount path (default "secret")
    kv_version     int    1 or 2 (default 2)
    paths          list   List of secret paths to fetch credentials from

  CyberArk-specific:
    app_id         str    CyberArk Application ID
    safe           str    Safe name
    objects        list   List of object names to retrieve
    cert_path      str    Path to client certificate .pem (optional)
    key_path       str    Path to client key .pem (optional)

  Azure Key Vault-specific:
    vault_name     str    Azure Key Vault name
    tenant_id      str    Azure AD tenant ID
    client_id      str    Service principal client ID
    client_secret  str    Service principal secret (or env AZURE_CLIENT_SECRET)
    secrets        list   List of secret names to fetch
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import Any

logger = logging.getLogger(__name__)

# Supported credential types produced by vault providers
_CRED_TYPE_MAP = {
    "ssh":      "ssh",
    "winrm":    "wmi",
    "wmi":      "wmi",
    "snmp":     "snmp",
    "snmp_v2c": "snmp",
    "snmp_v3":  "snmp",
}


def _http_get(url: str, headers: dict, tls_verify: bool = True, timeout: int = 15) -> dict:
    """Make a simple HTTPS GET and return parsed JSON."""
    ctx = ssl.create_default_context()
    if not tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode())


def _http_post(url: str, payload: dict, headers: dict, tls_verify: bool = True, timeout: int = 15) -> dict:
    """Make a simple HTTPS POST and return parsed JSON."""
    ctx = ssl.create_default_context()
    if not tls_verify:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", **headers}
    req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# HashiCorp Vault
# ---------------------------------------------------------------------------

class HashiCorpVaultProvider:
    """
    Fetch credentials from HashiCorp Vault KV secrets engine.

    Each secret path is expected to contain a flat key=value map that
    includes at minimum:
      type      ssh | wmi | snmp
      username  (ssh / wmi)
      password  (ssh / wmi / snmp community)
    Optional fields:
      key_path, passphrase, hosts, domain, snmp_version, port, notes
    """

    def __init__(self, cfg: dict) -> None:
        self.url        = cfg["url"].rstrip("/")
        self.auth_method = cfg.get("auth_method", "token")
        self.token      = cfg.get("token", "") or os.environ.get("VAULT_TOKEN", "")
        self.role_id    = cfg.get("role_id", "")
        self.secret_id  = cfg.get("secret_id", "") or os.environ.get("VAULT_SECRET_ID", "")
        self.mount      = cfg.get("mount", "secret")
        self.kv_version = int(cfg.get("kv_version", 2))
        self.paths      = cfg.get("paths", [])
        self.tls_verify = cfg.get("tls_verify", True)
        self.timeout    = int(cfg.get("timeout", 15))
        self._vault_token: str | None = None

    def _authenticate(self) -> str:
        """Return a Vault token, authenticating via AppRole if needed."""
        if self.auth_method == "token":
            if not self.token:
                raise ValueError("Vault token not configured (set config vault.token or VAULT_TOKEN env)")
            return self.token

        # AppRole authentication
        if not self.role_id or not self.secret_id:
            raise ValueError("AppRole requires role_id and secret_id")
        resp = _http_post(
            f"{self.url}/v1/auth/approle/login",
            payload={"role_id": self.role_id, "secret_id": self.secret_id},
            headers={},
            tls_verify=self.tls_verify,
            timeout=self.timeout,
        )
        token = resp.get("auth", {}).get("client_token", "")
        if not token:
            raise ValueError("AppRole authentication failed: no client_token in response")
        logger.info("HashiCorp Vault: AppRole authentication successful")
        return token

    def _read_secret(self, vault_token: str, path: str) -> dict:
        """Read a single KV secret and return the data dict."""
        if self.kv_version == 2:
            url = f"{self.url}/v1/{self.mount}/data/{path.lstrip('/')}"
        else:
            url = f"{self.url}/v1/{self.mount}/{path.lstrip('/')}"

        resp = _http_get(
            url,
            headers={"X-Vault-Token": vault_token},
            tls_verify=self.tls_verify,
            timeout=self.timeout,
        )
        if self.kv_version == 2:
            return resp.get("data", {}).get("data", {})
        return resp.get("data", {})

    def fetch_credentials(self) -> list[dict]:
        """Authenticate and fetch all configured secret paths. Return list of credential profiles."""
        if not self.paths:
            logger.warning("HashiCorp Vault: no paths configured under vault.paths")
            return []

        try:
            vault_token = self._authenticate()
        except Exception as exc:
            logger.error(f"HashiCorp Vault authentication failed: {exc}")
            return []

        credentials: list[dict] = []
        for path in self.paths:
            try:
                secret = self._read_secret(vault_token, path)
                if not secret:
                    logger.warning(f"HashiCorp Vault: empty secret at path '{path}'")
                    continue
                cred = _normalise_credential(secret, source=f"vault:{path}")
                if cred:
                    credentials.append(cred)
                    logger.info(f"HashiCorp Vault: loaded credential '{cred.get('name')}' from '{path}'")
            except Exception as exc:
                logger.error(f"HashiCorp Vault: failed to read path '{path}': {exc}")

        return credentials


# ---------------------------------------------------------------------------
# CyberArk CCP
# ---------------------------------------------------------------------------

class CyberArkProvider:
    """
    Fetch credentials from CyberArk Central Credential Provider (CCP) REST API.

    The CCP is queried per object name. The response JSON contains:
      UserName, Content (password), Address, etc.

    See: https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/CCP/Retrieve-Credentials.htm
    """

    def __init__(self, cfg: dict) -> None:
        self.url        = cfg["url"].rstrip("/")
        self.app_id     = cfg["app_id"]
        self.safe       = cfg.get("safe", "")
        self.objects    = cfg.get("objects", [])
        self.cert_path  = cfg.get("cert_path", "")
        self.key_path   = cfg.get("key_path", "")
        self.tls_verify = cfg.get("tls_verify", True)
        self.timeout    = int(cfg.get("timeout", 15))

    def _get_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        if self.cert_path and self.key_path:
            ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)
        return ctx

    def _fetch_object(self, object_name: str) -> dict:
        params = urllib.parse.urlencode({
            "AppID":  self.app_id,
            "Safe":   self.safe,
            "Object": object_name,
        })
        url = f"{self.url}/AIMWebService/api/Accounts?{params}"
        ctx = self._get_ssl_context()
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
            return json.loads(resp.read().decode())

    def fetch_credentials(self) -> list[dict]:
        if not self.objects:
            logger.warning("CyberArk: no objects configured under vault.objects")
            return []

        credentials: list[dict] = []
        for obj in self.objects:
            try:
                resp = self._fetch_object(obj)
                # Map CyberArk fields to AWN credential profile
                raw = {
                    "name":     obj,
                    "type":     resp.get("PlatformId", "ssh").lower(),
                    "username": resp.get("UserName", ""),
                    "password": resp.get("Content", ""),
                    "hosts":    [resp.get("Address", "*")] if resp.get("Address") else ["*"],
                }
                cred = _normalise_credential(raw, source=f"cyberark:{obj}")
                if cred:
                    credentials.append(cred)
                    logger.info(f"CyberArk: loaded credential '{obj}'")
            except Exception as exc:
                logger.error(f"CyberArk: failed to fetch object '{obj}': {exc}")

        return credentials


# ---------------------------------------------------------------------------
# Azure Key Vault
# ---------------------------------------------------------------------------

class AzureKeyVaultProvider:
    """
    Fetch credentials from Azure Key Vault using service principal auth.

    Each secret should be a JSON string with the same fields as a
    standard AWN credential profile, OR a simple password string.
    """

    _TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    _AKV_URL   = "https://{vault_name}.vault.azure.net/secrets/{secret}?api-version=7.4"

    def __init__(self, cfg: dict) -> None:
        self.vault_name    = cfg["vault_name"]
        self.tenant_id     = cfg["tenant_id"]
        self.client_id     = cfg["client_id"]
        self.client_secret = cfg.get("client_secret", "") or os.environ.get("AZURE_CLIENT_SECRET", "")
        self.secrets       = cfg.get("secrets", [])
        self.tls_verify    = cfg.get("tls_verify", True)
        self.timeout       = int(cfg.get("timeout", 15))
        self._access_token: str | None = None

    def _get_token(self) -> str:
        if not self.client_secret:
            raise ValueError("Azure Key Vault: client_secret not set (or set AZURE_CLIENT_SECRET env)")
        url  = self._TOKEN_URL.format(tenant_id=self.tenant_id)
        data = urllib.parse.urlencode({
            "grant_type":    "client_credentials",
            "client_id":     self.client_id,
            "client_secret": self.client_secret,
            "scope":         "https://vault.azure.net/.default",
        }).encode()
        ctx = ssl.create_default_context()
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        req  = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
            token = json.loads(resp.read().decode()).get("access_token", "")
        if not token:
            raise ValueError("Azure Key Vault: failed to obtain access token")
        logger.info("Azure Key Vault: OAuth2 token obtained")
        return token

    def _get_secret(self, token: str, secret_name: str) -> str:
        url = self._AKV_URL.format(vault_name=self.vault_name, secret=secret_name)
        ctx = ssl.create_default_context()
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
            return json.loads(resp.read().decode()).get("value", "")

    def fetch_credentials(self) -> list[dict]:
        if not self.secrets:
            logger.warning("Azure Key Vault: no secrets configured under vault.secrets")
            return []

        try:
            token = self._get_token()
        except Exception as exc:
            logger.error(f"Azure Key Vault auth failed: {exc}")
            return []

        credentials: list[dict] = []
        for secret_name in self.secrets:
            try:
                value = self._get_secret(token, secret_name)
                if not value:
                    logger.warning(f"Azure Key Vault: empty secret '{secret_name}'")
                    continue
                # Try to parse as JSON credential object first
                try:
                    raw = json.loads(value)
                except json.JSONDecodeError:
                    # Treat the raw value as a password for an SSH credential
                    raw = {"name": secret_name, "type": "ssh", "password": value}
                cred = _normalise_credential(raw, source=f"azure:{secret_name}")
                if cred:
                    credentials.append(cred)
                    logger.info(f"Azure Key Vault: loaded credential '{secret_name}'")
            except Exception as exc:
                logger.error(f"Azure Key Vault: failed to fetch '{secret_name}': {exc}")

        return credentials


# ---------------------------------------------------------------------------
# Credential normalisation
# ---------------------------------------------------------------------------

def _normalise_credential(raw: dict, source: str = "vault") -> dict | None:
    """
    Map a raw key-value dict from any vault provider to a standard AWN
    credential profile dict.  Returns None if the result is unusable.
    """
    cred_type = _CRED_TYPE_MAP.get((raw.get("type") or "ssh").lower(), "ssh")
    name      = (raw.get("name") or raw.get("username") or source or "vault-cred").strip()

    cred: dict = {
        "name":     name,
        "type":     cred_type,
        "username": raw.get("username", ""),
        "password": raw.get("password", "") or raw.get("snmp_community", ""),
        "hosts":    raw.get("hosts", ["*"]),
        "source":   source,   # provenance tag — never stored to disk
    }

    # SSH-specific optional fields
    if cred_type == "ssh":
        for field in ("key_path", "passphrase", "port"):
            if raw.get(field):
                cred[field] = raw[field]

    # WMI-specific
    if cred_type == "wmi":
        for field in ("domain",):
            if raw.get(field):
                cred[field] = raw[field]

    # SNMP-specific
    if cred_type == "snmp":
        for field in ("snmp_version", "snmp_auth_protocol", "snmp_auth_key",
                      "snmp_priv_protocol", "snmp_priv_key"):
            if raw.get(field):
                cred[field] = raw[field]

    # Must have either username+password or a key_path
    if cred_type in ("ssh", "wmi") and not cred["username"]:
        logger.warning(f"Vault credential '{name}' has no username — skipping")
        return None

    return cred


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def fetch_vault_credentials(vault_cfg: dict) -> list[dict]:
    """
    Entry point: read the ["vault"] section of config.json and return
    a list of credential profile dicts ready for use in a PluginContext.

    Args:
        vault_cfg:  The config["vault"] dict.

    Returns:
        List of normalised credential dicts.  Empty list on any failure.
    """
    if not vault_cfg.get("enabled", False):
        return []

    provider_name = (vault_cfg.get("provider") or "").lower()

    try:
        if provider_name == "hashicorp":
            provider = HashiCorpVaultProvider(vault_cfg)
        elif provider_name == "cyberark":
            provider = CyberArkProvider(vault_cfg)
        elif provider_name in ("azure_keyvault", "azure"):
            provider = AzureKeyVaultProvider(vault_cfg)
        else:
            logger.error(f"Unknown vault provider: '{provider_name}'. "
                         f"Supported: hashicorp, cyberark, azure_keyvault")
            return []

        creds = provider.fetch_credentials()
        logger.info(
            f"Vault provider '{provider_name}': fetched {len(creds)} credential(s)"
        )
        return creds

    except Exception as exc:
        logger.error(f"Vault credential fetch failed ({provider_name}): {exc}")
        return []


def is_vault_enabled(config: dict) -> bool:
    """Quick check: is vault integration configured and enabled?"""
    return bool(config.get("vault", {}).get("enabled", False))
