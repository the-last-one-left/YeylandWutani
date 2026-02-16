#!/usr/bin/env python3
"""
Yeyland Wutani - Network Discovery Pi
graph_auth.py - Microsoft Graph API OAuth2 Authentication

Handles client credentials flow for headless Graph API access.
"""

import json
import logging
import os
import time
from pathlib import Path

import msal

logger = logging.getLogger(__name__)

# Token cache file location
TOKEN_CACHE_PATH = Path("/opt/network-discovery/data/.token_cache.json")

# Graph API scope for sending mail
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]


class GraphAuthError(Exception):
    """Raised when Graph API authentication fails."""
    pass


class GraphAuth:
    """
    Manages OAuth2 client credentials authentication with Microsoft Graph API.
    Supports token caching and automatic refresh.
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token_cache = msal.SerializableTokenCache()
        self._app = None
        logger.debug(
            f"GraphAuth initialized — tenant: {tenant_id[:8]}..., "
            f"client: {client_id[:8]}..."
        )
        self._load_token_cache()

    def _load_token_cache(self):
        """Load token cache from disk if it exists."""
        if TOKEN_CACHE_PATH.exists():
            try:
                self._token_cache.deserialize(TOKEN_CACHE_PATH.read_text())
                logger.debug("Token cache loaded from disk.")
            except Exception as e:
                logger.warning(f"Could not load token cache: {e}. Starting fresh.")

    def _save_token_cache(self):
        """Persist token cache to disk with restricted permissions."""
        try:
            TOKEN_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            TOKEN_CACHE_PATH.write_text(self._token_cache.serialize())
            TOKEN_CACHE_PATH.chmod(0o600)
            logger.debug("Token cache saved to disk.")
        except Exception as e:
            logger.warning(f"Could not save token cache: {e}")

    def _build_app(self):
        """Build the MSAL ConfidentialClientApplication."""
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self._app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=authority,
            token_cache=self._token_cache,
        )
        logger.debug(f"MSAL app built for tenant: {self.tenant_id}")

    def get_token(self) -> str:
        """
        Acquire an access token using client credentials flow.
        Returns the access token string.
        Raises GraphAuthError on failure.
        """
        if self._app is None:
            self._build_app()

        # Try to get token from cache first
        logger.debug("Attempting to acquire token from cache...")
        t0 = time.time()
        result = self._app.acquire_token_silent(GRAPH_SCOPES, account=None)

        if result and "access_token" in result:
            logger.debug(f"Token acquired from cache in {time.time() - t0:.2f}s.")
            self._save_token_cache()
            return result["access_token"]

        # Cache miss - fetch new token
        logger.info("Token cache miss — fetching new access token from Azure AD...")
        t0 = time.time()
        result = self._app.acquire_token_for_client(scopes=GRAPH_SCOPES)
        token_duration = time.time() - t0

        if "access_token" in result:
            # Log expiry for diagnostics (MSAL returns expires_in as seconds)
            expires_in = result.get("expires_in", "unknown")
            logger.info(
                f"Access token acquired in {token_duration:.1f}s "
                f"(expires in {expires_in}s)"
            )
            self._save_token_cache()
            return result["access_token"]

        # Authentication failed
        error = result.get("error", "unknown_error")
        error_desc = result.get("error_description", "No description provided.")
        error_codes = result.get("error_codes", [])
        correlation_id = result.get("correlation_id", "N/A")
        logger.error(
            f"Authentication failed after {token_duration:.1f}s: "
            f"{error} - {error_desc} "
            f"(codes: {error_codes}, correlation_id: {correlation_id})"
        )
        raise GraphAuthError(f"Failed to acquire token: {error} - {error_desc}")

    def validate_credentials(self) -> bool:
        """
        Test that credentials are valid by acquiring a token.
        Returns True on success, False on failure.
        """
        try:
            token = self.get_token()
            return bool(token)
        except GraphAuthError as e:
            logger.error(f"Credential validation failed: {e}")
            return False


def load_credentials_from_config(config_path: str = "/opt/network-discovery/config/config.json") -> GraphAuth:
    """
    Load Graph API credentials from config.json or environment variables.
    Environment variables take precedence over config file values.
    """
    # Try environment variables first
    tenant_id = os.environ.get("GRAPH_TENANT_ID")
    client_id = os.environ.get("GRAPH_CLIENT_ID")
    client_secret = os.environ.get("GRAPH_CLIENT_SECRET")

    env_count = sum(1 for v in [tenant_id, client_id, client_secret] if v)
    if env_count == 3:
        logger.info("All Graph API credentials loaded from environment variables.")
    elif env_count > 0:
        logger.info(f"{env_count}/3 credentials from env vars, rest from config file.")

    # Fall back to config.json
    if not all([tenant_id, client_id, client_secret]):
        logger.debug(f"Reading credentials from config: {config_path}")
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
            graph_config = config.get("graph_api", {})
            tenant_id = tenant_id or graph_config.get("tenant_id")
            client_id = client_id or graph_config.get("client_id")
            client_secret = client_secret or graph_config.get("client_secret")
            logger.info(f"Graph API credentials loaded from {config_path}")
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            raise GraphAuthError(f"Config file not found: {config_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}", exc_info=True)
            raise GraphAuthError(f"Invalid JSON in config file: {e}")

    if not all([tenant_id, client_id, client_secret]):
        raise GraphAuthError(
            "Missing Graph API credentials. Set GRAPH_TENANT_ID, GRAPH_CLIENT_ID, "
            "and GRAPH_CLIENT_SECRET environment variables or update config.json."
        )

    # Warn if still using placeholder values
    for name, value in [("tenant_id", tenant_id), ("client_id", client_id), ("client_secret", client_secret)]:
        if value and value.startswith("YOUR_"):
            raise GraphAuthError(
                f"Placeholder value detected for {name}. "
                "Please configure real credentials before running."
            )

    return GraphAuth(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
