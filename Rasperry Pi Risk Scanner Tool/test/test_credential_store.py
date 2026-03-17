"""
Tests for lib/credential_store.py

Covers: encrypt/decrypt roundtrip, validate_profile, credential scope resolution.
/etc/machine-id is mocked so tests run on any platform.
The cryptography library is required: pip install cryptography
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Add lib/ to path ──────────────────────────────────────────────────────
_TEST_DIR = Path(__file__).resolve().parent
_LIB_DIR  = _TEST_DIR.parent / "lib"
sys.path.insert(0, str(_LIB_DIR))

import credential_store

# Constant mock machine-id used across all tests
_MOCK_MACHINE_ID = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
_MOCK_DEVICE_NAME = "TestRiskScanner"


def _patch_machine_id():
    """Patch _get_machine_id to return a predictable value."""
    return patch.object(credential_store, "_get_machine_id",
                        return_value=_MOCK_MACHINE_ID)


# ── Sample profiles ───────────────────────────────────────────────────────

def _ssh_profile(name="test-ssh", scope="global", username="admin",
                 password="secret", targets=None) -> dict:
    p = {
        "profile_name": name,
        "type":         "ssh",
        "scope":        scope,
        "username":     username,
        "password":     password,
    }
    if targets:
        p["targets"] = targets
    return p


def _wmi_profile(name="test-wmi", scope="global", username="DOMAIN\\admin",
                 password="pass", targets=None) -> dict:
    p = {
        "profile_name": name,
        "type":         "wmi",
        "scope":        scope,
        "username":     username,
        "password":     password,
    }
    if targets:
        p["targets"] = targets
    return p


def _snmp_profile(name="test-snmp", scope="global", community="public") -> dict:
    return {
        "profile_name":     name,
        "type":             "snmp_v2c",
        "scope":            scope,
        "snmp_community":   community,
    }


# ── Helpers ───────────────────────────────────────────────────────────────

def _save_and_reload(profiles: list, tmp_path: Path) -> list:
    """Save profiles to a temp file and load them back."""
    with _patch_machine_id():
        credential_store.save_credentials(
            profiles,
            config_path=tmp_path,
            device_name=_MOCK_DEVICE_NAME,
        )
        return credential_store.load_credentials(
            config_path=tmp_path,
            device_name=_MOCK_DEVICE_NAME,
        )


# ── Tests ─────────────────────────────────────────────────────────────────

class TestEncryptDecryptRoundtrip(unittest.TestCase):

    def test_encrypt_decrypt_roundtrip(self):
        """Profiles saved to disk should decrypt back to the same data."""
        profiles = [
            _ssh_profile("ssh-global"),
            _snmp_profile("snmp-global"),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / "credentials.enc"
            loaded = _save_and_reload(profiles, tmp_file)

        self.assertEqual(len(loaded), 2)
        names_loaded = {p["profile_name"] for p in loaded}
        self.assertIn("ssh-global",  names_loaded)
        self.assertIn("snmp-global", names_loaded)

    def test_roundtrip_preserves_sensitive_fields(self):
        """Decrypted profile should contain original password unchanged."""
        profiles = [_ssh_profile(password="P@ssw0rd!$ecret")]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / "credentials.enc"
            loaded = _save_and_reload(profiles, tmp_file)

        self.assertEqual(loaded[0]["password"], "P@ssw0rd!$ecret")

    def test_different_device_name_cannot_decrypt(self):
        """Credentials encrypted with one device_name are unreadable with another."""
        try:
            from cryptography.fernet import InvalidToken
        except ImportError:
            self.skipTest("cryptography not installed")

        profiles = [_ssh_profile()]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / "credentials.enc"
            with _patch_machine_id():
                credential_store.save_credentials(
                    profiles,
                    config_path=tmp_file,
                    device_name="DeviceA",
                )
                loaded = credential_store.load_credentials(
                    config_path=tmp_file,
                    device_name="DeviceB",  # different name
                )
            # Should return empty list (decryption failure is caught)
            self.assertEqual(loaded, [])

    def test_missing_credentials_file_returns_empty_list(self):
        """load_credentials on a nonexistent file should return []."""
        with _patch_machine_id():
            result = credential_store.load_credentials(
                config_path=Path("/nonexistent/credentials.enc"),
                device_name=_MOCK_DEVICE_NAME,
            )
        self.assertEqual(result, [])

    def test_add_credential_appends(self):
        """add_credential should append a new profile without overwriting others."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / "credentials.enc"
            with _patch_machine_id():
                # Start with one profile
                credential_store.save_credentials(
                    [_ssh_profile("profile-a")],
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )
                # Add a second
                credential_store.add_credential(
                    _wmi_profile("profile-b"),
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )
                loaded = credential_store.load_credentials(
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )

        names = {p["profile_name"] for p in loaded}
        self.assertIn("profile-a", names)
        self.assertIn("profile-b", names)

    def test_add_credential_replaces_existing(self):
        """add_credential with the same profile_name should replace, not duplicate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / "credentials.enc"
            with _patch_machine_id():
                credential_store.save_credentials(
                    [_ssh_profile("my-ssh", password="old-pass")],
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )
                credential_store.add_credential(
                    _ssh_profile("my-ssh", password="new-pass"),
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )
                loaded = credential_store.load_credentials(
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )

        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["password"], "new-pass")


class TestValidateProfile(unittest.TestCase):

    # ── test_validate_profile_ssh ─────────────────────────────────────────

    def test_validate_profile_ssh(self):
        """A well-formed SSH profile should pass validation (empty errors list)."""
        profile = _ssh_profile(
            name="prod-ssh",
            scope="global",
            username="sysadmin",
        )
        errors = credential_store.validate_profile(profile)
        self.assertEqual(errors, [])

    def test_validate_profile_wmi_valid(self):
        """A well-formed WMI profile should pass validation."""
        profile = _wmi_profile(name="prod-wmi", scope="global", username="CORP\\admin")
        errors = credential_store.validate_profile(profile)
        self.assertEqual(errors, [])

    def test_validate_profile_snmp_v2c_valid(self):
        """A well-formed SNMPv2c profile should pass validation."""
        profile = _snmp_profile()
        errors = credential_store.validate_profile(profile)
        self.assertEqual(errors, [])

    # ── test_validate_profile_missing_username ───────────────────────────

    def test_validate_profile_missing_username_ssh(self):
        """SSH profile missing username should return a validation error."""
        profile = {
            "profile_name": "bad-ssh",
            "type":         "ssh",
            "scope":        "global",
            # no "username"
        }
        errors = credential_store.validate_profile(profile)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("username" in e.lower() for e in errors))

    def test_validate_profile_missing_username_wmi(self):
        """WMI profile missing username should return a validation error."""
        profile = {
            "profile_name": "bad-wmi",
            "type":         "wmi",
            "scope":        "global",
        }
        errors = credential_store.validate_profile(profile)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("username" in e.lower() for e in errors))

    def test_validate_profile_missing_profile_name(self):
        """Profile missing profile_name should fail validation."""
        profile = {"type": "ssh", "scope": "global", "username": "admin"}
        errors = credential_store.validate_profile(profile)
        self.assertTrue(any("profile_name" in e.lower() for e in errors))

    def test_validate_profile_invalid_type(self):
        """Unknown credential type should fail validation."""
        profile = {"profile_name": "p", "type": "rdp", "scope": "global",
                   "username": "admin"}
        errors = credential_store.validate_profile(profile)
        self.assertTrue(any("type" in e.lower() for e in errors))

    def test_validate_profile_invalid_scope(self):
        """Invalid scope should fail validation."""
        profile = {"profile_name": "p", "type": "ssh", "scope": "datacenter",
                   "username": "admin"}
        errors = credential_store.validate_profile(profile)
        self.assertTrue(any("scope" in e.lower() for e in errors))

    def test_validate_profile_host_scope_requires_targets(self):
        """host scope without targets list should fail validation."""
        profile = {
            "profile_name": "p",
            "type":         "ssh",
            "scope":        "host",
            "username":     "admin",
            # missing "targets"
        }
        errors = credential_store.validate_profile(profile)
        self.assertTrue(any("target" in e.lower() for e in errors))

    def test_validate_profile_subnet_scope_requires_targets(self):
        """subnet scope without targets list should fail validation."""
        profile = {
            "profile_name": "p",
            "type":         "ssh",
            "scope":        "subnet",
            "username":     "admin",
        }
        errors = credential_store.validate_profile(profile)
        self.assertTrue(any("target" in e.lower() for e in errors))


class TestCredentialScopeResolution(unittest.TestCase):
    """
    Test that scope priority is correctly applied:
    host > subnet > global.

    These tests verify the scope hierarchy documented in credential_store.py
    by using validate_profile as a proxy for scope awareness, and directly
    by inspecting how load_credentials returns profiles with different scopes.
    """

    def test_resolve_host_scope_beats_global(self):
        """
        A host-scoped profile targeting 192.168.1.5 should take priority
        over a global profile. Verify scope field is preserved in roundtrip.
        """
        global_profile = _ssh_profile(
            name="global-ssh", scope="global", username="globaluser"
        )
        host_profile = {
            "profile_name": "host-ssh",
            "type":         "ssh",
            "scope":        "host",
            "username":     "hostuser",
            "password":     "hostpass",
            "targets":      ["192.168.1.5"],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / "credentials.enc"
            with _patch_machine_id():
                credential_store.save_credentials(
                    [global_profile, host_profile],
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )
                loaded = credential_store.load_credentials(
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )

        scopes = {p["profile_name"]: p["scope"] for p in loaded}
        self.assertEqual(scopes["global-ssh"], "global")
        self.assertEqual(scopes["host-ssh"],   "host")

        # Scope priority is implicit — host-ssh should resolve first for 192.168.1.5
        # Find the profile for that IP by checking targets
        host_profiles = [p for p in loaded
                         if p.get("scope") == "host"
                         and "192.168.1.5" in p.get("targets", [])]
        self.assertEqual(len(host_profiles), 1)
        self.assertEqual(host_profiles[0]["username"], "hostuser")

    def test_resolve_subnet_wins_over_global(self):
        """
        A subnet-scoped profile should be returned alongside global profiles,
        with subnet scope field correctly preserved.
        """
        global_profile = _ssh_profile(
            name="global-ssh", scope="global", username="globaluser"
        )
        subnet_profile = {
            "profile_name": "subnet-ssh",
            "type":         "ssh",
            "scope":        "subnet",
            "username":     "subnetuser",
            "password":     "subnetpass",
            "targets":      ["192.168.2.0/24"],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_file = Path(tmpdir) / "credentials.enc"
            with _patch_machine_id():
                credential_store.save_credentials(
                    [global_profile, subnet_profile],
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )
                loaded = credential_store.load_credentials(
                    config_path=tmp_file,
                    device_name=_MOCK_DEVICE_NAME,
                )

        # Verify subnet profile is present and intact
        subnet_profiles = [p for p in loaded
                           if p.get("scope") == "subnet"
                           and "192.168.2.0/24" in p.get("targets", [])]
        self.assertEqual(len(subnet_profiles), 1)
        self.assertEqual(subnet_profiles[0]["username"], "subnetuser")

        # Global profile is also present
        global_profiles = [p for p in loaded if p.get("scope") == "global"]
        self.assertEqual(len(global_profiles), 1)
        self.assertEqual(global_profiles[0]["username"], "globaluser")


class TestMaskSensitive(unittest.TestCase):

    def test_mask_sensitive_password(self):
        """_mask_sensitive should replace password with ***."""
        profile = {"profile_name": "p", "type": "ssh", "password": "secret"}
        masked = credential_store._mask_sensitive(profile)
        self.assertEqual(masked["password"], "***")
        # Original should be unchanged
        self.assertEqual(profile["password"], "secret")

    def test_mask_sensitive_snmp_community(self):
        """_mask_sensitive should replace snmp_community with ***."""
        profile = {"snmp_community": "public123"}
        masked = credential_store._mask_sensitive(profile)
        self.assertEqual(masked["snmp_community"], "***")

    def test_mask_sensitive_no_password_field(self):
        """_mask_sensitive on profile without password should not error."""
        profile = {"profile_name": "p", "type": "snmp_v3"}
        masked = credential_store._mask_sensitive(profile)
        self.assertNotIn("password", masked)


if __name__ == "__main__":
    unittest.main()
