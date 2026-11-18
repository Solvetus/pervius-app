from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from pervius.config import OPENVPN_SERVICE_TYPE  # noqa: E402
from pervius.catalogue.parser import parse_profile  # noqa: E402
from pervius.killswitchd.rules import Endpoint  # noqa: E402
from pervius.nm.importer import (  # noqa: E402
    ImportVerificationError,
    verify_imported_profile,
    verify_managed_profile,
)
from pervius.nm.profile import (  # noqa: E402
    apply_tunnel_settings,
    is_pinned,
    pin_remote,
    remote_names,
    unpin_remote,
)

from .fixtures import profile_text


def make_connection(parsed, ca_path: Path) -> NM.SimpleConnection:
    connection = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.props.id = "imported"
    s_con.props.uuid = "11111111-1111-1111-1111-111111111111"
    s_con.props.type = "vpn"
    s_vpn = NM.SettingVpn.new()
    s_vpn.props.service_type = OPENVPN_SERVICE_TYPE
    s_vpn.add_data_item("remote", ", ".join(f"{h}:{p}" for h, p in parsed.remotes))
    if parsed.protocol == "tcp":
        s_vpn.add_data_item("proto-tcp", "yes")
    s_vpn.add_data_item("remote-cert-tls", "server")
    s_vpn.add_data_item("verify-x509-name", parsed.verify_x509_name)
    s_vpn.add_data_item("auth", parsed.auth)
    s_vpn.add_data_item("data-ciphers", parsed.data_ciphers)
    s_vpn.add_data_item("data-ciphers-fallback", parsed.data_ciphers_fallback)
    s_vpn.add_data_item("tls-cipher", parsed.tls_cipher)
    s_vpn.add_data_item("connection-type", "password")
    s_vpn.add_data_item("password-flags", str(int(NM.SettingSecretFlags.AGENT_OWNED)))
    s_vpn.add_data_item("remote-random", "yes")
    s_vpn.add_data_item("ca", str(ca_path))
    connection.add_setting(s_con)
    connection.add_setting(s_vpn)
    return connection


def make_managed(parsed, ca_path: Path) -> NM.SimpleConnection:
    connection = make_connection(parsed, ca_path)
    apply_tunnel_settings(connection)
    return connection


class ImportVerificationTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.cert_dir = Path(self._temp.name) / "certificates" / "nm-openvpn"
        self.cert_dir.mkdir(parents=True)
        self.parsed = parse_profile(profile_text().encode(), "test.ovpn")
        self.ca_path = self.cert_dir / "vpn-ca.pem"
        self.ca_path.write_text(self.parsed.ca_pem, encoding="utf-8")
        os.chmod(self.ca_path, 0o600)

    def tearDown(self):
        self._temp.cleanup()

    def test_valid_profile_passes(self):
        imported = verify_imported_profile(
            make_connection(self.parsed, self.ca_path), self.parsed, self.cert_dir
        )
        self.assertEqual(imported.ca_path, self.ca_path)
        self.assertEqual(imported.warnings, ())

    def test_managed_verification_passes(self):
        warnings = verify_managed_profile(
            make_managed(self.parsed, self.ca_path), self.parsed, self.cert_dir
        )
        self.assertEqual(warnings, ())

    def test_profiles_from_older_releases_are_reimported(self):
        # No pinned device and no exclusive DNS: verification fails, which makes
        # the app import the profile again.
        with self.assertRaisesRegex(ImportVerificationError, "tunnel device is not pinned"):
            verify_managed_profile(make_connection(self.parsed, self.ca_path), self.parsed, self.cert_dir)

    def test_non_exclusive_dns_is_rejected(self):
        connection = make_managed(self.parsed, self.ca_path)
        connection.get_setting_ip4_config().props.dns_priority = 50
        with self.assertRaisesRegex(ImportVerificationError, "not exclusive"):
            verify_managed_profile(connection, self.parsed, self.cert_dir)

    def test_missing_default_dns_route_is_rejected(self):
        connection = make_managed(self.parsed, self.ca_path)
        connection.get_setting_ip4_config().clear_dns_searches()
        with self.assertRaisesRegex(ImportVerificationError, "default DNS route"):
            verify_managed_profile(connection, self.parsed, self.cert_dir)

    def test_pinned_remote_passes_and_unpins(self):
        managed = make_managed(self.parsed, self.ca_path)
        port = self.parsed.remotes[0][1]
        pinned = pin_remote(
            managed,
            (Endpoint("192.0.2.10", port, self.parsed.protocol), Endpoint("2001:db8::10", port, self.parsed.protocol)),
            self.parsed.protocol,
        )
        self.assertEqual(
            pinned.get_setting_vpn().get_data_item("remote"),
            f"192.0.2.10:{port}, [2001:db8::10]:{port}",
        )
        self.assertTrue(is_pinned(pinned))
        verify_managed_profile(pinned, self.parsed, self.cert_dir)
        restored = unpin_remote(pinned, remote_names(self.parsed.remotes))
        self.assertFalse(is_pinned(restored))
        verify_managed_profile(restored, self.parsed, self.cert_dir)

    def test_pinned_remote_must_be_ip_literals_on_profile_ports(self):
        for bad in ("evil.example.com:1194", "192.0.2.10:9999", "192.0.2.10", "[2001:db8::1]9", ""):
            connection = make_managed(self.parsed, self.ca_path)
            connection.get_setting_vpn().add_data_item("remote", bad)
            with self.assertRaises(ImportVerificationError, msg=bad):
                verify_managed_profile(connection, self.parsed, self.cert_dir)

    def test_profile_without_user_data_still_verifies(self):
        # The 0.2.0-migrated and NetworkManager-reloaded profiles have no user-data.
        managed = make_managed(self.parsed, self.ca_path)
        self.assertIsNone(managed.get_setting_by_name("user"))
        verify_managed_profile(managed, self.parsed, self.cert_dir)
        port = self.parsed.remotes[0][1]
        pinned = pin_remote(managed, (Endpoint("192.0.2.10", port, self.parsed.protocol),), self.parsed.protocol)
        verify_managed_profile(pinned, self.parsed, self.cert_dir)

    def test_wrong_proto_is_rejected(self):
        connection = make_connection(self.parsed, self.ca_path)
        s_vpn = connection.get_setting_vpn()
        assert s_vpn is not None
        s_vpn.add_data_item("proto-tcp", "yes")
        with self.assertRaisesRegex(ImportVerificationError, "proto-tcp"):
            verify_imported_profile(connection, self.parsed, self.cert_dir)

    def test_wrong_ca_mode_is_rejected(self):
        os.chmod(self.ca_path, 0o644)
        with self.assertRaisesRegex(ImportVerificationError, "mode 0644"):
            verify_imported_profile(
                make_connection(self.parsed, self.ca_path), self.parsed, self.cert_dir
            )

    def test_ca_outside_cert_dir_is_rejected(self):
        outside = Path(self._temp.name) / "outside.pem"
        outside.write_text(self.parsed.ca_pem, encoding="utf-8")
        os.chmod(outside, 0o600)
        with self.assertRaisesRegex(ImportVerificationError, "outside the app-owned"):
            verify_imported_profile(
                make_connection(self.parsed, outside), self.parsed, self.cert_dir
            )

    def test_ca_hash_mismatch_is_rejected(self):
        self.ca_path.write_text(
            self.parsed.ca_pem.replace("AAAA", "BBBB"), encoding="utf-8"
        )
        os.chmod(self.ca_path, 0o600)
        with self.assertRaisesRegex(ImportVerificationError, "does not match the source CA"):
            verify_imported_profile(
                make_connection(self.parsed, self.ca_path), self.parsed, self.cert_dir
            )

    def test_password_in_non_secret_data_is_rejected(self):
        connection = make_connection(self.parsed, self.ca_path)
        s_vpn = connection.get_setting_vpn()
        assert s_vpn is not None
        s_vpn.add_data_item("password", "secret")
        with self.assertRaises(ImportVerificationError):
            verify_imported_profile(connection, self.parsed, self.cert_dir)

    def test_wrong_password_flags_are_rejected(self):
        connection = make_connection(self.parsed, self.ca_path)
        s_vpn = connection.get_setting_vpn()
        assert s_vpn is not None
        s_vpn.add_data_item("password-flags", "0")
        with self.assertRaisesRegex(ImportVerificationError, "agent-owned"):
            verify_imported_profile(connection, self.parsed, self.cert_dir)

    def test_client_certificate_field_is_rejected(self):
        connection = make_connection(self.parsed, self.ca_path)
        s_vpn = connection.get_setting_vpn()
        assert s_vpn is not None
        s_vpn.add_data_item("cert", "/tmp/client.pem")
        with self.assertRaisesRegex(ImportVerificationError, "sensitive field 'cert'"):
            verify_imported_profile(connection, self.parsed, self.cert_dir)

    def test_wrong_service_is_rejected(self):
        connection = make_connection(self.parsed, self.ca_path)
        s_vpn = connection.get_setting_vpn()
        assert s_vpn is not None
        s_vpn.props.service_type = "org.example.other"
        with self.assertRaisesRegex(ImportVerificationError, "unexpected VPN service"):
            verify_imported_profile(connection, self.parsed, self.cert_dir)

    def test_tcp_profile_passes(self):
        parsed = parse_profile(profile_text(protocol="tcp").encode(), "test.ovpn")
        ca_path = self.cert_dir / "tcp-ca.pem"
        ca_path.write_text(parsed.ca_pem, encoding="utf-8")
        os.chmod(ca_path, 0o600)
        imported = verify_imported_profile(make_connection(parsed, ca_path), parsed, self.cert_dir)
        self.assertEqual(imported.ca_path, ca_path)


if __name__ == "__main__":
    unittest.main()
