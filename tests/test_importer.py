from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from solvetus.config import OPENVPN_SERVICE_TYPE  # noqa: E402
from solvetus.catalogue.parser import parse_profile  # noqa: E402
from solvetus.nm.importer import (  # noqa: E402
    ImportVerificationError,
    verify_imported_profile,
    verify_managed_profile,
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
            make_connection(self.parsed, self.ca_path), self.parsed, self.cert_dir
        )
        self.assertEqual(warnings, ())

    def test_tampered_remote_is_rejected(self):
        connection = make_connection(self.parsed, self.ca_path)
        s_vpn = connection.get_setting_vpn()
        assert s_vpn is not None
        s_vpn.add_data_item("remote", "evil.example.com:1194")
        with self.assertRaisesRegex(ImportVerificationError, "preservation check failed for 'remote'"):
            verify_imported_profile(connection, self.parsed, self.cert_dir)

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
