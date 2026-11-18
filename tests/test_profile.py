from __future__ import annotations

import unittest

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from pervius.config import MANAGED_CONNECTION_ID, MANAGED_UUID, OPENVPN_SERVICE_TYPE  # noqa: E402
from pervius.nm.profile import (  # noqa: E402
    ProfileBuildError,
    build_managed_connection,
    build_variant,
    low_risk_warnings,
)
from pervius.catalogue.parser import parse_profile  # noqa: E402

from .fixtures import profile_text

USER = "tester"
VPN_USER = "vpn-account@example"


def make_managed(imported, local_user: str = USER, vpn_user: str = VPN_USER):
    return build_managed_connection(
        imported, local_username=local_user, vpn_username=vpn_user
    )


def imported_connection(*, service: str = OPENVPN_SERVICE_TYPE) -> NM.SimpleConnection:
    connection = NM.SimpleConnection.new()
    s_con = NM.SettingConnection.new()
    s_con.props.id = "imported"
    s_con.props.uuid = "11111111-1111-1111-1111-111111111111"
    s_con.props.type = "vpn"
    s_vpn = NM.SettingVpn.new()
    s_vpn.props.service_type = service
    s_vpn.props.user_name = "previous-user"
    s_vpn.add_data_item("remote", "vpn.example.com:1194")
    s_vpn.add_data_item("remote-random", "yes")
    connection.add_setting(s_con)
    connection.add_setting(s_vpn)
    return connection


class ProfileTests(unittest.TestCase):
    def test_build_managed_connection(self):
        managed = make_managed(imported_connection())
        s_con = managed.get_setting_connection()
        s_vpn = managed.get_setting_vpn()
        assert s_con is not None and s_vpn is not None
        self.assertEqual(s_con.get_id(), MANAGED_CONNECTION_ID)
        self.assertEqual(s_con.get_uuid(), MANAGED_UUID)
        self.assertFalse(s_con.get_autoconnect())
        self.assertEqual(s_con.get_num_permissions(), 1)
        self.assertTrue(s_con.permissions_user_allowed(USER))
        self.assertFalse(s_con.permissions_user_allowed("other"))
        self.assertFalse(s_con.permissions_user_allowed(VPN_USER))
        # The VPN account name is sent to the server, never used as owner.
        self.assertEqual(s_vpn.props.user_name, VPN_USER)
        self.assertEqual(
            s_vpn.get_data_item("password-flags"),
            str(int(NM.SettingSecretFlags.AGENT_OWNED)),
        )
        self.assertIsNone(s_vpn.get_secret("password"))
        self.assertTrue(managed.verify())

    def test_vpn_username_is_not_used_for_ownership(self):
        managed = make_managed(imported_connection())
        s_con = managed.get_setting_connection()
        assert s_con is not None
        self.assertNotIn(VPN_USER, s_con.props.permissions)
        self.assertIn(f"user:{USER}:", s_con.props.permissions)

    def test_build_requires_both_usernames(self):
        with self.assertRaisesRegex(ProfileBuildError, "local username"):
            make_managed(imported_connection(), local_user="")
        with self.assertRaisesRegex(ProfileBuildError, "VPN username"):
            make_managed(imported_connection(), vpn_user="")

    def test_build_rejects_non_openvpn(self):
        with self.assertRaisesRegex(ProfileBuildError, "not an OpenVPN connection"):
            make_managed(imported_connection(service="org.example.other"))

    def test_build_removes_existing_permissions(self):
        imported = imported_connection()
        s_con = imported.get_setting_connection()
        assert s_con is not None
        s_con.add_permission("user", "someone-else", None)
        managed = make_managed(imported)
        managed_con = managed.get_setting_connection()
        assert managed_con is not None
        self.assertEqual(managed_con.get_num_permissions(), 1)
        self.assertTrue(managed_con.permissions_user_allowed(USER))

    def test_build_variant_never_contains_password(self):
        managed = make_managed(imported_connection())
        text = build_variant(managed).print_(False)
        self.assertIn("password-flags", text)
        self.assertNotIn("'password': <", text)

    def test_low_risk_warnings_empty_when_represented(self):
        parsed = parse_profile(profile_text().encode(), "test.ovpn")
        warnings = low_risk_warnings(parsed, imported_connection())
        self.assertEqual(warnings, ())

    def test_low_risk_warnings_report_missing_remote_random(self):
        parsed = parse_profile(profile_text().encode(), "test.ovpn")
        connection = imported_connection()
        s_vpn = connection.get_setting_vpn()
        assert s_vpn is not None
        s_vpn.remove_data_item("remote-random")
        warnings = low_risk_warnings(parsed, connection)
        self.assertTrue(any("remote-random" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
