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
    is_pinned,
    low_risk_warnings,
    pin_remote,
    pinned_endpoints,
    remote_names,
    strip_user_data,
    tunnel_settings_problem,
    unpin_remote,
)
from pervius.killswitchd.rules import Endpoint  # noqa: E402
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

    def test_tunnel_device_is_pinned_and_dns_is_exclusive(self):
        managed = make_managed(imported_connection())
        s_vpn = managed.get_setting_vpn()
        self.assertEqual(s_vpn.get_data_item("dev"), "pervius0")
        self.assertEqual(s_vpn.get_data_item("dev-type"), "tun")
        s_ip4 = managed.get_setting_ip4_config()
        s_ip6 = managed.get_setting_ip6_config()
        self.assertEqual(s_ip4.props.dns_priority, -1)
        self.assertEqual(s_ip6.props.dns_priority, -1)
        self.assertIn("~.", list(s_ip4.props.dns_search))
        self.assertIsNone(tunnel_settings_problem(managed))

    def test_no_user_data_is_written(self):
        # NetworkManager 1.58 drops connection user-data when it reads the
        # profile back, so nothing Pervius relies on may live there.
        imported = imported_connection()
        user = NM.SettingUser.new()
        user.set_data("com.solvetus.pervius.remote-names", "stale")
        imported.add_setting(user)
        managed = make_managed(imported)
        self.assertIsNone(managed.get_setting_by_name("user"))
        self.assertNotIn("'user'", build_variant(managed).print_(False))

    def test_pinning_needs_no_recorded_names(self):
        managed = make_managed(imported_connection())
        self.assertFalse(is_pinned(managed))
        endpoints = (Endpoint("192.0.2.10", 1194, "udp"), Endpoint("2001:db8::10", 1194, "udp"), Endpoint("192.0.2.11", 443, "tcp"))
        pinned = pin_remote(managed, endpoints, "udp")
        self.assertEqual(pinned.get_setting_vpn().get_data_item("remote"), "192.0.2.10:1194, [2001:db8::10]:1194")
        self.assertTrue(is_pinned(pinned))
        self.assertEqual([e.address for e in pinned_endpoints(pinned, "udp")], ["192.0.2.10", "2001:db8::10"])
        names = remote_names((("vpn.example.com", 1194),))
        restored = unpin_remote(pinned, names)
        self.assertEqual(restored.get_setting_vpn().get_data_item("remote"), "vpn.example.com:1194")
        self.assertFalse(is_pinned(restored))

    def test_strip_user_data(self):
        connection = imported_connection()
        self.assertFalse(strip_user_data(connection))
        connection.add_setting(NM.SettingUser.new())
        self.assertTrue(strip_user_data(connection))
        self.assertIsNone(connection.get_setting_by_name("user"))

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
