"""Profile writes start from NetworkManager's current settings, never libnm's cache.

Regression: right after an update, libnm's cached copy of the profile can
still be the old one; cloning it and writing it back undid the update (the
NetworkManager audit log showed a second write ~15 ms after every import).
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

import gi

gi.require_version("NM", "1.0")
from gi.repository import NM  # noqa: E402

from pervius.killswitchd.rules import Endpoint  # noqa: E402
from pervius.nm.profile import apply_tunnel_settings  # noqa: E402
from pervius.ui import window as module  # noqa: E402

from .test_profile import imported_connection  # noqa: E402


def connection_with(remote: str, *, user_data: bool = False) -> NM.SimpleConnection:
    connection = imported_connection()
    apply_tunnel_settings(connection)
    connection.get_setting_vpn().add_data_item("remote", remote)
    if user_data:
        setting = NM.SettingUser.new()
        setting.set_data("com.solvetus.pervius.remote-names", "stale")
        connection.add_setting(setting)
    return connection


class WriteProfileTests(unittest.TestCase):
    def setUp(self):
        self.written = []
        self.fake_self = SimpleNamespace(
            _disposed=False,
            settings=SimpleNamespace(protocol="udp"),
            _current_names=lambda: "vpn1.example.com:1194, vpn2.example.com:1194",
        )

    def write(self, cached, fresh, pins):
        results = []
        with mock.patch.object(module, "fetch_settings_async", lambda conn, cb: cb(fresh, None)), \
                mock.patch.object(
                    module,
                    "update_connection_async",
                    lambda conn, variant, cb: (self.written.append(NM.SimpleConnection.new_from_dbus(variant)), cb(conn, None)),
                ):
            module.MainWindow._write_profile(
                self.fake_self, cached, pins=pins, then=results.append, on_error=self.fail
            )
        return results

    def test_pinning_uses_the_fresh_settings_not_the_cache(self):
        stale_cache = connection_with("old.example.com:1194", user_data=True)
        stale_cache.get_setting_vpn().remove_data_item("dev")  # what libnm still had
        fresh = connection_with("vpn1.example.com:1194, vpn2.example.com:1194")
        self.write(stale_cache, fresh, (Endpoint("192.0.2.10", 1194, "udp"),))
        written = self.written[0]
        self.assertEqual(written.get_setting_vpn().get_data_item("remote"), "192.0.2.10:1194")
        self.assertEqual(written.get_setting_vpn().get_data_item("dev"), "pervius0")  # update kept
        self.assertIsNone(written.get_setting_by_name("user"))

    def test_names_come_from_the_catalogue(self):
        fresh = connection_with("192.0.2.10:1194")
        self.write(fresh, fresh, module.NAMES)
        self.assertEqual(
            self.written[0].get_setting_vpn().get_data_item("remote"),
            "vpn1.example.com:1194, vpn2.example.com:1194",
        )

    def test_unchanged_profile_is_not_written(self):
        fresh = connection_with("192.0.2.10:1194")
        results = self.write(fresh, fresh, (Endpoint("192.0.2.10", 1194, "udp"),))
        self.assertEqual(self.written, [])
        self.assertEqual(results, [fresh])

    def test_stale_user_data_is_removed(self):
        fresh = connection_with("192.0.2.10:1194", user_data=True)
        self.write(fresh, fresh, module.KEEP_PINS)
        self.assertIsNone(self.written[0].get_setting_by_name("user"))


if __name__ == "__main__":
    unittest.main()
