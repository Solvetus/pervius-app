from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from pervius.settings import Settings, SettingsStore


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.path = Path(self._temp.name) / "settings.json"

    def tearDown(self):
        self._temp.cleanup()

    def test_defaults(self):
        settings = SettingsStore(self.path).load()
        self.assertEqual(settings.protocol, "udp")
        self.assertEqual(settings.username, "")
        self.assertTrue(settings.save_password)
        self.assertTrue(settings.auto_reconnect)
        self.assertTrue(settings.notifications_enabled)
        self.assertFalse(settings.killswitch_allow_lan)

    def test_auto_reconnect_round_trip(self):
        store = SettingsStore(self.path)
        store.save(Settings(auto_reconnect=False))
        self.assertFalse(store.load().auto_reconnect)

    def test_notifications_round_trip(self):
        store = SettingsStore(self.path)
        store.save(Settings(notifications_enabled=False))
        self.assertFalse(store.load().notifications_enabled)

    def test_killswitch_allow_lan_round_trip(self):
        store = SettingsStore(self.path)
        store.save(Settings(killswitch_allow_lan=True))
        self.assertTrue(store.load().killswitch_allow_lan)
        self.path.write_text(json.dumps({"killswitch_allow_lan": "yes"}), encoding="utf-8")
        self.assertFalse(SettingsStore(self.path).load().killswitch_allow_lan)

    def test_favorites_round_trip(self):
        store = SettingsStore(self.path)
        store.save(Settings(favorites=["PT/Lisbon", "ES/Madrid"]))
        self.assertEqual(store.load().favorites, ["PT/Lisbon", "ES/Madrid"])

    def test_favorites_are_sanitized(self):
        self.path.write_text(
            json.dumps(
                {
                    "favorites": [
                        "PT/Lisbon",
                        "PT/Lisbon",
                        "  ES/Madrid  ",
                        "",
                        "no-country",
                        42,
                        "x" * 600,
                    ]
                }
            ),
            encoding="utf-8",
        )
        self.assertEqual(SettingsStore(self.path).load().favorites, ["PT/Lisbon", "ES/Madrid"])

    def test_favorites_are_limited(self):
        self.path.write_text(
            json.dumps({"favorites": [f"CC/City {index}" for index in range(100)]}),
            encoding="utf-8",
        )
        self.assertEqual(len(SettingsStore(self.path).load().favorites), 50)

    def test_malformed_auto_reconnect_falls_back_to_true(self):
        self.path.write_text(json.dumps({"auto_reconnect": "no"}), encoding="utf-8")
        self.assertTrue(SettingsStore(self.path).load().auto_reconnect)
        self.path.write_text(json.dumps({"auto_reconnect": 0}), encoding="utf-8")
        self.assertTrue(SettingsStore(self.path).load().auto_reconnect)

    def test_malformed_notifications_setting_falls_back_to_true(self):
        self.path.write_text(json.dumps({"notifications_enabled": "no"}), encoding="utf-8")
        self.assertTrue(SettingsStore(self.path).load().notifications_enabled)

    def test_round_trip(self):
        store = SettingsStore(self.path)
        original = Settings(
            username="alice",
            location_key="DE/Frankfurt",
            protocol="tcp",
            save_password=False,
            last_version="0.1.0",
        )
        store.save(original)
        loaded = store.load()
        self.assertEqual(loaded, original)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_invalid_protocol_falls_back_to_udp(self):
        self.path.write_text(json.dumps({"protocol": "icmp"}), encoding="utf-8")
        self.assertEqual(SettingsStore(self.path).load().protocol, "udp")

    def test_malformed_json_uses_defaults(self):
        self.path.write_text("{broken", encoding="utf-8")
        self.assertEqual(SettingsStore(self.path).load(), Settings())

    def test_wrong_shape_uses_defaults(self):
        self.path.write_text("[]", encoding="utf-8")
        self.assertEqual(SettingsStore(self.path).load(), Settings())

    def test_long_fields_are_truncated(self):
        self.path.write_text(
            json.dumps({"username": "x" * 1000, "location_key": "y" * 1000}),
            encoding="utf-8",
        )
        settings = SettingsStore(self.path).load()
        self.assertEqual(len(settings.username), 255)
        self.assertEqual(len(settings.location_key), 512)

    def test_no_password_field_is_written(self):
        store = SettingsStore(self.path)
        store.save(Settings(username="alice", save_password=True))
        value = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertNotIn("password", value)
        self.assertTrue(value["save_password"])




class NewSettingsTests(unittest.TestCase):
    def test_defaults(self):
        settings = Settings.from_dict({})
        self.assertFalse(settings.show_ip_addresses)
        self.assertTrue(settings.block_ipv6)
        self.assertEqual(settings.killswitch_interfaces, [])

    def test_flags_and_interfaces_are_validated(self):
        settings = Settings.from_dict(
            {
                "show_ip_addresses": "yes",
                "block_ipv6": 0,
                "killswitch_interfaces": ["wt0", "wt0", "bad name", "x" * 16, 7, "eth1"],
            }
        )
        self.assertFalse(settings.show_ip_addresses)
        self.assertTrue(settings.block_ipv6)
        self.assertEqual(settings.killswitch_interfaces, ["wt0", "eth1"])
        self.assertEqual(
            len(Settings.from_dict({"killswitch_interfaces": [f"if{i}" for i in range(40)]}).killswitch_interfaces),
            16,
        )


if __name__ == "__main__":
    unittest.main()
