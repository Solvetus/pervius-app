"""Product identity constants that other systems depend on."""

import unittest

import pervius
from pervius import config


class IdentityTests(unittest.TestCase):
    def test_reserved_profile_uuid_never_changes(self):
        # Upgraded installations adopt their existing NetworkManager profile
        # by this UUID; changing it would orphan every existing profile.
        self.assertEqual(config.MANAGED_UUID, "22d97462-fd9d-5bc6-9f0b-7110f7153e4f")

    def test_identifiers(self):
        self.assertEqual(config.APP_ID, "com.solvetus.Pervius")
        self.assertEqual(config.APP_NAME, "Pervius")
        self.assertEqual(config.MANAGED_CONNECTION_ID, "Pervius (managed)")
        self.assertEqual(config.SECRET_SCHEMA_NAME, "com.solvetus.Pervius")

    def test_single_version_source(self):
        self.assertEqual(config.VERSION, pervius.__version__)

    def test_killswitch_dbus_identifiers(self):
        from gi.repository import Gio

        from pervius.killswitchd import daemon, rules

        self.assertEqual(daemon.BUS_NAME, "com.solvetus.Pervius.KillSwitch1")
        self.assertEqual(daemon.OBJECT_PATH, "/com/solvetus/Pervius/KillSwitch1")
        self.assertEqual(daemon.POLKIT_ACTION, "com.solvetus.pervius.killswitch.control")
        self.assertEqual(str(daemon.STATE_DIR), "/run/pervius")
        self.assertEqual(rules.TABLE_SPEC, "inet pervius_ks")
        node = Gio.DBusNodeInfo.new_for_xml(daemon._INTROSPECTION_XML)
        interface = node.interfaces[0]
        self.assertEqual(interface.name, daemon.INTERFACE)
        self.assertEqual(
            sorted(method.name for method in interface.methods),
            ["Arm", "Configure", "Disarm", "GetStatus", "SetGuardOptions", "UpdateEndpoints"],
        )

    def test_disclaimer_text(self):
        self.assertEqual(
            config.DISCLAIMER,
            "Pervius is an independent open-source project by Solvetus Labs. It is not "
            "affiliated with, endorsed by, or sponsored by Namecheap, Inc. FastVPN is a "
            "trademark of Namecheap, Inc.",
        )


if __name__ == "__main__":
    unittest.main()
