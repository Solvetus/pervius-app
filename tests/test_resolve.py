from __future__ import annotations

import unittest
from types import SimpleNamespace

import gi

gi.require_version("GLib", "2.0")
from gi.repository import GLib  # noqa: E402

from pervius.nm.importer import ImportVerificationError  # noqa: E402
from pervius.resolve import resolve_endpoints_async  # noqa: E402
from pervius.ui.window import MainWindow  # noqa: E402


def run_until(predicate, seconds=5):
    loop = GLib.MainLoop()
    GLib.timeout_add(seconds * 1000, loop.quit)

    def check():
        if predicate():
            loop.quit()
            return False
        return True

    GLib.timeout_add(20, check)
    loop.run()


class ResolveTests(unittest.TestCase):
    def test_names_and_literals_resolve_without_blocking(self):
        results = []
        resolve_endpoints_async(
            [("localhost", 1194), ("192.0.2.5", 1194), ("2001:db8::5", 443)], "udp", lambda e, w: results.append((e, w))
        )
        self.assertEqual(results, [])  # nothing is answered synchronously
        run_until(lambda: results)
        endpoints, _warnings = results[0]
        addresses = {e.address for e in endpoints}
        self.assertIn("192.0.2.5", addresses)
        self.assertIn("2001:db8::5", addresses)
        self.assertTrue({"127.0.0.1", "::1"} & addresses)
        self.assertTrue(all(e.protocol == "udp" for e in endpoints))

    def test_unknown_name_gives_a_warning(self):
        results = []
        resolve_endpoints_async([("does-not-exist.invalid", 1194)], "udp", lambda e, w: results.append((e, w)))
        run_until(lambda: results)
        self.assertEqual(results[0][0], ())
        self.assertTrue(results[0][1])


class StoredProfileIdentityTests(unittest.TestCase):
    """A pinned profile lists IPs, so the manifest hash decides which location it is."""

    def test_profile_of_another_location_is_reimported(self):
        ref = SimpleNamespace(profile=SimpleNamespace(source_sha256="new"))
        with self.assertRaisesRegex(ImportVerificationError, "another location"):
            MainWindow._verify_for(object(), SimpleNamespace(source_sha256="old"), ref)
        with self.assertRaisesRegex(ImportVerificationError, "another location"):
            MainWindow._verify_for(object(), None, ref)


if __name__ == "__main__":
    unittest.main()
