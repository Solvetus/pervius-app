"""Documented distribution checks (pervius/distro.py)."""

import re
import unittest
from pathlib import Path

from pervius import distro

REPO = Path(__file__).resolve().parents[1]


def runner(responses):
    def run(argv):
        return responses.get(" ".join(argv), (1, ""))

    return run


class DistroCheckTests(unittest.TestCase):
    def test_system_bus_implementation(self):
        query = "systemctl show --property=Id --value dbus.service"
        self.assertEqual(distro.system_bus_implementation(runner({query: (0, "dbus-broker.service")})), "dbus-broker")
        self.assertEqual(distro.system_bus_implementation(runner({query: (0, "dbus.service")})), "dbus-daemon")
        self.assertEqual(distro.system_bus_implementation(runner({})), "unknown")

    def test_firewall_frontends(self):
        which = {"ufw": "/usr/sbin/ufw"}.get
        enabled = lambda _path: "# comment\nENABLED=yes\n"  # noqa: E731
        disabled = lambda _path: "ENABLED=no\n"  # noqa: E731
        active = runner({"systemctl is-active firewalld.service": (0, "active")})
        self.assertEqual(distro.firewall_frontends(runner({}), which, enabled), ["ufw (enabled)"])
        self.assertEqual(distro.firewall_frontends(runner({}), which, disabled), ["ufw (installed, disabled)"])
        self.assertEqual(distro.firewall_frontends(active, lambda _name: None, disabled), ["firewalld (active)"])
        self.assertEqual(distro.firewall_frontends(runner({}), lambda _name: None, disabled), [])

    def test_unreadable_ufw_config_counts_as_disabled(self):
        def unreadable(_path):
            raise PermissionError("denied")

        self.assertEqual(
            distro.firewall_frontends(runner({}), {"ufw": "/usr/sbin/ufw"}.get, unreadable),
            ["ufw (installed, disabled)"],
        )

    def test_report_warns_about_nftables_service_flush(self):
        findings = {
            f.name: f
            for f in distro.report(
                runner({"systemctl is-enabled nftables.service": (0, "enabled")}),
                lambda _name: None,
                lambda _path: "",
                lambda _path: False,
            )
        }
        self.assertEqual(findings["nftables.service"].value, "enabled")
        self.assertIn("flushes", findings["nftables.service"].note)
        self.assertEqual(findings["firewall front ends"].value, "none detected")
        self.assertEqual(findings["polkit rules directories"].value, "none")

    def test_missing_tools_never_raise(self):
        self.assertEqual(distro.run_command(["/nonexistent/tool"]), (127, ""))


class DistroLeakTests(unittest.TestCase):
    """Only pervius/distro.py may name distribution-specific tools or paths."""

    WORDS = re.compile(r"(?<![\w-])(dist-packages|dpkg|apt|ufw|dbus-broker|debian)(?![\w-])")

    def test_no_distribution_specifics_outside_distro_module(self):
        hits = []
        for path in sorted((REPO / "pervius").rglob("*.py")):
            if path.name == "distro.py" and path.parent.name == "pervius":
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if self.WORDS.search(line):
                    hits.append(f"{path.relative_to(REPO)}:{number}: {line.strip()}")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
