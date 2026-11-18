"""The Debian preinst guard for upgrades from the pre-rename package."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PREINST = REPO / "packaging" / "debian" / "preinst"
LEGACY_TABLE = "inet solvetus_ks"


class PreinstGuardTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.bin = Path(self._temp.name) / "bin"
        self.bin.mkdir()
        self.calls = Path(self._temp.name) / "nft-calls"
        # Only `cat` is real; nft and the legacy CLI are fakes.
        (self.bin / "cat").symlink_to("/bin/cat")

    def fake_nft(self, table_exists: bool):
        script = self.bin / "nft"
        script.write_text(
            "#!/bin/sh\n"
            f'echo "$*" >> "{self.calls}"\n'
            f'[ "$*" = "list table {LEGACY_TABLE}" ] && exit {0 if table_exists else 1}\n'
            "exit 1\n"
        )
        script.chmod(0o755)

    def fake_legacy_cli(self):
        script = self.bin / "solvetus-killswitch"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)

    def run_preinst(self, action="install"):
        return subprocess.run(
            ["/bin/sh", str(PREINST), action],
            env={"PATH": str(self.bin)},
            capture_output=True,
            text=True,
            check=False,
        )

    def nft_calls(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_armed_previous_kill_switch_stops_the_install(self):
        self.fake_nft(table_exists=True)
        self.fake_legacy_cli()
        for action in ("install", "upgrade"):
            result = self.run_preinst(action)
            self.assertEqual(result.returncode, 1)
            self.assertIn("solvetus-killswitch disarm", result.stderr)
            self.assertNotIn("nft delete", result.stderr)

    def test_fallback_command_when_the_previous_cli_is_gone(self):
        self.fake_nft(table_exists=True)
        result = self.run_preinst()
        self.assertEqual(result.returncode, 1)
        self.assertIn("nft delete table inet solvetus_ks", result.stderr)

    def test_never_modifies_the_firewall(self):
        self.fake_nft(table_exists=True)
        self.run_preinst()
        self.fake_nft(table_exists=False)
        self.run_preinst()
        self.assertEqual(self.nft_calls(), [f"list table {LEGACY_TABLE}"] * 2)

    def test_disarmed_or_absent_previous_package_installs(self):
        self.fake_nft(table_exists=False)
        self.assertEqual(self.run_preinst().returncode, 0)
        (self.bin / "nft").unlink()
        self.assertEqual(self.run_preinst().returncode, 0)

    def test_other_actions_do_nothing(self):
        self.fake_nft(table_exists=True)
        self.assertEqual(self.run_preinst("abort-upgrade").returncode, 0)
        self.assertEqual(self.nft_calls(), [])

    def test_script_is_executable(self):
        self.assertTrue(os.access(PREINST, os.X_OK))


if __name__ == "__main__":
    unittest.main()
