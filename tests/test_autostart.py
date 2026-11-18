from __future__ import annotations

import configparser
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pervius import autostart


class AutostartTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.tmp)})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_off_by_default(self):
        self.assertFalse(autostart.is_enabled())

    def test_enable_writes_a_hidden_start_entry(self):
        autostart.set_enabled(True)
        path = self.tmp / "autostart" / "com.solvetus.Pervius.desktop"
        self.assertTrue(autostart.is_enabled())
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read(path)
        entry = parser["Desktop Entry"]
        self.assertEqual(entry["Exec"], "pervius --hidden")
        self.assertEqual(entry["Type"], "Application")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_disable_removes_the_file_and_leaves_the_directory(self):
        (self.tmp / "autostart").mkdir(mode=0o755)
        os.chmod(self.tmp / "autostart", 0o755)
        autostart.set_enabled(True)
        autostart.set_enabled(False)
        self.assertFalse(autostart.is_enabled())
        self.assertEqual(stat.S_IMODE((self.tmp / "autostart").stat().st_mode), 0o755)
        autostart.set_enabled(False)  # idempotent


if __name__ == "__main__":
    unittest.main()
