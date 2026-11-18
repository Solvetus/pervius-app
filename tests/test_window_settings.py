"""The window size is remembered; bad values fall back to the default."""

import unittest
from pathlib import Path

from pervius.settings import Settings

WINDOW = Path(__file__).resolve().parents[1] / "pervius" / "ui" / "window.py"


class WindowSettingsTests(unittest.TestCase):
    def test_defaults_mean_nothing_saved(self):
        s = Settings.from_dict({})
        self.assertEqual((s.window_width, s.window_height, s.window_maximized), (0, 0, False))

    def test_round_trip(self):
        s = Settings.from_dict({"window_width": 500, "window_height": 700, "window_maximized": True})
        self.assertEqual((s.window_width, s.window_height, s.window_maximized), (500, 700, True))

    def test_invalid_values_are_ignored(self):
        for bad in ("500", 5, -1, 10**6, True, None, 12.5):
            s = Settings.from_dict({"window_width": bad, "window_height": 700})
            self.assertEqual((s.window_width, s.window_height), (0, 0), bad)

    def test_epoch_round_trip_and_validation(self):
        self.assertEqual(Settings.from_dict({}).window_size_epoch, 0)
        self.assertEqual(Settings.from_dict({"window_size_epoch": 1}).window_size_epoch, 1)
        for bad in ("1", True, -1, 10**6):
            self.assertEqual(Settings.from_dict({"window_size_epoch": bad}).window_size_epoch, 0, bad)

    def test_old_saved_size_is_cleared_once(self):
        text = WINDOW.read_text()
        start = text.split("self.settings: Settings = self.settings_store.load()")[1][:600]
        self.assertIn("window_size_epoch < WINDOW_SIZE_EPOCH", start)
        self.assertIn("self.settings.window_width = self.settings.window_height = 0", start)

    def test_size_is_saved_on_close_and_quit_and_restored_at_start(self):
        text = WINDOW.read_text()
        self.assertIn("self._save_window_size()", text.split("def _on_close_request")[1].split("def ")[0])
        self.assertIn("self._save_window_size()", text.split("def _quit_now")[1].split("def ")[0])
        self.assertIn("self.settings.window_width", text)


if __name__ == "__main__":
    unittest.main()
