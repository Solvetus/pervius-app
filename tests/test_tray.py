from __future__ import annotations

import unittest


from pervius.ui.tray import MenuItem, TrayIcon


def make_tray(icon_provider=None):
    return TrayIcon(
        app_id="com.solvetus.Pervius",
        title="Pervius",
        icon_name="com.solvetus.Pervius",
        menu_provider=lambda: (),
        tooltip_provider=lambda: ("title", "body"),
        action_handler=lambda _action: None,
        activate_handler=lambda: None,
        secondary_handler=lambda: None,
        icon_provider=icon_provider,
    )


class TrayTests(unittest.TestCase):
    def test_icon_provider_is_used(self):
        tray = make_tray(lambda: "com.solvetus.Pervius-connected")
        self.assertEqual(tray._current_icon(), "com.solvetus.Pervius-connected")

    def test_icon_provider_failure_falls_back(self):
        def broken():
            raise RuntimeError("not today")

        tray = make_tray(broken)
        with self.assertLogs("pervius.ui.tray", level="ERROR"):
            self.assertEqual(tray._current_icon(), "com.solvetus.Pervius")

    def test_separator_properties(self):
        props = TrayIcon._item_properties(MenuItem(1, separator=True))
        self.assertEqual(props["type"].unpack(), "separator")
        self.assertTrue(props["visible"].unpack())
        self.assertNotIn("label", props)

    def test_submenu_and_toggle_properties(self):
        item = MenuItem(
            2,
            "Notifications",
            toggle_state=1,
            children=(MenuItem(3, "Child"),),
        )
        props = TrayIcon._item_properties(item)
        self.assertEqual(props["children-display"].unpack(), "submenu")
        self.assertEqual(props["toggle-type"].unpack(), "checkmark")
        self.assertEqual(props["toggle-state"].unpack(), 1)
        self.assertEqual(props["label"].unpack(), "Notifications")

    def test_disabled_item_is_disabled(self):
        props = TrayIcon._item_properties(MenuItem(1, "Header", enabled=False))
        self.assertFalse(props["enabled"].unpack())


if __name__ == "__main__":
    unittest.main()
