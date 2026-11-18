"""Messages are toasts (self-dismissing) or banners (dismissible); none can stick."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / "pervius/ui/window.py").read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


class NotificationTests(unittest.TestCase):
    def test_toasts_dismiss_themselves_after_a_few_seconds(self):
        from pervius.ui.window import TOAST_SECONDS

        self.assertTrue(1 <= TOAST_SECONDS <= 5)
        self.assertIn("toast.set_timeout(TOAST_SECONDS)", SOURCE)
        self.assertNotIn("set_timeout(0)", SOURCE)  # 0 would mean "never"

    def test_banner_can_always_be_dismissed(self):
        self.assertIn('self.banner.set_button_label("✕")', SOURCE)
        self.assertIn('self.banner.connect("button-clicked", self._on_banner_dismissed)', SOURCE)

    def test_only_the_helpers_reveal_the_banner(self):
        reveals = [
            node.lineno
            for node in ast.walk(TREE)
            if isinstance(node, ast.Call)
            and ast.unparse(node.func) == "self.banner.set_revealed"
            and node.args
            and ast.unparse(node.args[0]) == "True"
        ]
        show = next(n for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef) and n.name == "_show_banner")
        self.assertTrue(reveals)
        self.assertTrue(all(show.lineno <= line <= show.end_lineno for line in reveals), reveals)

    def test_confirmations_are_toasts_not_banners(self):
        for confirmation in (
            "Kill switch disabled. Normal traffic is allowed.",
            "Kill switch armed. Traffic outside the VPN is blocked.",
            "Loaded {0} in {1}.",
            "Connection attempt cancelled.",
        ):
            index = SOURCE.index(confirmation)
            call = SOURCE.rfind("self._", 0, index)
            self.assertTrue(SOURCE.startswith("self._toast(", call), confirmation)

    def test_errors_and_warnings_are_banners(self):
        for warning in (
            "IPv6 is not blocked outside the tunnel.",
            "Kill-switch operation failed: {0}",
            "Could not switch location: {0}",
        ):
            index = SOURCE.index(warning)
            call = SOURCE.rfind("self._", 0, index)
            self.assertTrue(SOURCE.startswith("self._show_banner(", call), warning)

    def test_one_content_column(self):
        # The card has no margins of its own: it is as wide as the groups.
        card = SOURCE[SOURCE.index("status_card = Gtk.Box"):SOURCE.index("self.status_stack = Gtk.Stack()")]
        self.assertNotIn("set_margin_start", card)
        self.assertNotIn("set_margin_end", card)


if __name__ == "__main__":
    unittest.main()
