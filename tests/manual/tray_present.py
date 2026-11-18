"""Tray "Show Pervius" unminimises and presents with the host's activation token."""

from gi.repository import GLib

from harness import run_window_harness


def scenario(window, checks, done):
    calls = []
    original_present = window.present
    window.set_startup_id = lambda token: calls.append(("startup-id", token))
    window.unminimize = lambda: calls.append(("unminimize",))
    window.present = lambda: (calls.append(("present",)), original_present())
    window.hide()
    window.tray._activation_token = "token-from-shell"
    window._tray_action("show")
    checks.equal("order", calls, [("startup-id", "token-from-shell"), ("unminimize",), ("present",)])
    checks.equal("visible again", window.get_visible(), True)
    checks.equal("token used once", window.tray.take_activation_token(), None)
    GLib.timeout_add(300, lambda: done() or False)


raise SystemExit(run_window_harness("tray_present", scenario))
