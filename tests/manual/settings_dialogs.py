"""Settings, legal and component dialogs open without errors."""

from gi.repository import GLib

from harness import run_window_harness


def scenario(window, checks, done):
    window._show_settings()
    checks.true("settings dialog", True)
    window._show_legal("license")
    checks.true("license dialog", True)
    window._show_legal("components")
    checks.true("components dialog", True)
    window._show_about()
    checks.true("about dialog", True)
    window._show_protocol_help()
    checks.true("protocol guide", True)
    GLib.timeout_add(1000, lambda: done() or False)


raise SystemExit(run_window_harness("settings_dialogs", scenario))
