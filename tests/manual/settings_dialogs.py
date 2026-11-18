"""Settings, Help and About dialogs open without errors; the settings work."""

from gi.repository import GLib

from harness import run_window_harness


def scenario(window, checks, done):
    from pervius import autostart

    window._show_settings()
    checks.true("settings dialog", True)
    row = window._interfaces_row
    checks.true("interfaces row exists", row is not None)
    checks.equal("interfaces insensitive while off", row.get_sensitive(), False)
    checks.equal("start at login off", autostart.is_enabled(), False)
    autostart.set_enabled(True)
    checks.equal("start at login file", autostart.autostart_path().exists(), True)
    autostart.set_enabled(False)
    checks.equal("start at login removed", autostart.autostart_path().exists(), False)
    window._show_help()
    checks.true("help dialog", True)
    window._show_about()
    checks.true("about dialog", True)
    checks.equal("no legal dialog left", hasattr(window, "_show_legal"), False)
    GLib.timeout_add(1000, lambda: done() or False)


raise SystemExit(run_window_harness("settings_dialogs", scenario))
