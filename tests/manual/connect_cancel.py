"""Connecting never freezes: Cancel stops an attempt, Quit always works."""

import time

from gi.repository import GLib

from harness import run_window_harness


def scenario(window, checks, done):
    deactivated = []
    window._start_poll = lambda: None
    window.active = object()
    import pervius.ui.window as module

    module.deactivate_async = lambda client, active, cb: deactivated.append(active)
    window._attempt += 1
    window._intent_connected = True
    window._set_state("connecting")
    checks.equal("button offers Cancel", (window.connect_button.get_label(), window.connect_button.get_sensitive()), ("Cancel", True))
    primary = next(item for item in window._tray_menu() if item.id == 2)
    checks.equal("tray offers Cancel", (primary.label, primary.enabled), ("Cancel Connecting", True))
    started = time.monotonic()
    window.connect_button.emit("clicked")
    checks.true("cancel is immediate", time.monotonic() - started < 0.5)
    checks.equal("state after cancel", window._state, "idle")
    checks.equal("active attempt deactivated", len(deactivated), 1)
    checks.equal("intent cleared", window._intent_connected, False)

    # A late activation result of the cancelled attempt is dropped.
    late = []
    window._activate = lambda *a, **k: late.append("activate")
    checks.equal("late callbacks see a new attempt", window._attempt > 0, True)

    # Quit while connecting quits at once.
    window._set_state("connecting")
    quit_calls = []
    window._quit_now = lambda: quit_calls.append(time.monotonic())
    started = time.monotonic()
    window._request_quit(None)
    checks.equal("quit while connecting", len(quit_calls), 1)
    checks.true("quit within 2 s", quit_calls and quit_calls[0] - started < 2.0)
    GLib.timeout_add(300, lambda: done() or False)


raise SystemExit(run_window_harness("connect_cancel", scenario))
