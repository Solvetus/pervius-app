"""Reconnect state machine: success, give-up, manual cancel, switch off."""

import time

from gi.repository import GLib

from harness import run_window_harness

GIVE_UP = (
    "The VPN connection was lost and automatic reconnection stopped after 2 "
    "attempts: simulated activation failure"
)


def scenario(window, checks, done):
    from solvetus.reconnect import ReconnectPolicy
    from solvetus.ui import window as window_module

    window_module._RECONNECT = ReconnectPolicy((1, 1))
    window_module.verify_managed_profile = lambda *_args, **_kwargs: ()
    window._start_poll = lambda: None
    calls = []

    def connected():
        window._stop_poll()
        window._stop_timer()
        window.active = None
        window._existing_connection = object()
        window._intent_connected = True
        window._connected_since = time.monotonic()
        window._set_state("connected")

    def success(_connection, reconnecting=False):
        calls.append(("success", reconnecting))
        window._reconnect_in_flight = reconnecting
        window._set_connected()

    def failure(_connection, reconnecting=False):
        calls.append(("failure", reconnecting))
        window._reconnect_in_flight = True
        window._schedule_next_reconnect("simulated activation failure")

    # 1. drop and reconnect
    connected()
    window._activate = success
    window._connection_lost("simulated drop")
    checks.equal("drop: reconnecting", window._state, "reconnecting")
    checks.equal("drop: countdown", window.status_subtitle.get_label(), "Connection lost. Retrying in 1s (attempt 1 of 2).")

    def after_success():
        checks.equal("reconnected", (window._state, calls), ("connected", [("success", True)]))
        checks.equal("reconnected banner", window.banner.get_title(), "VPN reconnected automatically.")
        # 2. retry failure and give up
        calls.clear()
        connected()
        window._activate = failure
        window._connection_lost("simulated drop")
        GLib.timeout_add(6000, after_give_up)
        return False

    def after_give_up():
        checks.equal("gave up", (window._state, calls), ("error", [("failure", True), ("failure", True)]))
        checks.equal("give-up banner", window.banner.get_title(), GIVE_UP)
        # 3. manual cancel
        calls.clear()
        connected()
        window._activate = success
        window._connection_lost("simulated drop")
        window._cancel_reconnect("stopped by test")
        GLib.timeout_add(1500, after_cancel)
        return False

    def after_cancel():
        checks.equal("cancelled", (window._state, calls), ("idle", []))
        # 4. automatic reconnect switched off
        window.settings.auto_reconnect = False
        connected()
        window._connection_lost("simulated drop")
        checks.equal("auto-reconnect off", (window._state, calls), ("idle", []))
        checks.equal("off banner", window.banner.get_title(), "The VPN connection ended. Automatic reconnect is off.")
        window.settings.auto_reconnect = True
        done()
        return False

    GLib.timeout_add(2500, after_success)


raise SystemExit(run_window_harness("reconnect_state", scenario, delay_ms=1500))
