"""The Reconnect automatically switch, including turning it off mid-retry."""

import time

from harness import run_window_harness


def scenario(window, checks, done):
    from pervius.ui import window as window_module

    window_module.verify_managed_profile = lambda *_args, **_kwargs: ()
    window._verify_for = lambda *_args, **_kwargs: None
    window_module._RECONNECT = window_module.ReconnectPolicy((30, 30))
    window._start_poll = lambda: None

    def row():
        return (window.auto_reconnect_row.get_active(), window.settings.auto_reconnect)

    def drop(reason):
        window._stop_timer()
        window.active = None
        window._existing_connection = object()
        window._intent_connected = True
        window._connected_since = time.monotonic()
        window._set_state("connected")
        window._connection_lost(reason)

    checks.equal("initial", row(), (True, True))
    window.auto_reconnect_row.set_active(False)
    checks.equal("off", row(), (False, False))
    drop("switch test drop")
    checks.equal("no retry while off", window._state, "idle")
    window.auto_reconnect_row.set_active(True)
    checks.equal("on", row(), (True, True))
    drop("switch test drop 2")
    checks.equal("retrying", window._state, "reconnecting")
    window.auto_reconnect_row.set_active(False)
    checks.equal("off during retry", window._state, "idle")
    checks.equal("off banner", window.banner.get_title(), "Automatic reconnection disabled.")
    done()


raise SystemExit(run_window_harness("reconnect_switch", scenario, delay_ms=1500))
