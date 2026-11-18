"""Background notifications for a drop and an automatic reconnect."""

import time

from gi.repository import GLib

from harness import run_window_harness


def scenario(window, checks, done):
    from pervius.ui import window as window_module

    window_module.verify_managed_profile = lambda *_args, **_kwargs: ()
    window._verify_for = lambda *_args, **_kwargs: None
    window_module._RECONNECT = window_module.ReconnectPolicy((1, 1))
    notes = []
    window._start_poll = lambda: None
    window._send_notification = lambda title, body: notes.append((title, body))
    window.set_visible(False)
    window._stop_timer()
    window.settings.auto_reconnect = True
    window.active = None
    window._existing_connection = object()
    window._intent_connected = True
    window._connected_since = time.monotonic()
    window._set_state("connected")

    def success(_connection, reconnecting=False):
        window._reconnect_in_flight = reconnecting
        window._set_connected()

    window._activate = success
    window._connection_lost("test drop")
    checks.equal("after drop", notes, [("VPN connection lost", "Reconnecting automatically in a few seconds.")])

    def after():
        checks.equal(
            "after reconnect",
            notes[1:],
            [("VPN reconnected", "Connected to Andorra la Vella, Andorra.")],
        )
        done()
        return False

    GLib.timeout_add(2000, after)


raise SystemExit(run_window_harness("notifications", scenario, delay_ms=1500))
