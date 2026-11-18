"""Activation waits until the previous OpenVPN has released pervius0.

Regression: after a switch the new activation started while the old process
still held the pinned device and failed ("TUNSETIFF pervius0: Device or
resource busy"); GNOME showed "Activation of network connection failed".
"""

from gi.repository import GLib

from harness import run_window_harness


def scenario(window, checks, done):
    import pervius.ui.window as module

    busy = {"value": True}
    started = []
    window._tunnel_device_busy = lambda: busy["value"]
    module.activate_async = lambda client, connection, cb: started.append(connection)
    window._start_poll = lambda: None
    window.active = None
    window._intent_connected = True
    window._attempt += 1
    window._activate("conn")

    def still_waiting():
        checks.equal("no activation while pervius0 exists", started, [])
        checks.equal("user is told why", window.status_subtitle.get_label(), "Waiting for the previous tunnel to close…")
        busy["value"] = False
        GLib.timeout_add(600, released)
        return False

    def released():
        checks.equal("activation once the device is gone", started, ["conn"])
        done()
        return False

    GLib.timeout_add(800, still_waiting)


raise SystemExit(run_window_harness("tunnel_wait", scenario))
