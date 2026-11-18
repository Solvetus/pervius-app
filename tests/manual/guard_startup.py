"""Leak guard right after install: options sent at startup, warning only from fresh status.

Regression: the first connection after an upgrade warned "IPv6 is not
blocked outside the tunnel" from a status poll taken before the tunnel was
up, although the guard was in place.
"""

from gi.repository import GLib

from harness import run_window_harness

OFF = {"armed": False, "state": "off", "endpoints": 0, "allow_lan": False}


def scenario(window, checks, done):
    calls = []

    class Client:
        def set_guard_options(self, block, interfaces):
            calls.append(("guard", block, tuple(interfaces)))
            return dict(OFF)

        def status(self):
            calls.append(("status",))
            return dict(OFF, guard=True)  # the guard is in place now

    window.killswitch = Client()
    window._killswitch_ready = False
    window._guard_sent = None  # as on the first start after install
    window._killswitch_status_inflight = True
    window._on_killswitch_status(dict(OFF, guard=False), None)

    def after_startup():
        checks.equal("options sent on first status", calls, [("guard", True, ())])
        calls.clear()
        window._connected_since = 0
        window._state = "connected"
        window._tunnel_device_busy = lambda: True
        window._killswitch_status = dict(OFF, guard=False)  # stale poll
        window._check_tunnel_and_guard()
        GLib.timeout_add(500, after_check)
        return False

    def after_check():
        checks.equal("fresh status asked", calls, [("status",)])
        checks.equal("no false warning", "IPv6 is not blocked" in (window.banner.get_title() or ""), False)
        done()
        return False

    GLib.timeout_add(500, after_startup)


raise SystemExit(run_window_harness("guard_startup", scenario))
