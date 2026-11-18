"""Kill switch armed: endpoints are resolved and pinned before activating or switching."""

from gi.repository import GLib

from harness import run_window_harness

ARMED = {"armed": True, "state": "armed", "detail": "", "endpoints": 1, "allow_lan": False, "ipv6_guard": True}


def scenario(window, checks, done):
    from pervius.killswitch_client import KillSwitchError

    window._killswitch_status_inflight = True
    window._on_killswitch_status(dict(ARMED), None)
    events = []
    resolved = [("192.0.2.30", 1194, "udp")]

    class Client:
        fail = False

        def update_endpoints(self, replace):
            events.append(("update", replace))
            if Client.fail:
                raise KillSwitchError("could not resolve", "ResolveFailed")
            return dict(ARMED, resolved=resolved)

    window.killswitch = Client()

    def write_profile(connection, *, pins, then, on_error):
        events.append(("write", "keep" if pins is not None and not isinstance(pins, tuple) else
                       tuple(e.address for e in pins) if pins else None))
        then(connection)

    window._write_profile = write_profile
    window._activate = lambda connection, reconnecting=False: events.append(("activate", reconnecting))
    window._disconnect = lambda: events.append(("disconnect",))
    window._ensure_profile = lambda *, then, on_error, on_blocked, quiet=False: then("conn")

    window._finalize_and_activate("conn")

    def after_connect():
        checks.equal(
            "connect while armed resolves, pins, activates",
            events,
            [("update", True), ("write", ("192.0.2.30",)), ("activate", False)],
        )
        events.clear()
        window._finalize_and_activate("conn")
        checks.equal("fresh pins are reused", events, [("write", ("192.0.2.30",)), ("activate", False)])
        events.clear()
        window._pins = None
        window._finalize_and_activate("conn", reconnecting=True)
        GLib.timeout_add(300, after_reconnect)
        return False

    def after_reconnect():
        checks.equal(
            "reconnect merges (replace=False)",
            events[:2],
            [("update", False), ("write", ("192.0.2.30",))],
        )
        events.clear()
        # Switching a connected tunnel resolves first, then disconnects.
        window._state = "connected"
        target = window.catalogue.location_by_key("PT/Lisbon")
        window._pins = None
        window._switch_connected_to(target)
        GLib.timeout_add(300, after_switch)
        return False

    def after_switch():
        checks.equal(
            "switch resolves before dropping the tunnel",
            events,
            [("update", True), ("write", ("192.0.2.30",)), ("disconnect",)],
        )
        checks.equal("switch selected the new location", window.settings.location_key, "PT/Lisbon")
        events.clear()
        Client.fail = True
        window._pins = None
        before = window.settings.location_key
        window._switch_connected_to(window.catalogue.location_by_key("US/Ashburn"))
        GLib.timeout_add(300, lambda: after_failed_switch(before))
        return False

    def after_failed_switch(before):
        checks.equal("failed switch keeps the tunnel", events, [("update", True)])
        checks.equal("failed switch restores the location", window.settings.location_key, before)
        checks.true("failed switch explains", "Could not switch location" in window.banner.get_title())
        done()
        return False

    GLib.timeout_add(300, after_connect)


raise SystemExit(run_window_harness("armed_switch", scenario))
