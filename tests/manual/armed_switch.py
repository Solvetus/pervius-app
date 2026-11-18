"""Profiles are always pinned before activating; armed switches resolve through the live tunnel."""

from gi.repository import GLib

from harness import run_window_harness

ARMED = {"armed": True, "state": "armed", "detail": "", "endpoints": 1, "allow_lan": False, "guard": True}


def scenario(window, checks, done):
    import pervius.ui.window as module
    from pervius.killswitch_client import KillSwitchError
    from pervius.killswitchd.rules import Endpoint

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

        def set_guard_options(self, block, interfaces):
            events.append(("guard", block, tuple(interfaces)))
            return dict(ARMED)

    window.killswitch = Client()

    def write_profile(connection, *, pins, then, on_error):
        if pins is module.NAMES:
            events.append(("write", "names"))
        elif pins is module.KEEP_PINS:
            events.append(("write", "keep"))
        else:
            events.append(("write", tuple(e.address for e in pins)))
        then(connection)

    previous_pins = {"value": ()}

    class Fresh:
        pass

    module.fetch_settings_async = lambda connection, cb: cb(Fresh(), None)
    module.pinned_endpoints = lambda fresh, protocol: previous_pins["value"]
    window._write_profile = write_profile
    window._activate = lambda connection, reconnecting=False: events.append(("activate", reconnecting))
    window._disconnect = lambda: events.append(("disconnect",))
    window._ensure_profile = lambda *, then, on_error, on_blocked, quiet=False: then("conn")

    def begin():
        window._intent_connected = True
        window._attempt += 1

    begin()
    window._finalize_and_activate("conn")

    def after_connect():
        checks.equal(
            "armed connect: names, resolve, pin, activate (guard options sent at startup)",
            events,
            [("write", "names"), ("update", True), ("write", ("192.0.2.30",)), ("activate", False)],
        )
        events.clear()
        begin()
        window._finalize_and_activate("conn")
        checks.equal("fresh pins are reused", events, [("write", ("192.0.2.30",)), ("activate", False)])
        events.clear()
        window._pins = None
        begin()
        window._finalize_and_activate("conn", reconnecting=True)
        GLib.timeout_add(300, after_reconnect)
        return False

    def after_reconnect():
        checks.equal("reconnect merges", events[:3], [("write", "names"), ("update", False), ("write", ("192.0.2.30",))])
        events.clear()
        # Resolution fails: the earlier pins are kept (never left on bare names).
        Client.fail = True
        previous_pins["value"] = (Endpoint("192.0.2.40", 1194, "udp"),)
        window._pins = None
        begin()
        window._finalize_and_activate("conn")
        GLib.timeout_add(300, after_failed_refresh)
        return False

    def after_failed_refresh():
        checks.equal(
            "failed refresh re-pins the previous addresses",
            events,
            [("write", "names"), ("update", True), ("write", ("192.0.2.40",)), ("activate", False)],
        )
        events.clear()
        Client.fail = False
        previous_pins["value"] = ()
        # Switching a connected tunnel resolves first, then disconnects.
        window._state = "connected"
        window._pins = None
        window._switch_connected_to(window.catalogue.location_by_key("PT/Lisbon"))
        GLib.timeout_add(300, after_switch)
        return False

    def after_switch():
        checks.equal(
            "switch resolves through the live tunnel and keeps the old server",
            events,
            [("write", "names"), ("update", False), ("write", ("192.0.2.30",)), ("disconnect",)],
        )
        checks.equal("switch selected the new location", window.settings.location_key, "PT/Lisbon")
        events.clear()
        # Kill switch off: the app resolves the names itself and pins them.
        window._on_killswitch_status({"armed": False, "state": "off", "endpoints": 0, "allow_lan": False}, None)
        lookups = []
        module.resolve_endpoints_async = lambda remotes, protocol, cb: (
            lookups.append(list(remotes)),
            cb((Endpoint("192.0.2.50", 1194, "udp"),), []),
        )
        window._state = "idle"
        window._pins = None
        begin()
        window._finalize_and_activate("conn")
        checks.equal("unarmed connect looks the names up", len(lookups), 1)
        checks.equal(
            "unarmed connect pins before activating",
            events,
            [("write", ("192.0.2.50",)), ("activate", False)],  # guard options unchanged: not resent
        )
        done()
        return False

    GLib.timeout_add(300, after_connect)


raise SystemExit(run_window_harness("armed_switch", scenario))
