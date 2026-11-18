"""Kill-switch rendering from a fake armed/off service status."""

from harness import run_window_harness

ARMED = {"armed": True, "state": "armed", "detail": "Rules installed", "endpoints": 14, "allow_lan": False}
OFF = {"armed": False, "state": "off", "detail": "Not armed", "endpoints": 0, "allow_lan": False}


def scenario(window, checks, done):
    window._killswitch_status_inflight = True  # stop real polls updating
    window._on_killswitch_status(ARMED, None)
    checks.equal("armed", window._killswitch_armed, True)
    checks.equal("switch", (window.killswitch_row.get_active(), window.killswitch_row.get_sensitive()), (True, True))
    checks.equal(
        "subtitle",
        window.killswitch_row.get_subtitle(),
        "Armed — VPN not connected; internet traffic is blocked. Disarm before changing location or protocol.",
    )
    checks.equal("allow LAN locked", (window.allow_lan_row.get_active(), window.allow_lan_row.get_sensitive()), (False, False))
    checks.equal("location locked", window.location_button.get_sensitive(), False)
    checks.equal("protocol locked", window.protocol_switch.get_sensitive(), False)
    item = next(item for item in window._tray_menu() if item.action == "killswitch")
    checks.equal("tray toggle", (item.toggle_state, item.enabled), (1, True))

    confirmations = []
    window._confirm_disable_killswitch = lambda: confirmations.append("disable")
    window.killswitch_row.set_active(False)
    checks.equal("turning off asks first", confirmations, ["disable"])
    checks.equal("switch stays on until confirmed", window.killswitch_row.get_active(), True)

    window._on_killswitch_status(OFF, None)
    checks.equal(
        "off",
        (window._killswitch_armed, window.killswitch_row.get_active(), window.location_button.get_sensitive()),
        (False, False, True),
    )
    done()


raise SystemExit(run_window_harness("killswitch_ui", scenario))
