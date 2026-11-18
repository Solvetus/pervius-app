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
        "Armed — VPN not connected; internet traffic is blocked.",
    )
    checks.equal("allow LAN editable while armed", (window.allow_lan_row.get_active(), window.allow_lan_row.get_sensitive()), (False, True))
    checks.equal("blocked card shown while armed", window.killswitch_note.get_visible(), True)
    checks.equal("location allowed while armed", window.location_button.get_sensitive(), True)
    checks.equal("protocol allowed while armed", window.protocol_switch.get_sensitive(), True)
    configured = []
    window._configure_killswitch = lambda: configured.append(window.settings.killswitch_allow_lan)
    window.allow_lan_row.set_active(True)
    checks.equal("LAN change applied live", configured, [True])
    window.settings.killswitch_allow_lan = False
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
    checks.equal("allow LAN insensitive while off", window.allow_lan_row.get_sensitive(), False)
    checks.equal("blocked card hidden while off", window.killswitch_note.get_visible(), False)
    done()


raise SystemExit(run_window_harness("killswitch_ui", scenario))
