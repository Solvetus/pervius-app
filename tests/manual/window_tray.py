"""Window tray: StatusNotifierItem registration, menu order, status line and icons."""

import time

from gi.repository import GLib

from harness import run_window_harness


def scenario(window, checks, done):
    window._start_poll = lambda: None
    checks.true("tray registered", window.tray is not None)
    if window.tray is None:
        done()
        return
    menu = window._tray_menu()
    labels = [(item.id, item.label, item.enabled) for item in menu if not item.separator]
    checks.equal("menu ids", [item.id for item in menu], [1, 2, 3, 4, 5, 6, 7, 8])
    checks.equal(
        "menu labels",
        [item[1] for item in labels],
        ["Not connected", "Connect — Andorra la Vella, Andorra", "Favorites", "Choose Location…",
         "Kill switch", "Show Pervius", "Quit"],
    )
    checks.equal("status line greyed", labels[0][2], False)
    checks.equal("separator before kill switch", menu[4].separator, True)
    killswitch = next(item for item in menu if item.action == "killswitch")
    checks.equal("kill switch is a checkmark", killswitch.toggle_state, 0)
    checks.equal("idle icon", window._tray_icon_name(), "com.solvetus.Pervius-tray-off")
    checks.equal("tooltip has no protocol", "UDP" not in window._tray_tooltip()[1], True)
    window._reconnect_in_flight = True
    window._state = "reconnecting"
    checks.equal("reconnecting icon", window._tray_icon_name(), "com.solvetus.Pervius-tray-reconnecting")
    checks.equal("reconnecting line", window._tray_menu()[0].label, "Reconnecting…")
    checks.equal("stop retrying", window._tray_menu()[1].label, "Stop Retrying")
    window._reconnect_in_flight = False
    window._state = "idle"

    def connect():
        window._connected_since = time.monotonic() - 12
        window._set_state("connected")
        checks.equal("connected icon", window._tray_icon_name(), "com.solvetus.Pervius-tray-connected")
        menu = window._tray_menu()
        checks.equal("status line", menu[0].label, "Connected — Andorra la Vella, Andorra · 00:12")
        checks.equal("primary when connected", menu[1].label, "Disconnect")
        done()
        return False

    GLib.timeout_add(1000, connect)


raise SystemExit(run_window_harness("window_tray", scenario, delay_ms=2500))
