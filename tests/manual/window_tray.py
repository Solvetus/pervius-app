"""Window tray: StatusNotifierItem registration and the full menu layout."""

import time

from gi.repository import GLib

from harness import run_window_harness


def scenario(window, checks, done):
    window._start_poll = lambda: None
    checks.true("tray registered", window.tray is not None)
    if window.tray is None:
        done()
        return
    labels = [(item.id, item.label, item.enabled) for item in window._tray_menu() if not item.separator]
    checks.equal("menu ids", [item[0] for item in labels], [1, 2, 3, 4, 6, 8, 9, 10, 12, 13, 15, 16])
    checks.equal("primary", labels[1], (2, "Connect — Andorra la Vella, Andorra", True))
    checks.equal("forget disabled without username", labels[-2][2], False)
    checks.equal("idle icon", window._tray_icon_name().endswith("-disconnected"), True)

    def connect():
        window._connected_since = time.monotonic()
        window._set_state("connected")
        checks.equal("connected icon", window._tray_icon_name().endswith("-connected"), True)
        primary = next(item for item in window._tray_menu() if item.id == 2)
        checks.equal("primary when connected", primary.label, "Disconnect")
        done()
        return False

    GLib.timeout_add(1000, connect)


raise SystemExit(run_window_harness("window_tray", scenario, delay_ms=2500))
