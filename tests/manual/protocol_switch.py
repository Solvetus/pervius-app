"""UDP/TCP linked switch: exclusivity and the kill-switch lock."""

from harness import run_window_harness


def scenario(window, checks, done):
    window._killswitch_status_inflight = True

    def state():
        return (window.settings.protocol, window.udp_button.get_active(), window.tcp_button.get_active())

    checks.equal("initial", state(), ("udp", True, False))
    window.tcp_button.set_active(True)
    checks.equal("TCP selected", state(), ("tcp", False, True))
    checks.equal("row shows TCP", window.location_row.get_subtitle(), "🇦🇩 Andorra la Vella, Andorra · TCP")
    window.udp_button.set_active(True)
    checks.equal("UDP selected", state(), ("udp", True, False))
    window.udp_button.set_active(False)
    checks.equal("clicking the active side keeps it", state(), ("udp", True, False))
    window._killswitch_armed = True
    window.tcp_button.set_active(True)
    checks.equal("armed reverts", state(), ("udp", True, False))
    checks.equal("armed banner", window.banner.get_title(), "Disarm the kill switch before changing protocol.")
    window._killswitch_armed = False
    done()


raise SystemExit(run_window_harness("protocol_switch", scenario))
