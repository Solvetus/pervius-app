"""UDP/TCP linked switch: exclusivity; changes are allowed while the kill switch is armed."""

from harness import run_window_harness


def scenario(window, checks, done):
    window._killswitch_status_inflight = True

    def state():
        return (window.settings.protocol, window.udp_button.get_active(), window.tcp_button.get_active())

    checks.equal("initial", state(), ("udp", True, False))
    window.tcp_button.set_active(True)
    checks.equal("TCP selected", state(), ("tcp", False, True))
    checks.equal("row shows no protocol", window.location_row.get_subtitle(), "🇦🇩 Andorra la Vella, Andorra")
    checks.equal("details show TCP", window.protocol_value.get_text(), "OpenVPN · TCP")
    window.udp_button.set_active(True)
    checks.equal("UDP selected", state(), ("udp", True, False))
    window.udp_button.set_active(False)
    checks.equal("clicking the active side keeps it", state(), ("udp", True, False))
    window._killswitch_armed = True
    window.tcp_button.set_active(True)
    checks.equal("armed allows TCP", state(), ("tcp", False, True))
    checks.equal("no lock banner", window.banner.get_revealed(), False)
    window._killswitch_armed = False
    done()


raise SystemExit(run_window_harness("protocol_switch", scenario))
