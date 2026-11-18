"""Connection details panel while disconnected."""

from harness import DOC_IP, run_window_harness


def scenario(window, checks, done):
    checks.equal("state", window._state, "idle")
    checks.true("details visible", window.connection_details.get_visible())
    checks.equal("ISP IP hidden", window.isp_ip_value.get_text(), "•••.•••.•••.•••")
    window.ip_toggle.set_active(True)
    checks.equal("ISP IP", window.isp_ip_value.get_text(), DOC_IP)
    checks.equal("VPN exit IP hidden while disconnected", window.vpn_ip_value.get_visible(), False)
    checks.equal("counters hidden", (window.download_column.get_visible(), window.upload_column.get_visible()), (False, False))
    checks.equal("timer hidden", window.duration_column.get_visible(), False)
    checks.equal("protocol", window.protocol_value.get_text(), "OpenVPN · UDP")
    checks.equal("Switch IP hidden", window.switch_ip_button.get_visible(), False)
    done()


raise SystemExit(run_window_harness("idle_details", scenario, delay_ms=2500))
