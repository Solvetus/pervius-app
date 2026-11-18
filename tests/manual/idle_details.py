"""Connection details panel while disconnected."""

from harness import DOC_IP, run_window_harness


def scenario(window, checks, done):
    checks.equal("state", window._state, "idle")
    checks.true("details visible", window.connection_details.get_visible())
    checks.equal("ISP IP hidden", window.isp_ip_value.get_text(), "•••.•••.•••.•••")
    window.ip_toggle.set_active(True)
    checks.equal("ISP IP", window.isp_ip_value.get_text(), DOC_IP)
    # The details keep their place so the card never changes size.
    checks.equal("VPN exit IP placeholder", (window.vpn_ip_value.get_visible(), window.vpn_ip_value.get_text()), (True, "—"))
    checks.equal("counters placeholders", (window.download_value.get_text(), window.upload_value.get_text()), ("—", "—"))
    checks.equal("timer placeholder", (window.duration_column.get_visible(), window.duration_value.get_text()), (True, "—"))
    checks.equal("protocol", window.protocol_value.get_text(), "OpenVPN · UDP")
    checks.equal("Switch IP shown but insensitive", (window.switch_ip_button.get_visible(), window.switch_ip_button.get_sensitive()), (True, False))
    done()


raise SystemExit(run_window_harness("idle_details", scenario, delay_ms=2500))
