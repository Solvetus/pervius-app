"""Connection details panel while disconnected."""

from harness import DOC_IP, run_window_harness


def scenario(window, checks, done):
    checks.equal("state", window._state, "idle")
    checks.true("details visible", window.connection_details.get_visible())
    checks.equal("ISP IP", window.isp_ip_value.get_text(), DOC_IP)
    checks.equal("VPN exit IP", window.vpn_ip_value.get_text(), "—")
    checks.equal("download", window.download_value.get_text(), "—")
    checks.equal("upload", window.upload_value.get_text(), "—")
    checks.equal("protocol", window.protocol_value.get_text(), "OpenVPN · UDP")
    checks.equal("Switch IP sensitive", window.switch_ip_button.get_sensitive(), False)
    done()


raise SystemExit(run_window_harness("idle_details", scenario, delay_ms=2500))
