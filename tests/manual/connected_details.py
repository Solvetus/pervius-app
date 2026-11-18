"""Connection details panel while connected: exit IP, traffic, timer, Switch IP, IP toggle."""

from gi.repository import GLib

from harness import DOC_IP, run_window_harness


def scenario(window, checks, done):
    window._set_state("connected")
    window._read_tunnel_counters = lambda: (1000, 500, "tun9")
    window._update_stats()
    window._read_tunnel_counters = lambda: (2536, 909, "tun9")
    window._update_stats()

    def report():
        checks.true("details visible", window.connection_details.get_visible())
        checks.equal("IPs hidden by default", window.isp_ip_value.get_text(), "•••.•••.•••.•••")
        checks.equal("exit IP hidden", window.vpn_ip_value.get_text(), "•••.•••.•••.•••")
        checks.equal("hidden IPs not selectable", window.isp_ip_value.get_selectable(), False)
        window.ip_toggle.set_active(True)
        checks.equal("ISP IP", window.isp_ip_value.get_text(), DOC_IP)
        checks.equal("VPN exit IP", window.vpn_ip_value.get_text(), DOC_IP)
        checks.equal("preference saved", window.settings_store.load().show_ip_addresses, True)
        window.ip_toggle.set_active(False)
        checks.equal("hidden again", window.vpn_ip_value.get_text(), "•••.•••.•••.•••")
        checks.equal("protocol", window.protocol_value.get_text(), "OpenVPN · UDP")
        checks.equal("timer shown", window.duration_column.get_visible(), True)
        checks.equal("counters shown", window.download_column.get_visible(), True)
        checks.equal("Switch IP shown", window.switch_ip_button.get_visible(), True)
        checks.true("subtitle has no protocol", "UDP" not in window.status_subtitle.get_label())
        checks.equal("download", window.download_value.get_text(), "1.5 KB")
        checks.equal("upload", window.upload_value.get_text(), "409 B")
        calls = []
        window._disconnect = lambda: calls.append("disconnect")
        window._switch_ip()
        checks.equal("Switch IP reconnect pending", window._reconnect_after_disconnect, True)
        checks.equal("Switch IP disconnects", calls, ["disconnect"])
        checks.equal("no banner after Switch IP", window.banner.get_revealed(), False)
        done()
        return False

    GLib.timeout_add(1200, report)


raise SystemExit(run_window_harness("connected_details", scenario))
