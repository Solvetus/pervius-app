"""Start the main window and check the idle state after the catalogue loads."""

from harness import run_window_harness


def scenario(window, checks, done):
    checks.equal("state", window._state, "idle")
    checks.equal("catalogue profiles", window.catalogue.profile_count if window.catalogue else None, 16)
    checks.equal("default location", window.settings.location_key, "AD/Andorra la Vella")
    checks.equal("protocol", window.settings.protocol, "udp")
    checks.true("agent registered (stubbed)", window.agent and window.agent.registered)
    checks.true("NetworkManager client", window.client and window.client.get_nm_running())
    checks.true("connect button sensitive", window.connect_button.get_sensitive())
    checks.equal("title", window.status_title.get_label(), "Not connected")
    checks.equal("no banner", window.banner.get_revealed(), False)
    done()


raise SystemExit(run_window_harness("smoke", scenario, delay_ms=3000))
