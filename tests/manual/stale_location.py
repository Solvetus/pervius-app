"""Selecting a location updates both the row and the idle status line."""

from harness import run_window_harness


def scenario(window, checks, done):
    for key, label in (
        ("PT/Lisbon", "🇵🇹 Lisbon, Portugal"),
        ("US/Ashburn", "🇺🇸 Ashburn, United States"),
        ("AD/Andorra la Vella", "🇦🇩 Andorra la Vella, Andorra"),
    ):
        window._select_location(window.catalogue.location_by_key(key))
        checks.equal(f"{key} row", window.location_row.get_subtitle(), label)
        checks.equal(f"{key} status", window.status_subtitle.get_label(), label)
    done()


raise SystemExit(run_window_harness("stale_location", scenario, delay_ms=3000))
