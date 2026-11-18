"""Favorites: tray submenu, star toggles, favorites-only filter."""

import gi

gi.require_version("Gtk", "4.0")
from gi.repository import Gtk  # noqa: E402

from harness import run_window_harness  # noqa: E402


def walk(widget):
    child = widget.get_first_child()
    while child is not None:
        yield child
        yield from walk(child)
        child = child.get_next_sibling()


def scenario(window, checks, done):
    from pervius.ui.window import LocationWindow

    window._start_poll = lambda: None
    window.settings.favorites = ["PT/Lisbon", "ES/Madrid"]
    window._refresh_tray()
    items = window._tray_favorite_items()
    checks.equal(
        "tray favorites",
        [(item.id, item.label, item.action) for item in items if not item.separator],
        [
            (201, "🇵🇹 Lisbon, Portugal", "favorite|PT/Lisbon"),
            (202, "🇪🇸 Madrid, Spain", "favorite|ES/Madrid"),
            (299, "Manage Favorites…", "locations"),
        ],
    )

    catalogue = window.catalogue
    toggled = []
    chooser = LocationWindow(
        window,
        catalogue.locations,
        catalogue.location_by_key("PT/Lisbon"),
        lambda _location: None,
        favorites={"PT/Lisbon"},
        on_favorite_toggled=lambda key, enabled: toggled.append((key, enabled)),
    )
    rows = [chooser.listbox.get_row_at_index(i) for i in range(len(catalogue.locations))]
    lisbon = next(row for row in rows if row._location.key == "PT/Lisbon")
    star = next(c for c in walk(lisbon.get_child()) if isinstance(c, Gtk.ToggleButton))
    checks.equal("star initially active", (star.get_active(), star.get_icon_name()), (True, "starred-symbolic"))
    chooser.favorites_only.set_active(True)
    checks.equal("favorites-only count", sum(1 for row in rows if chooser._filter(row)), 1)
    star.set_active(False)
    checks.equal("toggle callback", toggled, [("PT/Lisbon", False)])
    checks.equal("favorites-only after unstar", sum(1 for row in rows if chooser._filter(row)), 0)
    chooser.close()
    done()


raise SystemExit(run_window_harness("favorites", scenario))
