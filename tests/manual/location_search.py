"""Location search: country names, codes, aliases, cities."""

import sys

from harness import Checks, prepare

prepare()

import gi  # noqa: E402

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk  # noqa: E402

from pervius.catalogue import CatalogueStore  # noqa: E402
from pervius.ui.window import LocationWindow  # noqa: E402

Gtk.init()
Adw.init()
checks = Checks("location_search")
catalogue = CatalogueStore().load()
window = LocationWindow(None, catalogue.locations, None, lambda _location: None)
rows = [window.listbox.get_row_at_index(i) for i in range(len(catalogue.locations))]

for query, expected in (
    ("Portugal", ["PT/Lisbon"]),
    ("United States", ["US/Ashburn", "US/New York"]),
    ("USA", ["US/Ashburn", "US/New York"]),
    ("britain", ["GB/Belfast", "GB/London"]),
    ("lisboa", []),
    ("Tokyo", ["JP/Tokyo"]),
    ("andorra la vella", ["AD/Andorra la Vella"]),
):
    window.search.set_text(query)
    checks.equal(f"search {query!r}", [row._location.key for row in rows if window._filter(row)], expected)

window.close()
sys.exit(checks.exit_code())
