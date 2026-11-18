"""One column, a stable card, self-dismissing toasts, dismissible banners, a roomy header."""

import time

from gi.repository import Adw, GLib, Gtk

from harness import run_window_harness

LONG_ERROR = (
    "Could not prepare the VPN profile: the NetworkManager profile could not be verified because "
    "the certificate file changed on disk and Pervius refuses to use it until it is imported again."
)


def walk(widget):
    child = widget.get_first_child()
    while child is not None:
        yield child
        yield from walk(child)
        child = child.get_next_sibling()


def bounds(widget, relative_to):
    ok, rect = widget.compute_bounds(relative_to)
    return (round(rect.get_x()), round(rect.get_width())) if ok else None


def scenario(window, checks, done):
    window._start_poll = lambda: None
    root = window.status_card.get_parent()
    children = []
    child = root.get_first_child()
    while child is not None:
        children.append(child)
        child = child.get_next_sibling()
    groups = [c for c in children if isinstance(c, Adw.PreferencesGroup)]
    window._show_banner("A banner that is visible")  # so its edges can be measured too

    states = [
        ("idle", ""),
        ("preparing", ""),
        ("connecting", ""),
        ("connected", ""),
        ("reconnecting", ""),
        ("error", LONG_ERROR),
        ("blocked", LONG_ERROR),
        ("idle", ""),
    ]
    sizes = []

    def measure(index=0):
        if index == len(states):
            return finish()
        state, detail = states[index]
        if state == "connected":
            window._connected_since = time.monotonic()
        if state == "reconnecting":
            window._reconnect_deadline = time.monotonic() + 5
            window._reconnect_attempt = 1
        window._set_state(state, detail)

        def after():
            sizes.append((state, window.status_card.get_width(), window.status_card.get_height(),
                          window.get_width(), window.get_height()))
            GLib.idle_add(lambda: measure(index + 1) and False)
            return False

        GLib.timeout_add(250, after)

    def finish():
        card = {(w, h) for _s, w, h, _ww, _wh in sizes}
        win = {(ww, wh) for _s, _w, _h, ww, wh in sizes}
        checks.equal("card size is identical in every state", len(card), 1)
        checks.equal("window size is identical in every state", len(win), 1)
        print("sizes:", sorted(card), sorted(win), flush=True)

        # One column: banner, status card and every group share left edge and width.
        edges = {bounds(window.banner, root), bounds(window.status_card, root)} | {bounds(g, root) for g in groups}
        checks.equal("banner, card and groups share one column", len(edges), 1)

        # Subtitle reserves two lines.
        heights = set()
        for text in ("one line", "x " * 120):
            window.status_subtitle.set_label(text)
            heights.add(window.status_subtitle.measure(Gtk.Orientation.VERTICAL, window.status_subtitle.get_width())[0])
        checks.equal("subtitle reserves a fixed height", len(heights), 1)

        # Toasts: recorded with a ~3 s timeout (they dismiss themselves).
        window.recorded_toasts.clear()
        for method in ("A kill-switch operation is already in progress.", "Kill switch disabled. Normal traffic is allowed."):
            window._toast(method)
        checks.equal("toasts auto-dismiss after 3 s", {t.get_timeout() for t in window.recorded_toasts}, {3})

        # Banners: the cross dismisses; a dismissed condition stays quiet until a new attempt.
        window._show_banner("Something needs attention")
        checks.equal("banner has a dismiss button", window.banner.get_button_label(), "✕")
        window.banner.emit("button-clicked")
        checks.equal("dismissed", window.banner.get_revealed(), False)
        window._show_banner("Something needs attention")
        checks.equal("same condition stays dismissed", window.banner.get_revealed(), False)
        window._show_banner("Something else")
        checks.equal("a changed condition shows again", window.banner.get_revealed(), True)
        window._clear_banner()
        window._show_banner("Something needs attention")
        checks.equal("a new attempt shows it again", window.banner.get_revealed(), True)

        # Header: a little taller, with room above, below and between the lines.
        header = next(w for w in walk(window) if isinstance(w, Adw.HeaderBar))
        labels = [w for w in walk(header) if isinstance(w, Gtk.Label) and w.get_label() in ("Pervius", "Unofficial client for FastVPN")]
        title = next(w for w in labels if w.get_label() == "Pervius")
        sub = next(w for w in labels if w.get_label() != "Pervius")
        _ok1, t_rect = title.compute_bounds(header)
        _ok2, s_rect = sub.compute_bounds(header)
        top = t_rect.get_y()
        gap = s_rect.get_y() - (t_rect.get_y() + t_rect.get_height())
        bottom = header.get_height() - (s_rect.get_y() + s_rect.get_height())
        print(f"header: height={header.get_height()} top={top:.1f} gap={gap:.1f} bottom={bottom:.1f}", flush=True)
        checks.true("header is taller", header.get_height() >= 56)
        checks.true("room above the title", top >= 6)
        checks.true("room between title and subtitle", gap >= 2)
        checks.true("room below the subtitle", bottom >= 6)
        done()
        return False

    GLib.timeout_add(600, lambda: measure() and False)


raise SystemExit(run_window_harness("layout_stable", scenario, delay_ms=1500))
