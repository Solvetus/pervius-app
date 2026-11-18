"""Main window and dialogs.

The UI is deliberately conservative: it exposes only actions that are backed
by the tested backend.  The kill switch is shown only with the state reported
by the system service; there is no auto-protect or DNS-filter toggle.
"""

from __future__ import annotations

import locale
import logging
import math
import threading
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("NM", "1.0")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk, NM, Pango  # noqa: E402

from .. import autostart, i18n
from ..catalogue import Catalogue, CatalogueStore, Location, ProfileRef, parse_catalogue
from ..catalogue.fetcher import fetch_catalogue
from ..config import (  # noqa: E402
    APP_ID,
    APP_NAME,
    APP_TAGLINE,
    CATALOGUE_URL,
    DEVELOPER_NAME,
    DISCLAIMER,
    HOMEPAGE_URL,
    ISSUES_URL,
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    NOTIFICATION_ID,
    OPENVPN_SERVICE_TYPE,
    TUNNEL_INTERFACE,
    STATUS_ICON_CONNECTED,
    STATUS_ICON_OFF,
    TRAY_ICON_CONNECTED,
    TRAY_ICON_OFF,
    TRAY_ICON_RECONNECTING,
    VERSION,
    certificate_dir,
    local_username,
)
from ..credentials import CredentialStore  # noqa: E402
from ..i18n import C_, _, ngettext  # noqa: E402
from ..killswitch_client import KillSwitchClient, call_async  # noqa: E402
from ..killswitchd.rules import Endpoint, RulesError, validate_interfaces  # noqa: E402
from ..migration import REFUSED, migrate_profile  # noqa: E402
from ..nm.agent import AgentError, NetworkManagerSecretAgent  # noqa: E402
from ..nm.client import (  # noqa: E402
    NetworkManagerError,
    activate_async,
    active_vpn_for_uuid,
    add_connection_async,
    deactivate_async,
    fetch_settings_async,
    new_client,
    prepare_managed_profile_async,
    update_connection_async,
    vpn_state_name,
    vpn_state_reason,
)
from ..nm.importer import ImportVerificationError, verify_managed_profile  # noqa: E402
from ..nm.profile import (  # noqa: E402
    build_variant,
    clone,
    pin_remote,
    pinned_endpoints,
    remote_names,
    strip_user_data,
    unpin_remote,
)
from ..resolve import resolve_endpoints_async  # noqa: E402
from ..ownership import (
    ManagedLookup,
    OwnershipError,
    OwnershipEntry,
    OwnershipStore,
    check_create_collision,
    find_managed_connection,
)
from ..public_ip import fetch_public_ip, fetch_public_ip_through  # noqa: E402
from ..reconnect import ReconnectPolicy  # noqa: E402
from ..settings import Settings, SettingsStore  # noqa: E402
from .account import CredentialsWindow  # noqa: E402
from .tray import MenuItem, TrayError, TrayIcon  # noqa: E402

log = logging.getLogger(__name__)

_RECONNECT = ReconnectPolicy()
_ACTIVE_STATES = {"preparing", "reconnecting", "connecting", "connected", "disconnecting"}
# Endpoints resolved within this many seconds are reused instead of asking the
# kill-switch service again (e.g. right after a switch prepared them).
_PINS_FRESH_SECONDS = 60
TOAST_SECONDS = 3
# One content column: the banner, the status card and every group share it.
DEFAULT_WIDTH = 470
# Bumped when the default size changes so a size saved by an older build is
# dropped once; the size is remembered again from then on.
WINDOW_SIZE_EPOCH = 1
CONTENT_WIDTH = 620
HEADER_HEIGHT = 58
_HIDDEN_IP = "•••.•••.•••.•••"
KEEP_PINS = object()
NAMES = object()


_CSS = f"""
/* A little more room in the header; the font size stays GNOME's own. */
headerbar.pervius-header {{ min-height: {HEADER_HEIGHT}px; }}
"""
_css_installed = False


def _install_css() -> None:
    global _css_installed
    if _css_installed:
        return
    provider = Gtk.CssProvider()
    provider.load_from_string(_CSS)
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
    )
    _css_installed = True


def format_duration(seconds: int) -> str:
    """00:12, 59:59, 1:02:03 — compact, locale-neutral."""
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def place_name(location: Location | None, *, flag: bool = False) -> str:
    if location is None:
        return ""
    # Translators: a VPN location; {0} is the city, {1} the country.
    text = _("{0}, {1}").format(location.display_city, location.display_country)
    return f"{location.flag} {text}" if flag and location.flag else text


def killswitch_error_text(error: Exception) -> str:
    """A translated sentence for a kill-switch service failure."""
    code = getattr(error, "code", "Failed")
    if code == "PermissionDenied":
        return _("You are not allowed to change the kill switch.")
    if code == "NotAvailable":
        return _("The kill-switch service is not available.")
    if code == "NotArmed":
        return _("The kill switch is not armed.")
    if code == "ResolveFailed":
        return _("The VPN server addresses could not be resolved.")
    # Translators: {0} is a technical error message (English).
    return _("The kill-switch service reported an error: {0}").format(error)


class LocationWindow(Adw.Window):
    def __init__(
        self,
        parent,
        locations: tuple[Location, ...],
        selected: Location | None,
        on_selected,
        favorites: set[str] | None = None,
        on_favorite_toggled=None,
    ):
        super().__init__()
        self._locations = locations
        self._on_selected = on_selected
        self._favorites = set(favorites or ())
        self._on_favorite_toggled = on_favorite_toggled or (
            lambda _key, _enabled: None
        )
        self.set_title(_("Choose Location"))
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_default_size(500, 650)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        close = Gtk.Button(label=_("Close"))
        close.connect("clicked", lambda *_: self.close())
        header.pack_end(close)
        toolbar.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)

        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text(_("Search city or country"))
        self.search.connect("search-changed", lambda *_: self.listbox.invalidate_filter())
        search_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.search.set_hexpand(True)
        search_row.append(self.search)
        self.favorites_only = Gtk.ToggleButton()
        self.favorites_only.set_icon_name("starred-symbolic")
        self.favorites_only.set_tooltip_text(_("Show favorites only"))
        self.favorites_only.add_css_class("flat")
        self.favorites_only.connect(
            "toggled", lambda *_: self.listbox.invalidate_filter()
        )
        search_row.append(self.favorites_only)
        box.append(search_row)

        self.listbox = Gtk.ListBox()
        self.listbox.set_selection_mode(Gtk.SelectionMode.NONE)
        self.listbox.set_filter_func(self._filter)
        self.listbox.connect("row-activated", self._row_activated)
        for location in locations:
            self.listbox.append(self._make_row(location))

        scroller = Gtk.ScrolledWindow()
        scroller.set_vexpand(True)
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(self.listbox)
        box.append(scroller)

        note = Gtk.Label()
        note.set_wrap(True)
        note.set_xalign(0.0)
        note.add_css_class("dim-label")
        note.set_label(
            _(
                "Locations come from the provider's public catalogue. "
                "Star a location to add it to Favorites and the tray menu; search "
                "understands city names, country names, codes, and common aliases."
            )
        )
        box.append(note)

        toolbar.set_content(box)
        self.set_content(toolbar)
        if selected is not None:
            self.listbox.select_row(None)
        self.search.grab_focus()

    def _make_row(self, location: Location) -> Gtk.ListBoxRow:
        row = Gtk.ListBoxRow()
        row._location = location  # type: ignore[attr-defined]
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(10)
        box.set_margin_end(10)
        flag = Gtk.Label(label=location.flag)
        flag.set_valign(Gtk.Align.CENTER)
        flag.add_css_class("title-3")
        if location.flag:
            box.append(flag)
        labels = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        title = Gtk.Label(label=location.display_city)
        title.set_xalign(0.0)
        title.add_css_class("body")
        subtitle = Gtk.Label(
            label=f"{location.display_country} · {' / '.join(p.upper() for p in location.protocols)}"
        )
        subtitle.set_xalign(0.0)
        subtitle.add_css_class("caption")
        subtitle.add_css_class("dim-label")
        labels.append(title)
        labels.append(subtitle)
        labels.set_hexpand(True)
        box.append(labels)

        favorite = location.key in self._favorites
        star = Gtk.ToggleButton()
        star.set_active(favorite)
        star.set_icon_name("starred-symbolic" if favorite else "non-starred-symbolic")
        star.set_tooltip_text(
            _("Remove from favorites") if favorite else _("Add to favorites")
        )
        star.add_css_class("flat")
        star.connect("toggled", self._favorite_toggled, location)
        box.append(star)

        chevron = Gtk.Image.new_from_icon_name("go-next-symbolic")
        chevron.add_css_class("dim-label")
        box.append(chevron)
        row.set_child(box)
        return row

    def _favorite_toggled(self, button: Gtk.ToggleButton, location: Location):
        enabled = button.get_active()
        if enabled:
            self._favorites.add(location.key)
        else:
            self._favorites.discard(location.key)
        button.set_icon_name("starred-symbolic" if enabled else "non-starred-symbolic")
        button.set_tooltip_text(
            _("Remove from favorites") if enabled else _("Add to favorites")
        )
        self._on_favorite_toggled(location.key, enabled)
        self.listbox.invalidate_filter()

    def _filter(self, row: Gtk.ListBoxRow) -> bool:
        location: Location = row._location  # type: ignore[attr-defined]
        if self.favorites_only.get_active() and location.key not in self._favorites:
            return False
        query = self.search.get_text().strip()
        if not query:
            return True
        return location.matches(query)

    def _row_activated(self, _listbox, row: Gtk.ListBoxRow) -> None:
        location: Location = row._location  # type: ignore[attr-defined]
        self._on_selected(location)
        self.close()


class MainWindow(Adw.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title(APP_NAME)
        self.set_default_size(DEFAULT_WIDTH, 760)

        self.settings_store = SettingsStore()
        self.settings: Settings = self.settings_store.load()
        if self.settings.window_size_epoch < WINDOW_SIZE_EPOCH:
            self.settings.window_width = self.settings.window_height = 0
            self.settings.window_maximized = False
            self.settings.window_size_epoch = WINDOW_SIZE_EPOCH
            try:
                self.settings_store.save(self.settings)
            except OSError:
                pass
        if self.settings.window_width:
            self.set_default_size(self.settings.window_width, self.settings.window_height)
        if self.settings.window_maximized:
            self.maximize()
        self.local_username = local_username()
        self.catalogue_store = CatalogueStore()
        self.catalogue: Catalogue | None = None
        self.credentials = CredentialStore()
        self.ownership: OwnershipStore | None = None
        self.client: NM.Client | None = None
        self.agent: NetworkManagerSecretAgent | None = None
        self.tray: TrayIcon | None = None
        self.killswitch = KillSwitchClient()
        self._killswitch_status: dict | None = None
        self._killswitch_armed = False
        self._killswitch_busy = False
        self._killswitch_status_inflight = False
        self._killswitch_timer: int | None = None
        self._killswitch_syncing = False
        self._killswitch_last_error = ""
        self._killswitch_pending = ""
        self._killswitch_ready = False
        self._interfaces_row = None
        self._dismissed_banners: set[str] = set()
        self._banner_text = ""
        # Incremented by every connect and cancel; late callbacks of an older
        # attempt see a different value and do nothing.
        self._attempt = 0
        self._activation_cancellable = None
        # (location key, protocol, endpoints, monotonic time) from the service.
        self._pins: tuple | None = None
        self._guard_warned = False
        self._guard_sent: tuple | None = None
        self._isp_ip = ""
        self._vpn_exit_ip = ""
        self._ip_fetching = ""
        self._isp_ip_checked = False
        self._stats_source: int | None = None
        self._stats_baseline: tuple[int, int] | None = None
        self._stats_iface = ""
        self._reconnect_after_disconnect = False
        self.active: NM.VpnConnection | None = None
        self._existing_connection: NM.Connection | None = None
        self._old_entry: OwnershipEntry | None = None
        self._prepared = None
        self._catalogue_thread: threading.Thread | None = None
        self._catalogue_loading = False
        self._poll_source: int | None = None
        self._timer_source: int | None = None
        self._reconnect_source: int | None = None
        self._connected_since: float | None = None
        self._connect_deadline: float | None = None
        self._reconnect_attempt = 0
        self._reconnect_deadline: float | None = None
        self._reconnect_reason = ""
        self._reconnect_in_flight = False
        self._intent_connected = False
        self._state = "loading"
        self._quitting = False
        self._allow_close = False
        self._quit_after_disconnect = False
        self._connect_after_credentials = False
        self._disposed = False
        self._warning = ""
        self._blocked_reason = ""
        self._migration_problem = ""
        self._pending_switch_key: str | None = None

        self._build_actions()
        self._build_ui()
        self._init_backend()
        self._init_tray()
        self._init_killswitch()
        self._load_catalogue()

    # ------------------------------------------------------------------ UI

    def _build_actions(self):
        for name, callback in (
            ("refresh", lambda *_: self._load_catalogue(force=True)),
            ("settings", lambda *_: self._show_settings()),
            ("help", lambda *_: self._show_help()),
            ("about", lambda *_: self._show_about()),
            ("quit", lambda *_: self._request_quit(None)),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    def _build_ui(self):
        toolbar = Adw.ToolbarView()
        _install_css()
        header = Adw.HeaderBar()
        header.add_css_class("pervius-header")
        header.set_centering_policy(Adw.CenteringPolicy.STRICT)
        title = Adw.WindowTitle(title=APP_NAME)
        header.set_title_widget(title)

        menu = Gio.Menu()
        menu.append(_("Refresh Locations"), "win.refresh")
        menu.append(_("Settings"), "win.settings")
        menu.append(_("Help"), "win.help")
        menu.append(_("About Pervius"), "win.about")
        menu.append(_("Quit"), "win.quit")
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_menu_model(menu)
        menu_button.set_tooltip_text(_("Main menu"))
        header.pack_end(menu_button)
        toolbar.add_top_bar(header)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        root.set_margin_top(18)
        root.set_margin_bottom(24)
        root.set_margin_start(18)
        root.set_margin_end(18)

        self.banner = Adw.Banner.new("")
        # Adw.Banner has one text button; the cross dismisses the banner.
        self.banner.set_button_label("✕")
        self.banner.connect("button-clicked", self._on_banner_dismissed)
        self.banner.set_revealed(False)
        root.append(self.banner)

        status_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        status_card.add_css_class("card")
        status_card.set_margin_top(4)
        status_card.set_margin_bottom(4)
        status_card.set_valign(Gtk.Align.START)
        self.status_card = status_card

        self.status_stack = Gtk.Stack()
        self.status_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.status_stack.set_margin_top(20)
        self.status_stack.set_margin_start(18)
        self.status_stack.set_margin_end(18)
        self.status_icon = Gtk.Image.new_from_icon_name(STATUS_ICON_OFF)
        self.status_icon.set_pixel_size(72)
        self.status_spinner = Gtk.Spinner()
        self.status_spinner.set_size_request(48, 48)
        self.status_stack.add_named(self.status_icon, "icon")
        spinner_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        spinner_box.set_halign(Gtk.Align.CENTER)
        spinner_box.append(self.status_spinner)
        self.status_stack.add_named(spinner_box, "spinner")
        self.status_stack.set_size_request(-1, 80)
        status_card.append(self.status_stack)

        self.status_title = Gtk.Label(label=_("Starting…"))
        self.status_title.add_css_class("title-1")
        self.status_title.set_wrap(False)
        self.status_title.set_ellipsize(Pango.EllipsizeMode.END)
        self.status_title.set_margin_start(18)
        self.status_title.set_margin_end(18)
        status_card.append(self.status_title)

        self.status_subtitle = Gtk.Label(label="")
        self.status_subtitle.add_css_class("dim-label")
        self.status_subtitle.set_wrap(True)
        self.status_subtitle.set_lines(2)
        self.status_subtitle.set_ellipsize(Pango.EllipsizeMode.END)
        self.status_subtitle.set_justify(Gtk.Justification.CENTER)
        # Always two lines high, so error text never pushes content down.
        self.status_subtitle.connect("realize", self._reserve_subtitle_height)
        self.status_subtitle.set_margin_start(22)
        self.status_subtitle.set_margin_end(22)
        self.status_subtitle.set_margin_bottom(8)
        status_card.append(self.status_subtitle)

        self.connect_button = Gtk.Button(label=_("Connect"))
        self.connect_button.add_css_class("pill")
        self.connect_button.add_css_class("suggested-action")
        self.connect_button.set_halign(Gtk.Align.CENTER)
        self.connect_button.set_size_request(230, 46)
        self.connect_button.set_margin_top(8)
        self.connect_button.set_margin_bottom(22)
        self.connect_button.set_margin_start(24)
        self.connect_button.set_margin_end(24)
        self.connect_button.connect("clicked", self._on_connect_clicked)
        status_card.append(self.connect_button)

        self.connection_details = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=10
        )
        self.connection_details.set_margin_top(4)
        self.connection_details.set_margin_start(24)
        self.connection_details.set_margin_end(24)
        self.connection_details.set_margin_bottom(20)

        caption_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        ip_caption = Gtk.Label(label=_("IP ADDRESSES"))
        ip_caption.add_css_class("caption")
        ip_caption.add_css_class("dim-label")
        ip_caption.set_xalign(0.0)
        ip_caption.set_hexpand(True)
        caption_row.append(ip_caption)
        self.ip_toggle = Gtk.ToggleButton()
        self.ip_toggle.add_css_class("flat")
        self.ip_toggle.set_valign(Gtk.Align.CENTER)
        self.ip_toggle.set_active(bool(self.settings.show_ip_addresses))
        self.ip_toggle.connect("toggled", self._on_ip_toggle)
        caption_row.append(self.ip_toggle)
        self.connection_details.append(caption_row)

        ip_grid = Gtk.Grid()
        ip_grid.set_column_spacing(14)
        ip_grid.set_row_spacing(4)
        ip_grid.set_halign(Gtk.Align.CENTER)
        isp_name = Gtk.Label(label=_("ISP IP"))
        isp_name.add_css_class("dim-label")
        isp_name.set_xalign(1.0)
        self.isp_ip_value = Gtk.Label(label="—")
        self.isp_ip_value.set_xalign(0.0)
        self.vpn_ip_name = Gtk.Label(label=_("VPN exit IP"))
        self.vpn_ip_name.add_css_class("dim-label")
        self.vpn_ip_name.set_xalign(1.0)
        self.vpn_ip_value = Gtk.Label(label="—")
        self.vpn_ip_value.set_xalign(0.0)
        ip_grid.attach(isp_name, 0, 0, 1, 1)
        ip_grid.attach(self.isp_ip_value, 1, 0, 1, 1)
        ip_grid.attach(self.vpn_ip_name, 0, 1, 1, 1)
        ip_grid.attach(self.vpn_ip_value, 1, 1, 1, 1)
        self.connection_details.append(ip_grid)

        self.switch_ip_button = Gtk.Button(label=_("Switch IP"))
        self.switch_ip_button.add_css_class("flat")
        self.switch_ip_button.set_halign(Gtk.Align.CENTER)
        self.switch_ip_button.set_tooltip_text(
            _("Reconnect the VPN to request a different server IP.")
        )
        self.switch_ip_button.connect("clicked", lambda *_args: self._switch_ip())
        self.connection_details.append(self.switch_ip_button)

        self.connection_details.append(Gtk.Separator())

        stats = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        stats.set_homogeneous(True)
        stats.set_halign(Gtk.Align.CENTER)

        def stat_column(icon_name: str, caption: str, value_label: Gtk.Label):
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            column.set_halign(Gtk.Align.CENTER)
            icon = Gtk.Image.new_from_icon_name(icon_name)
            icon.set_pixel_size(18)
            icon.add_css_class("dim-label")
            column.append(icon)
            value_label.set_xalign(0.5)
            value_label.add_css_class("body")
            column.append(value_label)
            caption_label = Gtk.Label(label=caption)
            caption_label.add_css_class("caption")
            caption_label.add_css_class("dim-label")
            column.append(caption_label)
            return column

        self.download_value = Gtk.Label(label="—")
        self.download_value.set_tooltip_text(_("Traffic received since this connection"))
        self.upload_value = Gtk.Label(label="—")
        self.upload_value.set_tooltip_text(_("Traffic sent since this connection"))
        self.protocol_value = Gtk.Label(label="UDP")
        self.duration_value = Gtk.Label(label="—")
        self.duration_value.set_tooltip_text(_("Time since the VPN connected"))
        self.download_column = stat_column(
            "go-down-symbolic", C_("traffic", "Download"), self.download_value
        )
        self.upload_column = stat_column("go-up-symbolic", C_("traffic", "Upload"), self.upload_value)
        self.duration_column = stat_column(
            # Translators: caption under the time since the VPN connected.
            "preferences-system-time-symbolic", C_("duration", "Connected"), self.duration_value
        )
        stats.append(self.download_column)
        stats.append(self.upload_column)
        stats.append(stat_column("network-vpn-symbolic", "OpenVPN", self.protocol_value))
        stats.append(self.duration_column)
        self.connection_details.append(stats)
        status_card.append(self.connection_details)
        root.append(status_card)

        group = Adw.PreferencesGroup()
        group.set_title(_("Connection"))
        self.location_row = Adw.ActionRow()
        self.location_row.set_title(_("Location"))
        self.location_row.set_subtitle(_("Not selected"))
        self.location_row.set_icon_name("mark-location-symbolic")
        change = Gtk.Button(label=_("Change"))
        change.add_css_class("flat")
        change.set_valign(Gtk.Align.CENTER)
        change.connect("clicked", lambda *_args: self._open_locations())
        self.location_row.add_suffix(change)
        self.location_button = change
        group.add(self.location_row)

        self.protocol_row = Adw.ActionRow()
        self.protocol_row.set_title(_("Protocol"))
        self.protocol_row.set_tooltip_text(
            _(
                "UDP is the usual default. Try TCP only when UDP is blocked. "
                "Both carry the same encrypted tunnel; see Help for details."
            )
        )
        self.protocol_row.set_icon_name("network-wired-symbolic")
        self.protocol_switch = Gtk.Box(
            orientation=Gtk.Orientation.HORIZONTAL, spacing=0
        )
        self.protocol_switch.add_css_class("linked")
        self.protocol_switch.set_valign(Gtk.Align.CENTER)
        self.protocol_switch.set_halign(Gtk.Align.END)
        self.udp_button = Gtk.ToggleButton(label="UDP")
        self.tcp_button = Gtk.ToggleButton(label="TCP")
        self.udp_button.set_size_request(64, 34)
        self.tcp_button.set_size_request(64, 34)
        self.udp_button.set_tooltip_text(_("UDP — lower latency; the usual choice."))
        self.tcp_button.set_tooltip_text(
            _("TCP — use when the network blocks or filters UDP.")
        )
        self.protocol_switch.append(self.udp_button)
        self.protocol_switch.append(self.tcp_button)
        self._protocol_syncing = True
        if self.settings.protocol == "tcp":
            self.tcp_button.set_active(True)
        else:
            self.udp_button.set_active(True)
        self._protocol_syncing = False
        self.udp_button.connect("toggled", self._on_protocol_toggled)
        self.tcp_button.connect("toggled", self._on_protocol_toggled)
        self.protocol_row.add_suffix(self.protocol_switch)
        group.add(self.protocol_row)

        self.account_row = Adw.ActionRow()
        self.account_row.set_title(_("Account"))
        self.account_row.set_subtitle(_("Credentials not set"))
        self.account_row.set_icon_name("avatar-default-symbolic")
        edit = Gtk.Button(label=_("Edit"))
        edit.add_css_class("flat")
        edit.set_valign(Gtk.Align.CENTER)
        edit.connect("clicked", lambda *_args: self._open_credentials(False))
        self.account_row.add_suffix(edit)
        self.account_button = edit
        group.add(self.account_row)

        self.auto_reconnect_row = Adw.SwitchRow()
        self.auto_reconnect_row.set_title(_("Reconnect automatically"))
        self.auto_reconnect_row.set_subtitle(
            _(
                "Retry after an unexpected drop, with increasing delays. "
                "Manual disconnects and failed first attempts never retry."
            )
        )
        self.auto_reconnect_row.set_icon_name("emblem-synchronizing-symbolic")
        self.auto_reconnect_row.set_active(bool(self.settings.auto_reconnect))
        self.auto_reconnect_row.connect(
            "notify::active", self._on_auto_reconnect_changed
        )
        group.add(self.auto_reconnect_row)
        root.append(group)

        security = Adw.PreferencesGroup()
        security.set_title(_("Security"))
        self.killswitch_row = Adw.SwitchRow()
        self.killswitch_row.set_title(_("Kill switch"))
        self.killswitch_row.set_subtitle(_("Checking the system service…"))
        self.killswitch_row.set_icon_name("security-high-symbolic")
        self.killswitch_row.set_sensitive(False)
        self.killswitch_row.connect("notify::active", self._on_killswitch_switch)
        security.add(self.killswitch_row)

        self.allow_lan_row = Adw.SwitchRow()
        self.allow_lan_row.set_title(_("Allow local network"))
        self.allow_lan_row.set_subtitle(
            _("Permit RFC 1918/ULA traffic while the kill switch is armed.")
        )
        self.allow_lan_row.set_icon_name("network-workgroup-symbolic")
        self.allow_lan_row.set_active(bool(self.settings.killswitch_allow_lan))
        self.allow_lan_row.set_sensitive(False)
        self.allow_lan_row.connect("notify::active", self._on_allow_lan_changed)
        security.add(self.allow_lan_row)

        self.killswitch_note = Adw.ActionRow()
        self.killswitch_note.set_title(_("Traffic outside the VPN is blocked"))
        self.killswitch_note.set_subtitle(
            _(
                "Only the VPN servers, the tunnel, the interfaces you always allow, "
                "DHCP and link control may pass. DNS outside the tunnel and global "
                "IPv6 are blocked."
            )
        )
        self.killswitch_note.set_icon_name("dialog-warning-symbolic")
        self.killswitch_note.set_visible(False)
        security.add(self.killswitch_note)
        root.append(security)

        self.footer = Gtk.Label()
        self.footer.set_wrap(True)
        self.footer.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
        self.footer.set_justify(Gtk.Justification.CENTER)
        self.footer.set_xalign(0.5)
        self.footer.set_hexpand(True)
        self.footer.add_css_class("caption")
        self.footer.add_css_class("dim-label")
        self._reset_footer()
        root.append(self.footer)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        clamp = Adw.Clamp()
        clamp.set_maximum_size(CONTENT_WIDTH)
        clamp.set_tightening_threshold(CONTENT_WIDTH)
        clamp.set_child(root)
        scroller.set_child(clamp)
        toolbar.set_content(scroller)
        # Toasts float over the content; they dismiss themselves.
        self.toasts = Adw.ToastOverlay()
        self.toasts.set_child(toolbar)
        self.set_content(self.toasts)

        self.connect("close-request", self._on_close_request)
        self._update_ip_toggle()
        self._set_state("loading")
        self._update_account_row()
        self._update_location_row()

    def _reserve_subtitle_height(self, label, *_args):
        metrics = label.get_pango_context().get_metrics(None, None)
        line = (metrics.get_ascent() + metrics.get_descent()) / Pango.SCALE
        label.set_size_request(-1, int(math.ceil(2 * line)) + 2)

    def _reset_footer(self):
        lines = (
            # Translators: footer, first line; {0} is the app name, {1} its version.
            _("{0} {1} · Unofficial client for FastVPN").format(APP_NAME, VERSION),
            # Translators: footer, second line; {0} is the catalogue host name.
            _("Not affiliated with Namecheap · Servers: {0}").format("vpn.ncapi.io"),
        )
        self.footer.set_label("\n".join(lines))

    def _init_backend(self):
        try:
            self.client = new_client()
        except NetworkManagerError as exc:
            # Translators: {0} is a technical error message.
            self._blocked(_("NetworkManager is unavailable: {0}").format(exc))
            return
        # Adopt the 0.1.x managed profile before anything looks it up.
        result = migrate_profile(self.client.get_connections(), self.local_username)
        if result.status == REFUSED:
            log.warning("could not adopt the previous managed profile: %s", result.detail)
            self._migration_problem = result.detail
        try:
            self.agent = NetworkManagerSecretAgent(
                self.credentials,
                lambda: self.settings.username,
                store_provider=OwnershipStore.load,
            )
            self.agent.register()
        except AgentError as exc:
            log.warning("secret agent unavailable: %s", exc)
            self.agent = None
            # Translators: {0} is a technical error message.
            self._blocked(_("The NetworkManager secret agent could not be registered: {0}").format(exc))
            return
        self._reconcile_active()

    # ------------------------------------------------------------------ tray

    def _init_tray(self):
        try:
            self.tray = TrayIcon(
                app_id=APP_ID,
                title=APP_NAME,
                icon_name=TRAY_ICON_OFF,
                menu_provider=self._tray_menu,
                tooltip_provider=self._tray_tooltip,
                action_handler=self._tray_action,
                activate_handler=self._present_from_tray,
                secondary_handler=self._tray_toggle_connection,
                icon_provider=self._tray_icon_name,
            )
            self.tray.register()
        except (TrayError, Exception) as exc:
            log.warning("tray icon unavailable: %s", exc)
            self.tray = None
            return
        self._refresh_tray()

    def _refresh_tray(self):
        if getattr(self, "tray", None) is not None:
            self.tray.refresh()

    def _shutdown_tray(self):
        if getattr(self, "tray", None) is not None:
            self.tray.shutdown()
            self.tray = None

    # ----------------------------------------------------------- kill switch

    def _init_killswitch(self):
        self._refresh_killswitch_status()
        self._killswitch_timer = GLib.timeout_add_seconds(5, self._killswitch_poll)

    def _killswitch_poll(self):
        if self._disposed:
            self._killswitch_timer = None
            return False
        if not self._killswitch_busy:
            self._refresh_killswitch_status()
        return True

    def _stop_killswitch_poll(self):
        if self._killswitch_timer is not None:
            GLib.source_remove(self._killswitch_timer)
            self._killswitch_timer = None

    def _refresh_killswitch_status(self):
        if self._killswitch_status_inflight:
            return
        self._killswitch_status_inflight = True
        call_async(self.killswitch.status, self._on_killswitch_status)

    def _on_killswitch_status(self, status, error):
        self._killswitch_status_inflight = False
        if self._disposed:
            return
        was_armed = self._killswitch_armed
        if error is not None:
            self._killswitch_status = None
            self._killswitch_last_error = str(error)
        else:
            self._killswitch_status = status
            self._killswitch_last_error = ""
        first = not self._killswitch_ready
        self._killswitch_ready = True
        if first and status is not None:
            # Make sure the leak guard has the options (and is on an already
            # active tunnel) right after install or upgrade.
            self._send_guard_options()
        self._render_killswitch_state()
        if self._killswitch_armed and not was_armed:
            self._isp_ip_checked = True
        elif was_armed and not self._killswitch_armed:
            self._isp_ip_checked = False
        if self._state == "connected":
            self._maybe_fetch_ip("vpn")
        elif not self._killswitch_armed and self._state in {"idle", "error"}:
            self._maybe_fetch_ip("isp")
        self._update_ip_labels()
        self._refresh_tray()

    def _set_killswitch_switch(self, value: bool):
        self._killswitch_syncing = True
        try:
            self.killswitch_row.set_active(bool(value))
        finally:
            self._killswitch_syncing = False

    def _set_allow_lan_switch(self, value: bool):
        self._killswitch_syncing = True
        try:
            self.allow_lan_row.set_active(bool(value))
        finally:
            self._killswitch_syncing = False

    def _render_killswitch_state(self):
        status = self._killswitch_status
        if status is None:
            armed = self._killswitch_armed
            self._set_killswitch_switch(armed)
            self.killswitch_row.set_sensitive(False)
            self.killswitch_row.set_subtitle(
                _("The kill-switch service is unavailable.")
                if self._killswitch_last_error
                else _("System service unavailable; the optional package is not active.")
            )
            self._set_allow_lan_switch(bool(self.settings.killswitch_allow_lan))
            self.allow_lan_row.set_sensitive(False)
            self.killswitch_note.set_visible(False)
            self._update_controls()
            return

        armed = bool(status.get("armed"))
        state = str(status.get("state", "off"))
        endpoints = int(status.get("endpoints", 0) or 0)
        self._killswitch_armed = armed
        self._set_killswitch_switch(armed)
        self.killswitch_row.set_sensitive(not self._killswitch_busy)
        if self._killswitch_busy:
            subtitle = _("Applying…")
        elif state == "error":
            subtitle = _(
                "The system service reported an error. Disarm, then arm the kill switch again."
            )
        elif armed:
            if self._state == "connected":
                subtitle = ngettext(
                    "Armed — {0} VPN endpoint allowed; all other traffic is blocked.",
                    "Armed — {0} VPN endpoints allowed; all other traffic is blocked.",
                    endpoints,
                ).format(endpoints)
            else:
                subtitle = _("Armed — VPN not connected; internet traffic is blocked.")
        else:
            subtitle = _("Off — normal network traffic is allowed.")
        self.killswitch_row.set_subtitle(subtitle)

        # The kill-switch options only matter while it is armed; they apply
        # live through the service.
        if armed:
            self._set_allow_lan_switch(bool(status.get("allow_lan")))
        else:
            self._set_allow_lan_switch(bool(self.settings.killswitch_allow_lan))
        self.allow_lan_row.set_sensitive(armed and state == "armed" and not self._killswitch_busy)
        self.killswitch_note.set_visible(armed and state == "armed")
        if self._interfaces_row is not None:
            self._interfaces_row.set_sensitive(armed and state == "armed" and not self._killswitch_busy)
        self._update_controls()

    def _on_killswitch_switch(self, row, _pspec):
        if self._killswitch_syncing:
            return
        desired = bool(row.get_active())
        if desired == self._killswitch_armed:
            return
        self._set_killswitch_switch(self._killswitch_armed)
        if self._killswitch_busy:
            self._toast(_("A kill-switch operation is already in progress."))
        elif desired:
            self._confirm_enable_killswitch()
        else:
            self._confirm_disable_killswitch()

    def _on_allow_lan_changed(self, row, _pspec):
        if self._killswitch_syncing:
            return
        value = bool(row.get_active())
        self.settings.killswitch_allow_lan = value
        try:
            self.settings_store.save(self.settings)
        except Exception as exc:
            log.warning("could not save kill-switch LAN preference: %s", exc)
        if self._killswitch_armed:
            self._configure_killswitch()

    def _configure_killswitch(self):
        """Apply LAN access and the allowed interfaces to the armed kill switch."""
        if self._killswitch_busy:
            self._toast(_("A kill-switch operation is already in progress."))
            return
        self._killswitch_busy = True
        self._killswitch_pending = "configure"
        self._render_killswitch_state()
        allow_lan = bool(self.settings.killswitch_allow_lan)
        interfaces = list(self.settings.killswitch_interfaces)
        call_async(
            lambda: self.killswitch.configure(allow_lan, interfaces),
            self._on_killswitch_action_done,
        )

    def _confirm_enable_killswitch(self):
        local = (
            _("Local network traffic will remain allowed.")
            if self.settings.killswitch_allow_lan
            else _("Local network traffic will also be blocked.")
        )
        dialog = Adw.AlertDialog.new(
            _("Enable the kill switch?"),
            # Translators: {0} says whether local network traffic stays allowed.
            _(
                "All traffic outside the VPN will be blocked, including DNS and "
                "global IPv6. If the VPN is not connected, normal internet access "
                "will stop until you disarm it or connect. {0}"
            ).format(local),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("enable", _("Enable"))
        dialog.set_close_response("cancel")
        dialog.set_default_response("cancel")
        dialog.set_response_appearance("enable", Adw.ResponseAppearance.SUGGESTED)

        def response(_dialog, response_id):
            if response_id == "enable":
                self._arm_killswitch()

        dialog.connect("response", response)
        dialog.present(self)

    def _confirm_disable_killswitch(self):
        dialog = Adw.AlertDialog.new(
            _("Disable the kill switch?"),
            _(
                "The firewall rules will be removed and normal network traffic will "
                "be allowed again, even if the VPN is down."
            ),
        )
        dialog.add_response("cancel", _("Cancel"))
        dialog.add_response("disable", _("Disable"))
        dialog.set_close_response("cancel")
        dialog.set_default_response("cancel")
        dialog.set_response_appearance("disable", Adw.ResponseAppearance.DESTRUCTIVE)

        def response(_dialog, response_id):
            if response_id == "disable":
                self._disarm_killswitch()

        dialog.connect("response", response)
        dialog.present(self)

    def _arm_killswitch(self):
        if self._killswitch_busy:
            return
        self._killswitch_busy = True
        self._killswitch_pending = "arm"
        self._render_killswitch_state()
        self._refresh_tray()
        allow_lan = bool(self.settings.killswitch_allow_lan)
        interfaces = list(self.settings.killswitch_interfaces)
        call_async(
            lambda: self.killswitch.arm(allow_lan, interfaces),
            self._on_killswitch_action_done,
        )

    def _disarm_killswitch(self):
        if self._killswitch_busy:
            return
        self._killswitch_busy = True
        self._killswitch_pending = "disarm"
        self._render_killswitch_state()
        self._refresh_tray()
        call_async(self.killswitch.disarm, self._on_killswitch_action_done)

    def _on_killswitch_action_done(self, status, error):
        pending = self._killswitch_pending
        self._killswitch_pending = ""
        self._killswitch_busy = False
        if self._disposed:
            return
        if error is not None:
            # Translators: {0} explains why the kill-switch change failed.
            self._show_banner(_("Kill-switch operation failed: {0}").format(killswitch_error_text(error)))
            self._refresh_killswitch_status()
            return
        self._killswitch_status = status
        self._killswitch_last_error = ""
        self._killswitch_armed = bool(status.get("armed"))
        self._render_killswitch_state()
        self._refresh_tray()
        if pending == "arm":
            self._isp_ip_checked = True
            self._update_ip_labels()
            self._remember_resolved(status)
            self._pin_now()
            self._toast(_("Kill switch armed. Traffic outside the VPN is blocked."))
        elif pending == "disarm":
            self._isp_ip_checked = False
            self._pins = None
            self._maybe_fetch_ip("isp")
            self._update_ip_labels()
            self._toast(_("Kill switch disabled. Normal traffic is allowed."))
        elif pending == "configure":
            self._toast(_("Kill-switch settings applied."))
        self._refresh_killswitch_status()

    def _toggle_killswitch_from_tray(self):
        self._present_from_tray()
        if self._killswitch_busy:
            self._toast(_("A kill-switch operation is already in progress."))
            return
        if self._killswitch_status is None:
            self._show_banner(_("The kill-switch service is unavailable."))
            self._refresh_killswitch_status()
            return
        if self._killswitch_armed:
            self._confirm_disable_killswitch()
        else:
            self._confirm_enable_killswitch()

    # ------------------------------------------------------ endpoint pinning

    def _remember_endpoints(self, endpoints) -> bool:
        endpoints = tuple(endpoints or ())
        if not endpoints:
            return False
        self._pins = (self.settings.location_key, self.settings.protocol, endpoints, time.monotonic())
        return True

    def _remember_resolved(self, status: dict | None) -> bool:
        """Keep the endpoints the service resolved for us, to pin the profile."""
        endpoints = []
        for item in (status or {}).get("resolved") or ():
            try:
                address, port, protocol = item
                endpoints.append(Endpoint(str(address), int(port), str(protocol)))
            except (RulesError, TypeError, ValueError):
                continue
        return self._remember_endpoints(endpoints)

    def _fresh_pins(self) -> tuple[Endpoint, ...] | None:
        if not self._pins:
            return None
        key, protocol, endpoints, when = self._pins
        if key != self.settings.location_key or protocol != self.settings.protocol:
            return None
        if time.monotonic() - when > _PINS_FRESH_SECONDS:
            return None
        return endpoints

    def _current_names(self) -> str:
        ref = self._selected_ref()
        return remote_names(ref.profile.remotes) if ref is not None else ""

    def _write_profile(self, connection, *, pins, then, on_error):
        """Set the stored profile's remotes, starting from NetworkManager's current settings.

        ``pins`` is a tuple of endpoints (pin them), NAMES (the provider's server
        names from the catalogue, so the kill-switch service resolves them) or
        KEEP_PINS (leave the remotes, only drop stale user-data).  The current
        settings are read from NetworkManager first: libnm's cached copy can lag
        behind our own last write, and writing it back would undo that write.
        """
        def with_fresh(fresh, error):
            if self._disposed:
                return
            if error is not None:
                on_error(str(error))
                return
            try:
                if pins is KEEP_PINS:
                    copy = clone(fresh)
                    strip_user_data(copy)
                elif pins is NAMES:
                    copy = unpin_remote(fresh, self._current_names())
                else:
                    copy = pin_remote(fresh, pins, self.settings.protocol)
                changed = not copy.compare(fresh, NM.SettingCompareFlags.EXACT)
            except Exception as exc:
                on_error(str(exc))
                return
            if not changed:
                then(connection)
                return

            def done(_connection, update_error):
                if self._disposed:
                    return
                if update_error is not None:
                    on_error(str(update_error))
                else:
                    then(connection)

            update_connection_async(connection, build_variant(copy), done)

        fetch_settings_async(connection, with_fresh)

    def _pin_now(self):
        """After arming: pin the stored profile to the endpoints the service allows."""
        pins = self._fresh_pins()
        connection = self._existing_connection
        if not pins or connection is None:
            return
        self._write_profile(
            connection,
            pins=pins,
            then=lambda _c: None,
            on_error=lambda message: log.warning("could not pin the profile: %s", message),
        )

    def _refresh_endpoints(self, *, replace: bool, then, on_error):
        """Ask the service to re-resolve the servers; remember the result."""
        def done(status, error):
            if self._disposed:
                return
            if error is not None:
                on_error(error)
                return
            self._killswitch_status = status
            self._remember_resolved(status)
            self._render_killswitch_state()
            then()

        call_async(lambda: self.killswitch.update_endpoints(replace), done)

    def _resolve_for_kill_switch(self, connection, *, replace: bool, then, on_error):
        """Write the server names, let the service resolve and allow them, keep the result."""
        self._write_profile(
            connection,
            pins=NAMES,
            then=lambda _c: self._refresh_endpoints(replace=replace, then=then, on_error=on_error),
            on_error=lambda message: on_error(RuntimeError(message)),
        )

    def _refresh_after_connect(self, connection):
        """Track provider IP rotation while connected (kill switch armed).

        The server names are resolved through the tunnel's DNS and allowed too;
        the profile ends up pinned either way (to the fresh addresses, or back
        to the ones it had), so it never stays on bare names.
        """
        def with_previous(fresh, error):
            if error is not None or self._disposed:
                return
            previous = pinned_endpoints(fresh, self.settings.protocol)

            def restore(reason):
                log.info("endpoint refresh after connect failed: %s", reason)
                if previous:
                    self._write_profile(
                        connection,
                        pins=previous,
                        then=lambda _c: None,
                        on_error=lambda message: log.warning("could not re-pin the profile: %s", message),
                    )

            # Now that this tunnel is up, drop servers of earlier locations; the
            # service always keeps the live server allowed.
            self._resolve_for_kill_switch(
                connection, replace=True, then=self._pin_now, on_error=restore
            )

        fetch_settings_async(connection, with_previous)

    def _send_guard_options(self, then=None):
        """Give the leak guard (dispatcher hook) the current options, then continue."""
        wanted = (bool(self.settings.block_ipv6), tuple(self.settings.killswitch_interfaces))
        if self._killswitch_status is None or wanted == self._guard_sent:
            if then:
                then()
            return

        def done(_status, error):
            if error is None:
                self._guard_sent = wanted
            else:
                log.warning("could not save the leak guard options: %s", error)
            if then and not self._disposed:
                then()

        call_async(lambda: self.killswitch.set_guard_options(*wanted), done)

    # ------------------------------------------------------- connection details

    def _refresh_connection_details(self):
        connected = self._state == "connected"
        self.protocol_value.set_label(self.settings.protocol.upper())
        # Every detail always keeps its place (so the card never changes size);
        # while disconnected the values show "—" and Switch IP is insensitive.
        if not connected:
            self._stop_stats()
            self._vpn_exit_ip = ""
            self.download_value.set_text("—")
            self.upload_value.set_text("—")
            self.duration_value.set_text("—")
            self._update_ip_labels()
            self._maybe_fetch_ip("isp")
            return
        self._update_duration()
        self._update_ip_labels()
        self._start_stats()
        self._maybe_fetch_ip("vpn")

    def _on_ip_toggle(self, button):
        self.settings.show_ip_addresses = bool(button.get_active())
        try:
            self.settings_store.save(self.settings)
        except Exception as exc:
            log.warning("could not save the IP visibility preference: %s", exc)
        self._update_ip_toggle()
        self._update_ip_labels()

    def _update_ip_toggle(self):
        shown = bool(self.settings.show_ip_addresses)
        self.ip_toggle.set_icon_name("view-conceal-symbolic" if shown else "view-reveal-symbolic")
        self.ip_toggle.set_tooltip_text(_("Hide IP addresses") if shown else _("Show IP addresses"))

    def _maybe_fetch_ip(self, role: str):
        if not self._killswitch_ready or self._ip_fetching:
            return
        if role == "isp":
            if self._killswitch_armed or self._state not in {"idle", "error"}:
                return
            if self._isp_ip_checked:
                return
            self._isp_ip_checked = True
        elif role == "vpn":
            if self._state != "connected":
                return
        else:
            return
        self._ip_fetching = role
        threading.Thread(
            target=self._fetch_ip_worker,
            args=(role,),
            name=f"pervius-public-ip-{role}",
            daemon=True,
        ).start()

    def _fetch_ip_worker(self, role: str):
        try:
            # While connected, our own lookup must resolve through the tunnel
            # only; the ISP address is looked up the normal way while
            # disconnected (it is the point of that lookup).
            ip = fetch_public_ip_through(TUNNEL_INTERFACE) if role == "vpn" else fetch_public_ip()
        except Exception as exc:
            GLib.idle_add(lambda exc=exc: self._on_ip_fetched(role, None, exc))
        else:
            GLib.idle_add(lambda ip=ip: self._on_ip_fetched(role, ip, None))

    def _on_ip_fetched(self, role: str, ip: str | None, error: Exception | None):
        self._ip_fetching = ""
        if self._disposed:
            return
        if role == "isp":
            if self._state == "connected":
                self._maybe_fetch_ip("vpn")
                return
            if self._killswitch_armed or self._state not in {"idle", "error"}:
                return
            self._isp_ip = ip or ""
            self._update_ip_labels()
            return
        if self._state != "connected":
            return
        if error is not None:
            self._vpn_exit_ip = ""
            self._update_ip_labels()
            return
        self._vpn_exit_ip = ip or ""
        self._update_ip_labels()

    def _update_ip_labels(self):
        shown = bool(self.settings.show_ip_addresses)
        isp = self._isp_ip
        if isp:
            isp = isp if shown else _HIDDEN_IP
        elif self._state == "connected" and not self._isp_ip_checked:
            isp = _("Not captured")
        elif self._isp_ip_checked:
            isp = _("Unavailable")
        else:
            isp = _("Checking…")
        self.isp_ip_value.set_text(isp)
        if self._state == "connected":
            vpn = self._vpn_exit_ip
            if vpn:
                vpn = vpn if shown else _HIDDEN_IP
            else:
                vpn = _("Checking…") if self._ip_fetching == "vpn" else _("Unavailable")
        else:
            vpn = "—"
        self.vpn_ip_value.set_text(vpn)
        for label in (self.isp_ip_value, self.vpn_ip_value):
            label.set_selectable(shown)
        self.switch_ip_button.set_sensitive(
            self._state == "connected"
            and not self._ip_fetching
            and not self._reconnect_after_disconnect
        )

    def _switch_ip(self):
        if self._state != "connected" or self._reconnect_after_disconnect:
            return
        self._reconnect_after_disconnect = True
        self.switch_ip_button.set_sensitive(False)
        self._disconnect()

    # -------------------------------------------------------------- traffic

    def _start_stats(self):
        if self._stats_source is None:
            self._stats_baseline = None
            self._stats_iface = ""
            self._update_stats()
            self._stats_source = GLib.timeout_add_seconds(1, self._stats_tick)

    def _stop_stats(self):
        if self._stats_source is not None:
            GLib.source_remove(self._stats_source)
            self._stats_source = None
        self._stats_baseline = None
        self._stats_iface = ""

    def _stats_tick(self):
        if self._disposed or self._state != "connected":
            self._stats_source = None
            return False
        self._update_stats()
        return True

    def _read_tunnel_counters(self):
        # The managed profile pins the tunnel device name.
        base = Path("/sys/class/net") / TUNNEL_INTERFACE / "statistics"
        try:
            rx = int((base / "rx_bytes").read_text(encoding="ascii").strip())
            tx = int((base / "tx_bytes").read_text(encoding="ascii").strip())
        except (OSError, ValueError):
            return None
        return rx, tx, TUNNEL_INTERFACE

    def _update_stats(self):
        counters = self._read_tunnel_counters()
        if counters is None:
            self.download_value.set_text("—")
            self.upload_value.set_text("—")
            return
        rx, tx, iface = counters
        if self._stats_baseline is None or iface != self._stats_iface:
            self._stats_baseline = (rx, tx)
            self._stats_iface = iface
        baseline_rx, baseline_tx = self._stats_baseline
        self.download_value.set_text(
            self._format_bytes(max(0, rx - baseline_rx))
        )
        self.upload_value.set_text(
            self._format_bytes(max(0, tx - baseline_tx))
        )

    @staticmethod
    def _format_bytes(value: int) -> str:
        size = float(max(0, value))
        units = (
            # Translators: byte-count units; {0} is the number.
            C_("bytes", "{0} B"),
            C_("bytes", "{0} KB"),
            C_("bytes", "{0} MB"),
            C_("bytes", "{0} GB"),
            C_("bytes", "{0} TB"),
        )
        for index, unit in enumerate(units):
            if size < 1024.0 or index == len(units) - 1:
                if index == 0:
                    return unit.format(int(size))
                return unit.format(locale.format_string("%.1f", size))
            size /= 1024.0
        return units[-1].format(locale.format_string("%.1f", size))

    def _present_from_tray(self):
        """Show, unminimise and focus the window from the tray.

        The tray host's XDG activation token (if it sent one) lets the
        compositor raise the window; without it GNOME only says
        "Pervius is ready".
        """
        token = self.tray.take_activation_token() if getattr(self, "tray", None) is not None else None
        if token:
            self.set_startup_id(token)
        if not self.get_visible():
            self.set_visible(True)
        self.unminimize()
        self.present()
        app = self.get_application()
        if app is not None:
            app.withdraw_notification(NOTIFICATION_ID)

    def _tray_icon_name(self) -> str:
        if self._state == "connected":
            return TRAY_ICON_CONNECTED
        if self._state == "reconnecting" or (
            self._state == "connecting" and self._reconnect_in_flight
        ):
            return TRAY_ICON_RECONNECTING
        return TRAY_ICON_OFF

    def _status_line(self) -> str:
        """The greyed first line of the tray menu (and the tooltip)."""
        state = self._state
        if state == "connected":
            where = place_name(self._selected_location())
            duration = format_duration(
                time.monotonic() - self._connected_since if self._connected_since else 0
            )
            if where:
                # Translators: tray status; {0} is the location, {1} the time connected.
                return _("Connected — {0} · {1}").format(where, duration)
            # Translators: tray status; {0} is the time connected.
            return _("Connected · {0}").format(duration)
        if state == "reconnecting" or (state == "connecting" and self._reconnect_in_flight):
            return _("Reconnecting…")
        if state in {"preparing", "connecting"}:
            return _("Connecting…")
        if state == "disconnecting":
            return _("Disconnecting…")
        return _("Not connected")

    def _tray_tooltip(self) -> tuple[str, str]:
        return (APP_NAME, self._status_line())

    def _tray_favorite_items(self) -> tuple[MenuItem, ...]:
        children: list[MenuItem] = []
        if self.catalogue is not None:
            for index, key in enumerate(self.settings.favorites[:20]):
                location = self.catalogue.location_by_key(key)
                if location is None:
                    continue
                children.append(
                    MenuItem(201 + index, place_name(location, flag=True), action=f"favorite|{key}")
                )
        if children:
            children.append(MenuItem(298, separator=True))
        else:
            children.append(MenuItem(297, _("No favorites yet"), enabled=False))
        children.append(MenuItem(299, _("Manage Favorites…"), action="locations"))
        return tuple(children)

    def _tray_menu(self) -> tuple[MenuItem, ...]:
        state = self._state
        location = self._selected_location()
        where = place_name(location)
        if state == "connected":
            primary = _("Disconnect")
            primary_enabled = True
        elif state == "reconnecting":
            primary = _("Stop Retrying")
            primary_enabled = True
        elif state in {"preparing", "connecting", "disconnecting"}:
            if state == "disconnecting":
                primary = _("Disconnecting…")
                primary_enabled = False
            else:
                # Translators: tray menu item that stops a connection attempt.
                primary = _("Cancel Connecting")
                primary_enabled = True
        else:
            # Translators: tray menu; {0} is the location.
            primary = _("Connect — {0}").format(where) if where else _("Connect…")
            primary_enabled = bool(
                location is not None
                and self.catalogue is not None
                and self.client is not None
                and self.agent is not None
            )
        busy = state in {"preparing", "connecting", "disconnecting"}
        return (
            MenuItem(1, self._status_line(), enabled=False),
            MenuItem(2, primary, enabled=primary_enabled, action="toggle"),
            MenuItem(
                3,
                _("Favorites"),
                enabled=self.catalogue is not None and not busy,
                children=self._tray_favorite_items(),
            ),
            MenuItem(
                4,
                _("Choose Location…"),
                enabled=self.catalogue is not None and not busy,
                action="locations",
            ),
            MenuItem(5, separator=True),
            MenuItem(
                6,
                _("Kill switch"),
                enabled=self._killswitch_status is not None and not self._killswitch_busy,
                toggle_state=1 if self._killswitch_armed else 0,
                action="killswitch",
            ),
            # Translators: tray menu; {0} is the app name.
            MenuItem(7, _("Show {0}").format(APP_NAME), action="show"),
            MenuItem(8, _("Quit"), action="quit"),
        )

    def _tray_action(self, action: str):
        if action == "toggle":
            self._tray_toggle_connection()
            return
        if action == "quit":
            self._present_from_tray()
            self._request_quit(None)
            return
        if action == "killswitch":
            self._toggle_killswitch_from_tray()
            return
        if action.startswith("favorite|"):
            self._tray_select_favorite(action.split("|", 1)[1])
            return
        self._present_from_tray()
        if action == "locations":
            self._open_locations()

    def _tray_toggle_connection(self):
        self._present_from_tray()
        if self._state == "connected":
            self._disconnect()
        elif self._state in {"preparing", "connecting"}:
            self._cancel_connect()
        elif self._state == "reconnecting":
            self._cancel_reconnect(_("Automatic reconnection stopped."))
        elif self._state in {"idle", "error"}:
            self._connect()
        else:
            self._toast(_("Wait for the current connection operation to finish."))

    def _tray_select_favorite(self, key: str):
        self._present_from_tray()
        if self.catalogue is None:
            self._toast(_("The location list is not loaded yet."))
            return
        location = self.catalogue.location_by_key(key)
        if location is None:
            self._set_favorite(key, False)
            self._toast(_("That favorite is no longer in the catalogue and was removed."))
            return
        self._choose_location(location)

    def _choose_location(self, location: Location):
        """Select a location; when connected, offer to switch to it."""
        if self._state in {"preparing", "connecting", "disconnecting"}:
            self._toast(_("Wait for the current connection operation to finish."))
            return
        current = self._selected_location()
        if self._state == "connected":
            if current is not None and current.key == location.key:
                # Translators: {0} is the location.
                self._toast(_("Already connected to {0}.").format(place_name(location, flag=True)))
                return
            dialog = Adw.AlertDialog.new(
                _("Switch VPN location?"),
                # Translators: {0} is the location.
                _("Disconnect from the current VPN and connect to {0}?").format(
                    place_name(location, flag=True)
                ),
            )
            dialog.add_response("cancel", _("Cancel"))
            dialog.add_response("switch", _("Switch"))
            dialog.set_close_response("cancel")
            dialog.set_default_response("cancel")
            dialog.set_response_appearance("switch", Adw.ResponseAppearance.SUGGESTED)

            def response(_dialog, response_id):
                if response_id == "switch":
                    self._switch_connected_to(location)

            dialog.connect("response", response)
            dialog.present(self)
            return
        if self._state == "reconnecting":
            self._cancel_reconnect()
        self._select_location(location)
        self._connect()

    def _set_notifications(self, enabled: bool):
        self.settings.notifications_enabled = enabled
        try:
            self.settings_store.save(self.settings)
        except Exception as exc:
            log.warning("could not save notification preference: %s", exc)
        self._refresh_tray()

    def _show_settings(self):
        dialog = Adw.PreferencesDialog()
        dialog.set_title(_("Settings"))
        page = Adw.PreferencesPage()

        general = Adw.PreferencesGroup(title=_("General"))
        codes = ["", *[code for code, _name in i18n.LANGUAGE_NAMES]]
        names = Gtk.StringList()
        # Translators: the language option that follows the desktop's language.
        names.append(_("System default"))
        for _code, name in i18n.LANGUAGE_NAMES:
            names.append(name)  # each language in its own name
        language = Adw.ComboRow()
        language.set_title(_("Language"))
        language.set_model(names)
        current = self.settings.language if self.settings.language in codes else ""
        language.set_selected(codes.index(current))

        def language_subtitle():
            if self.settings.language != i18n.active_language():
                language.set_subtitle(_("Restart Pervius to apply"))
            else:
                language.set_subtitle("")

        def language_changed(row, _pspec):
            index = row.get_selected()
            if not (0 <= index < len(codes)) or codes[index] == self.settings.language:
                return
            self.settings.language = codes[index]
            try:
                self.settings_store.save(self.settings)
            except Exception as exc:
                log.warning("could not save the language: %s", exc)
            language_subtitle()
            dialog.add_toast(Adw.Toast.new(_("Restart Pervius to apply")))

        language_subtitle()
        language.connect("notify::selected", language_changed)
        general.add(language)

        login = Adw.SwitchRow()
        login.set_title(_("Start at login"))
        login.set_subtitle(_("Start hidden in the tray when you log in."))
        login.set_active(autostart.is_enabled())

        def login_changed(row, _pspec):
            try:
                autostart.set_enabled(bool(row.get_active()))
            except OSError as exc:
                log.warning("could not change start at login: %s", exc)
                dialog.add_toast(Adw.Toast.new(_("Could not change start at login.")))
                row.set_active(autostart.is_enabled())

        login.connect("notify::active", login_changed)
        general.add(login)

        notifications = Adw.SwitchRow()
        notifications.set_title(_("Desktop notifications"))
        notifications.set_subtitle(
            _("Show connection loss, recovery, and background status while the window is hidden.")
        )
        notifications.set_active(bool(self.settings.notifications_enabled))
        notifications.connect(
            "notify::active",
            lambda row, _pspec: self._set_notifications(bool(row.get_active())),
        )
        general.add(notifications)
        page.add(general)

        group = Adw.PreferencesGroup(title=_("Connection"))
        reconnect = Adw.SwitchRow()
        reconnect.set_title(_("Reconnect automatically"))
        reconnect.set_subtitle(
            _(
                "Retry after an unexpected drop, with increasing delays. "
                "Manual disconnects and failed first attempts never retry."
            )
        )
        reconnect.set_active(bool(self.settings.auto_reconnect))
        reconnect.connect(
            "notify::active",
            lambda row, _pspec: self._set_auto_reconnect(bool(row.get_active())),
        )
        group.add(reconnect)
        page.add(group)

        privacy = Adw.PreferencesGroup(title=_("Privacy and security"))
        block = Adw.SwitchRow()
        block.set_title(_("Block IPv6 while connected"))
        block.set_subtitle(
            _(
                "While the VPN is up, IPv6 traffic outside the tunnel is blocked, "
                "even when the kill switch is off. Applies from the next connection."
            )
        )
        block.set_active(bool(self.settings.block_ipv6))

        def block_changed(row, _pspec):
            self.settings.block_ipv6 = bool(row.get_active())
            self._save_guard_settings()

        block.connect("notify::active", block_changed)
        privacy.add(block)

        interfaces = Adw.EntryRow()
        interfaces.set_title(_("Always allow these interfaces"))
        interfaces.set_text(", ".join(self.settings.killswitch_interfaces))
        interfaces.set_show_apply_button(True)
        interfaces.set_tooltip_text(
            _(
                "Interface names separated by commas, for example wt0 for NetBird. "
                "They are allowed by the kill switch and the IPv6 guard. Editable "
                "while the kill switch is armed."
            )
        )

        def interfaces_applied(row):
            raw = [part for part in row.get_text().replace(" ", ",").split(",") if part]
            try:
                names = list(validate_interfaces(raw))
            except RulesError:
                row.add_css_class("error")
                dialog.add_toast(
                    Adw.Toast.new(
                        _(
                            "Use interface names of up to 15 letters, digits, dots, "
                            "dashes or underscores, at most 16 of them."
                        )
                    )
                )
                return
            row.remove_css_class("error")
            row.set_text(", ".join(names))
            self.settings.killswitch_interfaces = names
            self._save_guard_settings()
            if self._killswitch_armed:
                self._configure_killswitch()

        interfaces.connect("apply", interfaces_applied)
        self._interfaces_row = interfaces
        privacy.add(interfaces)

        keyring = Adw.ActionRow()
        keyring.set_title(_("Password storage"))
        keyring.set_subtitle(
            _(
                "Saved only in the desktop keyring when you enable it in the Account "
                "dialog, which is also where you can forget it."
            )
        )
        keyring.set_icon_name("channel-secure-symbolic")
        privacy.add(keyring)
        page.add(privacy)
        dialog.add(page)

        def closed(*_args):
            self._interfaces_row = None

        dialog.connect("closed", closed)
        self._render_killswitch_state()
        dialog.present(self)

    def _save_guard_settings(self):
        """Persist the leak-guard options and hand them to the service."""
        try:
            self.settings_store.save(self.settings)
        except Exception as exc:
            log.warning("could not save the leak guard settings: %s", exc)
        self._send_guard_options()

    def _reconcile_active(self):
        if self.client is None:
            return
        active = active_vpn_for_uuid(self.client)
        if active is None:
            return
        try:
            store = OwnershipStore.load()
            lookup: ManagedLookup = find_managed_connection(
                self.client.get_connections(), store, self.local_username
            )
        except OwnershipError as exc:
            self._blocked(
                # Translators: {0} is a technical error message.
                _(
                    "A VPN connection uses the reserved Pervius UUID, but its ownership "
                    "cannot be verified: {0}"
                ).format(exc)
            )
            return
        if lookup.connection is None:
            self._blocked(
                _(
                    "A VPN connection uses the reserved Pervius UUID, but no owned "
                    "profile was found; refusing to manage it."
                )
            )
            return
        self.ownership = store
        self._existing_connection = lookup.connection
        self._old_entry = lookup.entry
        self.active = active
        state = vpn_state_name(active)
        if state == "activated":
            self._set_connected()
        elif state == "failed":
            # Translators: {0} is NetworkManager's technical reason.
            self._fail(_("The VPN connection is in a failed state: {0}").format(vpn_state_reason(active)))
        else:
            self._set_state("connecting")
            self._connect_deadline = time.monotonic() + 90
            self._start_poll()

    # --------------------------------------------------------------- catalogue

    def _load_catalogue(self, force: bool = False):
        if self._catalogue_loading:
            return
        self._catalogue_loading = True
        if self.catalogue is None and self.active is None:
            self._set_state("loading")
        self._clear_banner()

        cached = None
        try:
            cached = self.catalogue_store.load()
        except Exception as exc:
            log.warning("cached catalogue unavailable: %s", exc)

        if cached is not None and not force:
            self._on_catalogue_loaded(cached, None, False)
            return

        def worker():
            try:
                blob = fetch_catalogue()
                catalogue = parse_catalogue(blob, source_url=CATALOGUE_URL)
                try:
                    self.catalogue_store.save(blob, catalogue)
                except Exception as exc:
                    log.warning("could not persist catalogue: %s", exc)
            except Exception as exc:
                GLib.idle_add(self._on_catalogue_loaded, cached, exc, False)
            else:
                GLib.idle_add(self._on_catalogue_loaded, catalogue, None, True)

        self._catalogue_thread = threading.Thread(
            target=worker, name="pervius-catalogue", daemon=True
        )
        self._catalogue_thread.start()

    def _on_catalogue_loaded(self, catalogue, error, refreshed):
        if self._disposed:
            return
        self._catalogue_loading = False
        if catalogue is None:
            # Translators: {0} is a technical error message.
            message = _("Could not load the location list: {0}").format(error)
            self._set_state("error", message)
            self._show_banner(message)
            return
        self.catalogue = catalogue
        location = None
        if self.settings.location_key:
            location = catalogue.location_by_key(self.settings.location_key)
        if location is None:
            location = catalogue.locations[0] if catalogue.locations else None
        self._select_location(location, save=False)
        if self.active is not None:
            self._set_connected()
        elif self._blocked_reason:
            self._set_state("blocked", self._blocked_reason)
        else:
            self._set_state("idle")
        for name, reason in catalogue.skipped:
            log.warning("skipped catalogue profile %s: %s", name, reason)
        if error is not None:
            # Translators: {0} is a technical error message.
            self._show_banner(_("Using the saved location list; refresh failed: {0}").format(error))
        elif catalogue.skipped:
            count = len(catalogue.skipped)
            self._show_banner(
                ngettext(
                    "{0} server profile failed validation and was left out: {1}",
                    "{0} server profiles failed validation and were left out: {1}",
                    count,
                ).format(count, ", ".join(name.rsplit("/", 1)[-1] for name, _reason in catalogue.skipped[:3]))
            )
        elif refreshed and self.active is None:
            profiles = ngettext(
                "{0} profile", "{0} profiles", catalogue.profile_count
            ).format(catalogue.profile_count)
            locations = ngettext(
                "{0} location", "{0} locations", len(catalogue.locations)
            ).format(len(catalogue.locations))
            # Translators: {0} is "N profiles", {1} is "N locations".
            self._toast(_("Loaded {0} in {1}.").format(profiles, locations))

    def _selected_ref(self) -> ProfileRef | None:
        if self.catalogue is None or not self.settings.location_key:
            return None
        return self.catalogue.profile_for(self.settings.location_key, self.settings.protocol)

    def _selected_location(self) -> Location | None:
        if self.catalogue is None:
            return None
        return self.catalogue.location_by_key(self.settings.location_key)

    def _select_location(self, location: Location | None, *, save: bool = True):
        if location is None:
            self.settings.location_key = ""
            self._update_location_row()
            return
        self.settings.location_key = location.key
        if self.settings.protocol not in location.profiles:
            self.settings.protocol = location.protocols[0] if location.protocols else "udp"
        self._set_protocol(self.settings.protocol)
        self._update_location_row()
        if save:
            self.settings_store.save(self.settings)

    def _set_protocol(self, protocol: str):
        self._protocol_syncing = True
        try:
            if protocol == "tcp":
                self.tcp_button.set_active(True)
                self.udp_button.set_active(False)
            else:
                self.udp_button.set_active(True)
                self.tcp_button.set_active(False)
        finally:
            self._protocol_syncing = False

    def _on_protocol_toggled(self, button):
        if self._protocol_syncing:
            return
        if not button.get_active():
            # Clicking the active side must not leave both sides off.
            self._set_protocol(self.settings.protocol)
            return
        protocol = "tcp" if button is self.tcp_button else "udp"
        location = self._selected_location()
        if location is not None and protocol not in location.profiles:
            # Keep the nearest valid choice rather than pretending it exists.
            protocol = "udp" if "udp" in location.profiles else "tcp"
        self._set_protocol(protocol)
        self.settings.protocol = protocol
        self.protocol_value.set_label(protocol.upper())
        self._update_location_row()
        if self._state not in _ACTIVE_STATES:
            self.settings_store.save(self.settings)

    def _update_location_row(self):
        location = self._selected_location()
        if location is None:
            self.location_row.set_subtitle(_("Not selected"))
        else:
            self.location_row.set_subtitle(place_name(location, flag=True))
        if self._state == "idle":
            self._refresh_idle_subtitle()
        self._refresh_tray()

    def _update_account_row(self):
        username = self.settings.username.strip()
        self.account_row.set_subtitle(username if username else _("Credentials not set"))

    def _on_auto_reconnect_changed(self, row, _pspec):
        self._set_auto_reconnect(bool(row.get_active()))

    def _set_auto_reconnect(self, enabled: bool):
        self.settings.auto_reconnect = enabled
        if self.auto_reconnect_row.get_active() != enabled:
            self.auto_reconnect_row.set_active(enabled)
        try:
            self.settings_store.save(self.settings)
        except Exception as exc:
            log.warning("could not save reconnect preference: %s", exc)
        if not enabled and self._state == "reconnecting":
            self._cancel_reconnect(_("Automatic reconnection disabled."))
        self._refresh_tray()

    # --------------------------------------------------------------- actions

    def _on_connect_clicked(self, *_args):
        if self._state == "connected":
            self._disconnect()
        elif self._state in {"preparing", "connecting"}:
            self._cancel_connect()
        elif self._state == "reconnecting":
            self._cancel_reconnect(_("Automatic reconnection stopped."))
        elif self._state in {"idle", "error"}:
            self._connect()

    def _ensure_credentials(self) -> bool:
        username = self.settings.username.strip()
        if not username:
            self._open_credentials(True)
            return False
        if self.credentials.password_state(username):
            return True
        self._open_credentials(True)
        return False

    def _connect(self):
        if self.client is None:
            self._blocked(_("NetworkManager is unavailable."))
            return
        if self.agent is None or not self.agent.registered:
            self._blocked(
                _("The NetworkManager secret agent is not registered; reconnect after restarting the app.")
            )
            return
        if self._selected_ref() is None:
            self._toast(_("Choose a location and protocol first."))
            return
        if self.active is not None:
            self._toast(_("A VPN connection is already active. Disconnect it first."))
            return
        if not self._ensure_credentials():
            return
        self._warning = ""
        self._clear_banner()
        self._intent_connected = True
        self._attempt += 1
        attempt = self._attempt
        self._ensure_profile(
            then=lambda connection: self._finalize_and_activate(connection)
            if attempt == self._attempt
            else None,
            on_error=lambda message: self._fail(message) if attempt == self._attempt else None,
            on_blocked=lambda message: self._blocked(
                # Translators: {0} is a technical error message.
                _("The managed VPN profile cannot be used safely: {0}").format(message)
            ),
        )

    def _ensure_profile(self, *, then, on_error, on_blocked, quiet: bool = False):
        """Make sure the managed profile matches the selected location and protocol.

        Reuses a stored profile that still verifies, otherwise imports and
        verifies the catalogue profile again.  ``then(connection)`` receives the
        stored connection.  ``quiet`` keeps the current state (used while a
        connected tunnel is being switched).
        """
        ref = self._selected_ref()
        if ref is None:
            on_error(_("Choose a location and protocol first."))
            return
        try:
            store = OwnershipStore.load()
            lookup: ManagedLookup = find_managed_connection(
                self.client.get_connections(), store, self.local_username
            )
        except OwnershipError as exc:
            on_blocked(str(exc))
            return
        self.ownership = store
        self._existing_connection = lookup.connection
        self._old_entry = lookup.entry

        if lookup.connection is not None:
            try:
                self._verify_for(lookup.connection, lookup.entry, ref)
            except (ImportVerificationError, OSError) as exc:
                log.info("existing profile will be re-imported: %s", exc)
            else:
                then(lookup.connection)
                return

        if not quiet:
            self._set_state("preparing")
        self.footer.set_label(_("Importing and verifying the selected profile…"))

        def prepared_done(prepared, error):
            if self._disposed:
                return
            self._reset_footer()
            if error is not None:
                # Translators: {0} is a technical error message.
                on_error(_("Could not prepare the VPN profile: {0}").format(error))
                return
            self._prepared = prepared
            self._apply_prepared(prepared, then=then, on_error=on_error, on_blocked=on_blocked)

        prepare_managed_profile_async(
            ref,
            self.settings.username.strip(),
            self.local_username,
            prepared_done,
        )

    @staticmethod
    def _verify_for(connection, entry, ref):
        """The stored profile is the selected catalogue profile, unchanged.

        A pinned profile lists IP addresses, so the remote list alone cannot
        tell locations apart; the ownership manifest records which catalogue
        profile was imported.
        """
        if entry is None or entry.source_sha256 != ref.profile.source_sha256:
            raise ImportVerificationError("the stored profile is for another location or protocol")
        verify_managed_profile(connection, ref.profile, certificate_dir())

    def _apply_prepared(self, prepared, *, then, on_error, on_blocked):
        try:
            lookup = find_managed_connection(
                self.client.get_connections(), self.ownership, self.local_username
            )
        except OwnershipError as exc:
            self._cleanup_unreferenced_ca(prepared.ca_path)
            on_blocked(str(exc))
            return
        existing = lookup.connection
        self._existing_connection = existing
        self._old_entry = lookup.entry

        def done(connection, error):
            if self._disposed:
                return
            if error is not None:
                self._cleanup_unreferenced_ca(prepared.ca_path)
                # Translators: {0} is a technical error message.
                on_error(_("Could not save the managed profile: {0}").format(error))
                return
            entry = OwnershipEntry(
                uuid=MANAGED_UUID,
                connection_id=MANAGED_CONNECTION_ID,
                service_type=OPENVPN_SERVICE_TYPE,
                created_at=lookup.entry.created_at if lookup.entry else "",
                source_sha256=prepared.source_sha256,
                ca_sha256=prepared.ca_sha256,
                ca_path=prepared.ca_path,
            )
            try:
                self.ownership.record(entry)
            except Exception as exc:
                log.error("could not save ownership manifest: %s", exc)
                if lookup.connection is None:
                    try:
                        connection.delete(None)
                    except Exception:
                        pass
                on_error(
                    # Translators: {0} is a technical error message.
                    _(
                        "The NetworkManager profile was created, but the ownership manifest "
                        "could not be saved: {0}. The profile will not be used."
                    ).format(exc)
                )
                return
            if lookup.entry and lookup.entry.ca_path and lookup.entry.ca_path != prepared.ca_path:
                self._cleanup_old_ca(lookup.entry.ca_path, prepared.ca_path)
            self._old_entry = entry
            self._existing_connection = connection
            self._warning = " ".join(prepared.warnings)
            then(connection)

        if existing is not None:
            update_connection_async(existing, prepared.variant, done)
        else:
            try:
                check_create_collision(self.client.get_connections(), self.local_username)
            except OwnershipError as exc:
                self._cleanup_unreferenced_ca(prepared.ca_path)
                on_blocked(str(exc))
                return
            add_connection_async(self.client, prepared.variant, done)

    def _finalize_and_activate(self, connection, *, reconnecting: bool = False):
        """Pin the profile to resolved server addresses, then activate.

        The profile is always pinned: while connected the leak guard blocks
        DNS outside the tunnel (and the kill switch blocks it while armed), so
        OpenVPN must never need DNS to (re)connect.  With the kill switch armed
        the service resolves and allows the servers; otherwise the app resolves
        them.  The certificate checks still decide whether a server is genuine.
        """
        attempt = self._attempt

        def current() -> bool:
            return attempt == self._attempt and self._intent_connected and not self._disposed

        def activate(conn):
            if current():
                self._activate(conn, reconnecting=reconnecting)

        def failed(message: str):
            if not current():
                return
            if reconnecting and self._should_retry_after_failure():
                self._reconnect_in_flight = False
                self._schedule_next_reconnect(message)
            else:
                self._fail(message)

        def pin_and_activate(endpoints):
            if not current():
                return
            self._write_profile(
                connection,
                pins=endpoints,
                then=lambda conn: self._send_guard_options(lambda: activate(conn)),
                # Translators: {0} is a technical error message.
                on_error=lambda message: failed(_("Could not update the managed profile: {0}").format(message)),
            )

        pins = self._fresh_pins()
        if pins:
            pin_and_activate(pins)
            return

        self._set_state("connecting")
        armed = self._killswitch_armed and self._killswitch_status is not None
        self.status_subtitle.set_label(
            _("Updating the kill switch for this server…") if armed else _("Looking up the VPN servers…")
        )

        def with_previous(fresh, error):
            if not current():
                return
            previous = pinned_endpoints(fresh, self.settings.protocol) if fresh is not None else ()

            def fall_back(reason: str):
                if previous:
                    # Keep the addresses pinned earlier; they usually still work.
                    log.info("server lookup failed, using the pinned addresses: %s", reason)
                    pin_and_activate(previous)
                else:
                    failed(reason)

            if armed:
                self._resolve_for_kill_switch(
                    connection,
                    replace=not reconnecting,
                    then=lambda: pin_and_activate(self._fresh_pins()) if self._fresh_pins() else fall_back(
                        _("The VPN server addresses could not be resolved.")
                    ),
                    on_error=lambda error: fall_back(killswitch_error_text(error)),
                )
                return
            ref = self._selected_ref()
            if ref is None:
                failed(_("Choose a location and protocol first."))
                return

            def resolved(endpoints, warnings):
                for warning in warnings:
                    log.info("server lookup: %s", warning)
                if self._remember_endpoints(endpoints):
                    pin_and_activate(endpoints)
                else:
                    fall_back(_("The VPN server addresses could not be resolved."))

            resolve_endpoints_async(ref.profile.remotes, self.settings.protocol, resolved)

        fetch_settings_async(connection, with_previous)

    def _switch_connected_to(self, location: Location):
        """Switch a connected tunnel to another location.

        Without the kill switch: disconnect, then connect (the new servers
        are looked up before connecting).  With it armed, the new profile is
        prepared and its servers resolved, allowed and pinned first, while the
        current tunnel still carries DNS, so the switch needs no DNS outside
        the tunnel and protection never lapses.
        """
        previous = self.settings.location_key
        self._select_location(location)
        if not self._killswitch_armed:
            self._pending_switch_key = location.key
            self._disconnect()
            return

        def failed(message):
            self.settings.location_key = previous
            self._select_location(self._selected_location())
            # Translators: {0} explains why the switch failed.
            self._show_banner(_("Could not switch location: {0}").format(message))

        def ready(connection):
            pins = self._fresh_pins()
            if not pins:
                failed(_("The VPN server addresses could not be resolved."))
                return

            def switch(_conn):
                self._pending_switch_key = location.key
                self._disconnect()

            self._write_profile(connection, pins=pins, then=switch, on_error=failed)

        self._toast(_("Preparing the new location…"))
        self._ensure_profile(
            then=lambda connection: self._resolve_for_kill_switch(
                connection,
                # Keep the old server allowed until the new tunnel is up, so
                # the old OpenVPN can close cleanly and free pervius0.
                replace=False,
                then=lambda: ready(connection),
                on_error=lambda error: failed(killswitch_error_text(error)),
            ),
            on_error=failed,
            on_blocked=failed,
            quiet=True,
        )

    @staticmethod
    def _tunnel_device_busy() -> bool:
        return (Path("/sys/class/net") / TUNNEL_INTERFACE).exists()

    def _activate(self, connection, *, reconnecting: bool = False, waited: float = 0.0):
        """Activate, once the previous tunnel has released ``pervius0``.

        The device name is pinned, so a new OpenVPN cannot open it while the
        previous one is still exiting ("TUNSETIFF pervius0: Device or resource
        busy"); wait for it (at most 15 s) before asking NetworkManager.
        """
        self._reconnect_in_flight = reconnecting
        self._set_state("connecting")
        if self.active is None and self._tunnel_device_busy() and waited < 15.0:
            attempt = self._attempt
            self.status_subtitle.set_label(_("Waiting for the previous tunnel to close…"))

            def retry():
                if attempt == self._attempt and self._intent_connected and not self._disposed:
                    self._activate(connection, reconnecting=reconnecting, waited=waited + 0.25)
                return False

            GLib.timeout_add(250, retry)
            return
        self._connect_deadline = time.monotonic() + 90
        self._start_poll()

        attempt = self._attempt

        def done(active, error):
            if self._disposed:
                return
            if attempt != self._attempt:
                # Cancelled meanwhile: drop whatever NetworkManager started.
                if active is not None and self.client is not None:
                    deactivate_async(self.client, active, lambda *_args: None)
                return
            if error is not None:
                if self._should_retry_after_failure():
                    self._reconnect_in_flight = False
                    self._stop_poll()
                    self._schedule_next_reconnect(str(error))
                else:
                    # Translators: {0} is a technical error message.
                    self._fail(_("Could not start the VPN: {0}").format(error))
                return
            self.active = active
            state = vpn_state_name(active)
            if state == "activated":
                self._set_connected()
            elif state == "failed":
                # Translators: {0} is NetworkManager's technical reason.
                reason = _("The VPN connection failed: {0}").format(vpn_state_reason(active))
                if self._should_retry_after_failure():
                    self._reconnect_in_flight = False
                    self._stop_poll()
                    self._schedule_next_reconnect(reason)
                else:
                    self._fail(reason)
            else:
                self._set_state("connecting")

        self._activation_cancellable = activate_async(self.client, connection, done)

    def _cancel_connect(self):
        """Stop a connection attempt: nothing started for it may continue."""
        self._attempt += 1
        self._intent_connected = False
        self._pending_switch_key = None
        self._reconnect_after_disconnect = False
        if self._activation_cancellable is not None:
            self._activation_cancellable.cancel()
            self._activation_cancellable = None
        self._reset_reconnect_state()
        self._stop_poll()
        active = self.active or (
            active_vpn_for_uuid(self.client) if self.client is not None else None
        )
        self.active = None
        self._connected_since = None
        if active is not None and self.client is not None:
            deactivate_async(self.client, active, lambda *_args: None)
        self._reset_footer()
        self._set_state("idle")
        self._toast(_("Connection attempt cancelled."))

    def _should_retry_after_failure(self) -> bool:
        return bool(
            self._reconnect_in_flight
            and self._intent_connected
            and self.settings.auto_reconnect
            and not self._quitting
        )

    def _disconnect(self):
        self._intent_connected = False
        if self._state == "reconnecting":
            self._cancel_reconnect(_("Automatic reconnection stopped."))
            return
        active = self.active or (
            active_vpn_for_uuid(self.client) if self.client is not None else None
        )
        if active is None:
            self._finish_disconnected()
            return
        self._set_state("disconnecting")

        def done(ok, error):
            if self._disposed:
                return
            if not ok:
                # Translators: {0} is a technical error message.
                self._fail(_("Could not stop the VPN: {0}").format(error))
                return
            self.active = active
            self._start_poll()

        deactivate_async(self.client, active, done)

    def _finish_disconnected(self, message: str | None = None):
        self._intent_connected = False
        self._reset_reconnect_state()
        self._stop_poll()
        self._stop_timer()
        self._isp_ip_checked = self._reconnect_after_disconnect
        self.active = None
        self._connected_since = None
        self._set_state("idle")
        if message:
            self._toast(message)
        if self._quit_after_disconnect:
            self._pending_switch_key = None
            self._reconnect_after_disconnect = False
            self._quit_after_disconnect = False
            self._quit_now()
            return
        if self._pending_switch_key is not None:
            self._pending_switch_key = None
            GLib.idle_add(self._connect_after_switch)
            return
        if self._reconnect_after_disconnect:
            self._reconnect_after_disconnect = False
            GLib.idle_add(self._connect_after_switch)

    def _connect_after_switch(self):
        self._connect()
        return False

    def _fail(self, message: str):
        self._intent_connected = False
        self._pending_switch_key = None
        self._reconnect_after_disconnect = False
        self._isp_ip_checked = False
        self._reset_reconnect_state()
        self._stop_poll()
        self._stop_timer()
        failed_active = self.active
        self.active = None
        self._set_state("error", message)
        self._show_banner(message)
        if failed_active is not None and self.client is not None:
            # A failed active connection can otherwise block a retry.  This is
            # a cleanup attempt; its own error is not useful to the user.
            try:
                deactivate_async(self.client, failed_active, lambda *_args: None)
            except Exception:
                pass

    def _blocked(self, message: str):
        if self._migration_problem:
            # Translators: {0} is the problem, {1} a technical reason.
            message = _(
                "{0} The profile from the previous release could not be adopted: {1}."
            ).format(message, self._migration_problem)
        self._blocked_reason = message
        self._intent_connected = False
        self._pending_switch_key = None
        self._reconnect_after_disconnect = False
        self._isp_ip_checked = False
        self._reset_reconnect_state()
        self._stop_poll()
        self._stop_timer()
        self._set_state("blocked", message)
        self._show_banner(message)

    # ------------------------------------------------------------------ state

    def _set_state(self, state: str, detail: str = ""):
        self._state = state
        busy = state in {"preparing", "connecting", "disconnecting"}
        if busy:
            self.status_stack.set_visible_child_name("spinner")
            self.status_spinner.start()
        else:
            self.status_spinner.stop()
            self.status_stack.set_visible_child_name("icon")
        self.status_icon.set_from_icon_name(
            STATUS_ICON_CONNECTED if state == "connected" else STATUS_ICON_OFF
        )

        if state == "loading":
            self.status_title.set_label(_("Loading locations…"))
            self.status_subtitle.set_label(_("Reading the public catalogue."))
            self.connect_button.set_label(_("Connect"))
            self.connect_button.set_sensitive(False)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "idle":
            self.status_title.set_label(_("Not connected"))
            self._refresh_idle_subtitle()
            self.connect_button.set_label(_("Connect"))
            self.connect_button.set_sensitive(
                self.catalogue is not None
                and self.client is not None
                and self.agent is not None
                and self.agent.registered
            )
            self.connect_button.remove_css_class("destructive-action")
        elif state == "preparing":
            self.status_title.set_label(_("Preparing VPN profile…"))
            self.status_subtitle.set_label(_("Importing and verifying the selected profile."))
            self.connect_button.set_label(_("Cancel"))
            self.connect_button.set_sensitive(True)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "connecting":
            self.status_title.set_label(_("Connecting…"))
            self.status_subtitle.set_label(_("Waiting for NetworkManager and the OpenVPN plugin."))
            # Translators: stops a connection attempt in progress.
            self.connect_button.set_label(_("Cancel"))
            self.connect_button.set_sensitive(True)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "reconnecting":
            self.status_title.set_label(_("Reconnecting…"))
            self._update_reconnect_subtitle()
            self.connect_button.set_label(_("Stop Retrying"))
            self.connect_button.set_sensitive(True)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "connected":
            self.status_title.set_label(_("Connected"))
            self._refresh_connected_subtitle()
            self.connect_button.set_label(_("Disconnect"))
            self.connect_button.set_sensitive(True)
            self.connect_button.add_css_class("destructive-action")
            self.connect_button.remove_css_class("suggested-action")
        elif state == "disconnecting":
            self.status_title.set_label(_("Disconnecting…"))
            self.status_subtitle.set_label(_("Telling NetworkManager to stop the tunnel."))
            self.connect_button.set_label(_("Disconnecting…"))
            self.connect_button.set_sensitive(False)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "error":
            self.status_title.set_label(_("Connection failed") if self.active else _("Not connected"))
            self.status_subtitle.set_label(detail or _("The last operation failed."))
            self.connect_button.set_label(_("Try Again"))
            self.connect_button.set_sensitive(
                self.catalogue is not None
                and self.client is not None
                and self.agent is not None
                and self.agent.registered
            )
            self.connect_button.remove_css_class("destructive-action")
        elif state == "blocked":
            self.status_title.set_label(_("Setup problem"))
            self.status_subtitle.set_label(detail or _("The app cannot safely continue."))
            self.connect_button.set_label(_("Unavailable"))
            self.connect_button.set_sensitive(False)
            self.connect_button.remove_css_class("destructive-action")

        if state == "connected":
            self.connect_button.add_css_class("destructive-action")
            self.connect_button.remove_css_class("suggested-action")
        else:
            self.connect_button.add_css_class("suggested-action")
            self.connect_button.remove_css_class("destructive-action")

        self._update_controls()
        self._refresh_connection_details()
        self._refresh_tray()

    def _update_controls(self):
        state = self._state
        idle = state not in _ACTIVE_STATES and state not in {"loading", "blocked"}
        # Location and protocol may change while the kill switch is armed: the
        # service swaps the allowed endpoints atomically.  A connected tunnel can
        # switch location (it offers to reconnect); protocol changes wait.
        self.location_button.set_sensitive(idle or state == "connected")
        self.protocol_switch.set_sensitive(idle)
        self.account_button.set_sensitive(state not in _ACTIVE_STATES)

    def _set_connected(self):
        was_reconnecting = self._reconnect_in_flight
        self._reset_reconnect_state()
        if self._state != "connected":
            self._vpn_exit_ip = ""
            self._connected_since = time.monotonic()
            self._set_state("connected")
            self._start_timer()
            where = place_name(self._selected_location()) or _("the selected server")
            if was_reconnecting:
                self._toast(_("VPN reconnected automatically."))
                self._notify_if_background(
                    _("VPN reconnected"),
                    # Translators: {0} is the location.
                    _("Connected to {0}.").format(where),
                )
            elif self._warning:
                # Translators: {0} lists technical notes about the profile.
                self._show_banner(_("Profile imported with notes: {0}").format(self._warning))
            else:
                self._notify_if_background(
                    _("VPN connected"),
                    # Translators: {0} is the location.
                    _("Connected to {0}.").format(where),
                )
            GLib.timeout_add_seconds(3, self._check_tunnel_and_guard)
            if self._killswitch_armed and self._existing_connection is not None:
                self._refresh_after_connect(self._existing_connection)
        self._start_poll()

    def _check_tunnel_and_guard(self):
        """Warn when protection that should be active is not."""
        if self._disposed or self._state != "connected":
            return False
        if not self._tunnel_device_busy():
            # Translators: {0} is a network interface name.
            self._show_banner(
                _(
                    "The VPN tunnel is not named {0}; the kill switch and the IPv6 guard "
                    "may block it. Reconnect, or report this problem."
                ).format(TUNNEL_INTERFACE)
            )
            return False
        if self._killswitch_status is None or self._guard_warned:
            return False

        # Ask the service now: the 5-second status poll may predate this
        # connection and would report a guard that is in fact in place.
        def fresh(status, error):
            if self._disposed or self._state != "connected" or error is not None:
                return
            self._killswitch_status = status
            if not bool(status.get("guard", True)) and not self._guard_warned:
                self._guard_warned = True
                self._show_banner(
                    _("IPv6 is not blocked outside the tunnel. Reconnect to apply the IPv6 guard.")
                )

        call_async(self.killswitch.status, fresh)
        return False

    def _start_timer(self):
        self._stop_timer()
        self._update_timer()
        self._timer_source = GLib.timeout_add_seconds(1, self._update_timer)

    def _stop_timer(self):
        if self._timer_source is not None:
            GLib.source_remove(self._timer_source)
            self._timer_source = None

    def _update_timer(self):
        if self._state != "connected" or self._connected_since is None:
            self._timer_source = None
            return False
        self._refresh_connected_subtitle()
        self._update_duration()
        if getattr(self, "tray", None) is not None:
            self.tray.update_item(1)
        return True

    def _update_duration(self):
        if self._connected_since is None:
            self.duration_value.set_text("—")
            return
        self.duration_value.set_text(format_duration(time.monotonic() - self._connected_since))

    def _refresh_idle_subtitle(self):
        location = self._selected_location()
        if location is None:
            self.status_subtitle.set_label(_("Choose a location to begin."))
            return
        self.status_subtitle.set_label(place_name(location, flag=True))

    def _refresh_connected_subtitle(self):
        location = self._selected_location()
        self.status_subtitle.set_label(place_name(location, flag=True) or "VPN")

    # ------------------------------------------------------------- reconnect

    def _reconnect_problem(self) -> str | None:
        if self._quitting:
            return _("the application is shutting down")
        if self.client is None:
            return _("NetworkManager is unavailable")
        if self.agent is None or not self.agent.registered:
            return _("the secret agent is not registered")
        connection = self._existing_connection
        if connection is None:
            return _("the managed profile is missing")
        ref = self._selected_ref()
        if ref is None:
            return _("the selected location or protocol is no longer available")
        try:
            self._verify_for(connection, self._old_entry, ref)
        except Exception as exc:
            return str(exc)
        return None

    def _connection_lost(self, reason: str):
        had_session = self._connected_since is not None
        was_retrying = self._reconnect_in_flight
        self._stop_poll()
        self._stop_timer()
        self.active = None
        self._connected_since = None

        if not had_session and not was_retrying:
            # An initial activation that never completed must not turn a bad
            # password or a broken profile into an automatic retry loop.
            self._intent_connected = False
            self._fail(reason)
            return

        if not self._intent_connected or self._quitting:
            self._set_state("idle")
            self._toast(_("The VPN connection ended."))
            self._notify_if_background(_("VPN disconnected"), _("The VPN connection ended."))
            return
        if not self.settings.auto_reconnect:
            self._intent_connected = False
            self._set_state("idle")
            self._show_banner(_("The VPN connection ended. Automatic reconnect is off."))
            self._notify_if_background(
                _("VPN disconnected"), _("The VPN connection ended; automatic reconnect is off.")
            )
            return

        problem = self._reconnect_problem()
        if problem is not None:
            self._intent_connected = False
            # Translators: {0} explains what is wrong.
            message = _(
                "The VPN connection ended and cannot be safely reconnected: "
                "{0}. Press Try Again to rebuild it."
            ).format(problem)
            self._set_state("error", message)
            self._show_banner(message)
            self._notify_if_background(_("VPN reconnection stopped"), message)
            return

        self._reconnect_attempt = 0
        self._reconnect_reason = reason
        self._toast(_("The VPN connection was lost. Reconnecting automatically…"))
        self._notify_if_background(
            _("VPN connection lost"), _("Reconnecting automatically in a few seconds.")
        )
        self._schedule_next_reconnect(reason)

    def _schedule_next_reconnect(self, reason: str):
        if not self._intent_connected or not self.settings.auto_reconnect:
            self._reset_reconnect_state()
            self._set_state("idle")
            return
        problem = self._reconnect_problem()
        if problem is not None:
            self._intent_connected = False
            self._reset_reconnect_state()
            # Translators: {0} explains what is wrong.
            message = _("Automatic reconnection stopped: {0}.").format(problem)
            self._set_state("error", message)
            self._show_banner(message)
            return

        self._reconnect_attempt += 1
        delay = _RECONNECT.delay(self._reconnect_attempt)
        if delay is None:
            self._give_up(reason)
            return
        self._reconnect_reason = reason
        self._reconnect_deadline = time.monotonic() + delay
        self._set_state("reconnecting")
        if self._reconnect_source is None:
            self._reconnect_source = GLib.timeout_add(250, self._reconnect_tick)

    def _reconnect_tick(self):
        if self._disposed or self._state != "reconnecting" or not self._intent_connected:
            self._reconnect_source = None
            return False
        if self._reconnect_deadline is None:
            self._reconnect_source = None
            return False
        remaining = self._reconnect_deadline - time.monotonic()
        if remaining <= 0:
            self._reconnect_source = None
            self._reconnect_deadline = None
            connection = self._existing_connection
            if connection is None:
                self._give_up(self._reconnect_reason)
                return False
            if self._killswitch_armed and self._reconnect_attempt == 1:
                # Before the first retry, re-resolve the servers in case the
                # provider rotated their addresses (the service uses its own
                # short DNS window while the tunnel is down).
                self._reconnect_in_flight = True
                self._finalize_and_activate(connection, reconnecting=True)
            else:
                self._activate(connection, reconnecting=True)
            return False
        self._update_reconnect_subtitle()
        return True

    def _update_reconnect_subtitle(self):
        remaining = 1
        if self._reconnect_deadline is not None:
            remaining = max(1, math.ceil(self._reconnect_deadline - time.monotonic()))
        retry = ngettext(
            "Connection lost. Retrying in {0} second", "Connection lost. Retrying in {0} seconds", remaining
        ).format(remaining)
        # Translators: {0} is "Connection lost. Retrying in N seconds",
        # {1} the attempt number and {2} the number of attempts.
        self.status_subtitle.set_label(
            _("{0} (attempt {1} of {2}).").format(retry, self._reconnect_attempt, _RECONNECT.max_attempts)
        )

    def _cancel_reconnect(self, message: str = ""):
        self._intent_connected = False
        self._reset_reconnect_state()
        self._set_state("idle")
        if message:
            self._toast(message)

    def _give_up(self, reason: str):
        self._intent_connected = False
        self._reset_reconnect_state()
        # Translators: {0} is the number of attempts, {1} a technical reason.
        message = ngettext(
            "The VPN connection was lost and automatic reconnection stopped after {0} attempt: {1}",
            "The VPN connection was lost and automatic reconnection stopped after {0} attempts: {1}",
            _RECONNECT.max_attempts,
        ).format(_RECONNECT.max_attempts, reason)
        self._set_state("error", message)
        self._show_banner(message)
        self._notify_if_background(_("Automatic reconnection stopped"), message)

    def _reset_reconnect_state(self):
        if self._reconnect_source is not None:
            GLib.source_remove(self._reconnect_source)
            self._reconnect_source = None
        self._reconnect_attempt = 0
        self._reconnect_deadline = None
        self._reconnect_reason = ""
        self._reconnect_in_flight = False

    def _start_poll(self):
        if self._poll_source is None:
            self._poll_source = GLib.timeout_add_seconds(1, self._poll)

    def _stop_poll(self):
        if self._poll_source is not None:
            GLib.source_remove(self._poll_source)
            self._poll_source = None

    def _poll(self):
        if self._disposed or self.client is None:
            self._poll_source = None
            return False
        if self._state not in {"connecting", "connected", "disconnecting"}:
            self._poll_source = None
            return False
        active = active_vpn_for_uuid(self.client)
        if self._state == "disconnecting":
            if active is None:
                self._poll_source = None
                self._finish_disconnected()
                return False
            self.active = active
            return True
        if active is None:
            if self._state == "connected":
                self._poll_source = None
                self._connection_lost(_("The VPN connection ended."))
                return False
            if self._state == "connecting":
                if self._connect_deadline is None:
                    self._connect_deadline = time.monotonic() + 90
                if time.monotonic() > self._connect_deadline:
                    self._poll_source = None
                    if self._reconnect_in_flight:
                        self._reconnect_in_flight = False
                        self._schedule_next_reconnect(_("The connection attempt timed out."))
                    else:
                        self._fail(_("The connection attempt timed out."))
                    return False
            return True
        self.active = active
        state = vpn_state_name(active)
        if state == "activated":
            self._set_connected()
        elif state == "failed":
            self._poll_source = None
            # Translators: {0} is NetworkManager's technical reason.
            reason = _("The VPN connection failed: {0}").format(vpn_state_reason(active))
            if self._reconnect_in_flight:
                self._reconnect_in_flight = False
                self._schedule_next_reconnect(reason)
            else:
                self._fail(reason)
            return False
        elif state in {"disconnected", "deactivated"}:
            self._poll_source = None
            self._connection_lost(_("NetworkManager reports the tunnel is gone."))
            return False
        elif state == "need-auth":
            self.status_subtitle.set_label(_("Waiting for the secret agent to supply credentials…"))
        return True

    # --------------------------------------------------------------- dialogs

    def _open_credentials(self, and_connect: bool):
        self._connect_after_credentials = and_connect

        def saved():
            self._update_account_row()
            if self._connect_after_credentials:
                self._connect_after_credentials = False
                GLib.idle_add(self._connect_after_credentials_now)

        window = CredentialsWindow(self, self.credentials, self.settings, saved)
        window.present()

    def _connect_after_credentials_now(self):
        if self._state in {"idle", "error"}:
            self._connect()
        return False

    def _open_locations(self):
        if self.catalogue is None:
            self._toast(_("The location list is not loaded yet."))
            return
        LocationWindow(
            self,
            self.catalogue.locations,
            self._selected_location(),
            self._location_selected,
            favorites=set(self.settings.favorites),
            on_favorite_toggled=self._set_favorite,
        ).present()

    def _set_favorite(self, key: str, enabled: bool):
        favorites = list(self.settings.favorites)
        if enabled:
            if key not in favorites:
                favorites.append(key)
        else:
            favorites = [item for item in favorites if item != key]
        favorites = favorites[:50]
        if favorites == self.settings.favorites:
            return
        self.settings.favorites = favorites
        try:
            self.settings_store.save(self.settings)
        except Exception as exc:
            log.warning("could not save favorites: %s", exc)
        self._refresh_tray()

    def _location_selected(self, location: Location):
        if self._state == "connected":
            self._choose_location(location)
            return
        self._select_location(location, save=True)
        self._update_location_row()

    def _show_help(self):
        dialog = Adw.Dialog()
        dialog.set_title(_("Help"))
        dialog.set_content_width(520)
        dialog.set_content_height(560)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        page = Adw.PreferencesPage()

        def section(title: str, paragraphs: list[str]) -> Adw.PreferencesGroup:
            group = Adw.PreferencesGroup(title=title)
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
            for text in paragraphs:
                label = Gtk.Label(label=text)
                label.set_wrap(True)
                label.set_xalign(0.0)
                label.set_selectable(True)
                box.append(label)
            group.add(box)
            return group

        page.add(
            section(
                _("UDP or TCP"),
                [
                    _(
                        "Both choices carry the same encrypted OpenVPN tunnel, with the same "
                        "certificate checks and authentication. Neither is more private or more secure."
                    ),
                    _(
                        "UDP sends packets without a connection handshake or retransmission. That "
                        "usually means lower overhead and lower latency, which is why it is the "
                        "default for VPNs, games, and calls."
                    ),
                    _(
                        "TCP adds ordered delivery and retransmission. Use it when a network blocks "
                        "UDP or only lets TCP through. Because OpenVPN over TCP carries TCP inside "
                        "TCP, packet loss can cause duplicate retransmissions and stalls, so it is "
                        "often slower and less responsive on unstable connections."
                    ),
                    _(
                        "Practical rule: use UDP first. Switch to TCP only if UDP cannot connect or "
                        "is unstable because the local network filters it."
                    ),
                ],
            )
        )
        page.add(
            section(
                _("Kill switch"),
                [
                    _(
                        "While the kill switch is armed, only the VPN servers, the tunnel and the "
                        "interfaces you always allow can be reached; everything else is blocked, "
                        "including DNS outside the tunnel. A restart of the computer turns it off."
                    ),
                    # Translators: {0} is a command; keep it unchanged.
                    _(
                        "If you are offline because the kill switch is still armed, run {0} in a "
                        "terminal."
                    ).format("pervius-killswitch disarm"),
                ],
            )
        )
        toolbar.set_content(page)
        dialog.set_child(toolbar)
        dialog.present(self)

    def _show_about(self):
        dialog = Adw.AboutDialog()
        dialog.set_application_name(APP_NAME)
        dialog.set_application_icon(APP_ID)
        dialog.set_version(VERSION)
        dialog.set_developer_name(DEVELOPER_NAME)
        dialog.set_website(HOMEPAGE_URL)
        dialog.set_issue_url(ISSUES_URL)
        dialog.set_comments(
            "\n\n".join(
                (
                    _(APP_TAGLINE),
                    _(
                        "It manages an existing FastVPN (OpenVPN) subscription through "
                        "NetworkManager and its OpenVPN plugin. The application never runs as "
                        "root; NetworkManager performs privileged network operations, and the "
                        "optional kill switch is a separate system service."
                    ),
                )
            )
        )
        dialog.set_copyright("© 2026 Solvetus Labs")
        dialog.set_developers([DEVELOPER_NAME])
        dialog.set_license_type(Gtk.License.APACHE_2_0)
        # Translators: put your names here, one per line, as shown in About.
        credits = _("translator-credits")
        if credits != "translator-credits":
            dialog.set_translator_credits(credits)
        dialog.add_legal_section(_("Trademarks"), None, Gtk.License.CUSTOM, _(DISCLAIMER))
        dialog.add_legal_section(
            _("Third-party components"),
            None,
            Gtk.License.CUSTOM,
            # Translators: {0} is the app name.
            _(
                "{0} is an independent front end. It uses the installed NetworkManager, "
                "NetworkManager-openvpn, OpenVPN, nftables, polkit, GTK, libadwaita, "
                "libsecret, libsoup, dnspython and iso-codes components. Those projects are "
                "distributed under their own licenses and are not bundled in this package."
            ).format(APP_NAME),
        )
        dialog.present(self)

    def _toast(self, text: str):
        """A short confirmation or hint that dismisses itself after ~3 s."""
        toast = Adw.Toast.new(text)
        toast.set_timeout(TOAST_SECONDS)
        self.toasts.add_toast(toast)

    def _show_banner(self, text: str):
        """A warning or error that stays until dismissed with the button.

        A banner the user dismissed does not come back for the same condition:
        the same text is suppressed until a new attempt (connect, refresh)
        starts, so only a changed condition shows it again.
        """
        if text in self._dismissed_banners:
            return
        self._banner_text = text
        self.banner.set_title(text)
        self.banner.set_revealed(True)

    def _on_banner_dismissed(self, *_args):
        if self._banner_text:
            self._dismissed_banners.add(self._banner_text)
        self.banner.set_revealed(False)

    def _clear_banner(self):
        """A new attempt starts: hide the banner and forget what was dismissed."""
        self._dismissed_banners.clear()
        self._banner_text = ""
        self.banner.set_revealed(False)

    # ------------------------------------------------------------ notifications

    def _send_notification(self, title: str, body: str) -> None:
        if not self.settings.notifications_enabled:
            return
        app = self.get_application()
        if app is None:
            return
        try:
            notification = Gio.Notification.new(title)
            notification.set_body(body)
            notification.set_icon(Gio.ThemedIcon.new(APP_ID))
            notification.set_default_action("app.present")
            app.send_notification(NOTIFICATION_ID, notification)
        except Exception as exc:
            log.warning("could not send desktop notification: %s", exc)

    def _notify_if_background(self, title: str, body: str) -> None:
        try:
            focused = self.get_visible() and self.is_active()
        except Exception:
            focused = self.get_visible()
        if not focused:
            self._send_notification(title, body)

    # ---------------------------------------------------------- cert cleanup

    def _inside_cert_dir(self, path_value: str) -> bool:
        try:
            path = Path(path_value).resolve(strict=True)
            root = certificate_dir().resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        return root in path.parents

    def _cleanup_unreferenced_ca(self, path_value: str):
        if not self._inside_cert_dir(path_value):
            return
        try:
            Path(path_value).unlink()
        except OSError as exc:
            log.warning("could not remove unreferenced CA file: %s", exc)

    def _cleanup_old_ca(self, old_value: str, new_value: str):
        if not old_value or old_value == new_value or not self._inside_cert_dir(old_value):
            return
        try:
            Path(old_value).unlink()
        except OSError as exc:
            log.warning("could not remove old CA file: %s", exc)

    # ------------------------------------------------------------ lifecycle

    def _alert(self, heading: str, body: str, responses, *, default: str, destructive=(), suggested=(), on_response):
        """A modal question with (id, label) responses."""
        dialog = Adw.AlertDialog.new(heading, body)
        for response_id, label in responses:
            dialog.add_response(response_id, label)
        dialog.set_close_response("cancel")
        dialog.set_default_response(default)
        for response_id in destructive:
            dialog.set_response_appearance(response_id, Adw.ResponseAppearance.DESTRUCTIVE)
        for response_id in suggested:
            dialog.set_response_appearance(response_id, Adw.ResponseAppearance.SUGGESTED)
        dialog.connect("response", lambda _dialog, response_id: on_response(response_id))
        dialog.present(self)

    def _save_window_size(self):
        """Remember the size like GNOME apps do; the default applies until then."""
        maximized = self.is_maximized()
        width, height = self.get_default_size()
        if not maximized and width > 0 and height > 0:
            self.settings.window_width, self.settings.window_height = width, height
        self.settings.window_maximized = maximized
        try:
            self.settings_store.save(self.settings)
        except OSError:
            pass

    def _on_close_request(self, *_args):
        self._save_window_size()
        if self._quitting or self._allow_close:
            return False
        if self._state == "reconnecting" or (
            self._state == "connecting" and self._reconnect_in_flight
        ):
            def response(response_id):
                if response_id == "hide":
                    self.hide()
                    self._send_notification(
                        _("VPN is reconnecting"),
                        # Translators: {0} is the app name.
                        _(
                            "{0} is still retrying in the background. "
                            "Open it from the app menu to see the status."
                        ).format(APP_NAME),
                    )
                elif response_id == "quit":
                    if self._killswitch_armed:
                        self._request_quit_with_killswitch()
                    else:
                        self._quit_now()

            self._alert(
                _("VPN is reconnecting"),
                _(
                    "The tunnel is currently down and the app is waiting to retry. "
                    "Closing this window hides it and keeps retrying in the background. "
                    "Quit stops automatic reconnection."
                ),
                (("cancel", _("Cancel")), ("hide", _("Keep Retrying")), ("quit", _("Quit"))),
                default="hide",
                destructive=("quit",),
                on_response=response,
            )
            return True
        if self._state in {"preparing", "connecting", "disconnecting"}:
            # Keep working in the background; the tray and the app menu bring
            # the window back.
            self.hide()
            return True
        if self._killswitch_armed:
            def response(response_id):
                if response_id == "hide":
                    self.hide()
                    self._send_notification(
                        _("Kill switch is armed"),
                        # Translators: {0} is the app name.
                        _("{0} is running in the background with firewall protection active.").format(
                            APP_NAME
                        ),
                    )
                elif response_id == "disarm_quit":
                    self._disarm_and_quit()
                elif response_id == "keep_quit":
                    self._quit_now()

            self._alert(
                _("Kill switch is armed"),
                _(
                    "Closing hides the window and keeps the app and firewall rules "
                    "running. Quitting can disarm first, or leave protection active; "
                    "while armed, traffic outside the VPN stays blocked. If the VPN is "
                    "not connected, normal internet access remains blocked."
                ),
                (
                    ("cancel", _("Cancel")),
                    ("hide", _("Hide Window")),
                    ("disarm_quit", _("Disarm and Quit")),
                    ("keep_quit", _("Quit and Keep Protection")),
                ),
                default="hide",
                destructive=("keep_quit",),
                on_response=response,
            )
            return True
        if self.active is None:
            self._quitting = True
            return False

        def response(response_id):
            if response_id == "hide":
                self.hide()
                self._send_notification(
                    _("VPN is still connected"),
                    # Translators: {0} is the app name.
                    _(
                        "{0} is running in the background. "
                        "Open it from the app menu to disconnect or quit."
                    ).format(APP_NAME),
                )
            elif response_id == "quit":
                self._quit_after_disconnect = True
                self._disconnect()

        self._alert(
            _("VPN is still connected"),
            # Translators: {0} is the app name.
            _(
                "Closing this window hides it and leaves the app process running so it "
                "can answer reauthentication requests. Open {0} again from the app menu "
                "to show the window. If the process exits, the tunnel may stay up without "
                "the secret agent."
            ).format(APP_NAME),
            (
                ("cancel", _("Cancel")),
                ("hide", _("Keep VPN Connected")),
                ("quit", _("Disconnect and Quit")),
            ),
            default="hide",
            destructive=("quit",),
            on_response=response,
        )
        return True

    def _request_quit(self, disconnect: bool | None):
        if self._state == "reconnecting" or (
            self._state == "connecting" and self._reconnect_in_flight
        ):
            def response(response_id):
                if response_id == "quit":
                    if self._killswitch_armed:
                        self._request_quit_with_killswitch()
                    else:
                        self._quit_now()

            self._alert(
                _("Quit while reconnecting?"),
                _(
                    "Automatic reconnection will stop if the app exits. The VPN is not "
                    "connected at this moment."
                ),
                (("cancel", _("Cancel")), ("quit", _("Quit"))),
                default="cancel",
                destructive=("quit",),
                on_response=response,
            )
            return
        if self._state in {"preparing", "connecting"} and not self._reconnect_in_flight:
            # Quit always works: stop the attempt and leave.
            self._cancel_connect()
            if self._killswitch_armed:
                self._request_quit_with_killswitch()
            else:
                self._quit_now()
            return
        if self._state == "disconnecting":
            self._quit_now()
            return
        if self._killswitch_armed:
            self._request_quit_with_killswitch()
            return
        if self.active is None:
            self._quit_now()
            return
        if disconnect is True:
            self._quit_after_disconnect = True
            self._disconnect()
            return

        def response(response_id):
            if response_id == "disconnect":
                self._quit_after_disconnect = True
                self._disconnect()
            elif response_id == "leave":
                self._quit_now()

        self._alert(
            _("Quit while connected?"),
            _(
                "The tunnel can stay up after the app exits, but the secret agent will also "
                "exit. If the VPN asks for credentials again, reauthentication cannot succeed "
                "until you reopen the app. Quit and disconnect if you want a clean stop."
            ),
            (
                ("cancel", _("Cancel")),
                ("leave", _("Quit and Leave Connected")),
                ("disconnect", _("Disconnect and Quit")),
            ),
            default="cancel",
            destructive=("disconnect",),
            on_response=response,
        )

    def _request_quit_with_killswitch(self):
        connected = self.active is not None or self._state == "connected"
        detail = (
            _("The VPN is connected; quitting can leave the tunnel up.")
            if connected
            else _("The VPN is not connected; normal internet access remains blocked.")
        )

        def response(response_id):
            if response_id == "disarm_quit":
                self._disarm_and_quit()
            elif response_id == "keep_quit":
                self._quit_now()

        self._alert(
            _("Quit with the kill switch armed?"),
            # Translators: {0} says whether the VPN is connected.
            _(
                "The system firewall rules will stay active if you quit without "
                "disarming. That keeps traffic blocked outside the VPN, but you may "
                "need the pervius-killswitch command to disarm later. {0}"
            ).format(detail),
            (
                ("cancel", _("Cancel")),
                ("disarm_quit", _("Disarm and Quit")),
                ("keep_quit", _("Quit and Keep Protection")),
            ),
            default="cancel",
            destructive=("keep_quit",),
            on_response=response,
        )

    def _disarm_and_quit(self):
        if self._killswitch_busy:
            self._show_banner(_("A kill-switch operation is already in progress."))
            return
        self._killswitch_busy = True
        self._killswitch_pending = "disarm_quit"
        self._render_killswitch_state()
        self._refresh_tray()
        self._toast(_("Disarming the kill switch before quitting…"))
        call_async(self.killswitch.disarm, self._on_disarm_for_quit)

    def _on_disarm_for_quit(self, status, error):
        self._killswitch_pending = ""
        self._killswitch_busy = False
        if self._disposed:
            return
        if error is not None:
            # Translators: {0} explains why disarming failed.
            self._show_banner(_("Could not disarm the kill switch: {0}").format(killswitch_error_text(error)))
            self._refresh_killswitch_status()
            return
        self._killswitch_status = status
        self._killswitch_armed = bool(status.get("armed", False))
        self._render_killswitch_state()
        self._quit_now()

    def _quit_now(self):
        self._save_window_size()
        self._quitting = True
        self._intent_connected = False
        self._reset_reconnect_state()
        self._stop_killswitch_poll()
        self._shutdown_tray()
        self._stop_stats()
        self._stop_poll()
        self._stop_timer()
        if self.agent is not None:
            try:
                self.agent.unregister()
            except Exception:
                log.exception("could not unregister the secret agent")
            self.agent = None
        try:
            self.settings_store.save(self.settings)
        except Exception:
            pass
        app = self.get_application()
        self.destroy()
        if app is not None:
            app.quit()

    def cleanup(self):
        if self._disposed:
            return
        self._disposed = True
        self._stop_killswitch_poll()
        self._shutdown_tray()
        self._reset_reconnect_state()
        self._stop_stats()
        self._stop_poll()
        self._stop_timer()
        if self.agent is not None:
            try:
                self.agent.unregister()
            except Exception:
                pass
            self.agent = None
