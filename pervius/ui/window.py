"""Main window and dialogs.

The UI is deliberately conservative: it exposes only actions that are backed
by the tested backend.  The kill switch is shown only with the state reported
by the system service; there is no auto-protect or DNS-filter toggle.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("NM", "1.0")
from gi.repository import Adw, Gio, GLib, Gtk, NM  # noqa: E402

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
    TRAY_ICON_CONNECTED,
    TRAY_ICON_DISCONNECTED,
    VERSION,
    certificate_dir,
    local_username,
)
from ..credentials import CredentialError, CredentialStore  # noqa: E402
from ..killswitch_client import KillSwitchClient, KillSwitchError, call_async  # noqa: E402
from ..nm.agent import AgentError, NetworkManagerSecretAgent  # noqa: E402
from ..nm.client import (  # noqa: E402
    NetworkManagerError,
    activate_async,
    active_vpn_for_uuid,
    add_connection_async,
    deactivate_async,
    get_connection_by_uuid,
    new_client,
    prepare_managed_profile_async,
    update_connection_async,
    vpn_state_name,
    vpn_state_reason,
)
from ..nm.importer import ImportVerificationError, verify_managed_profile  # noqa: E402
from ..ownership import (
    ManagedLookup,
    OwnershipError,
    OwnershipEntry,
    OwnershipStore,
    check_create_collision,
    find_managed_connection,
)
from ..public_ip import PublicIPError, fetch_public_ip  # noqa: E402
from ..reconnect import ReconnectPolicy  # noqa: E402
from ..settings import Settings, SettingsStore  # noqa: E402
from .tray import MenuItem, TrayError, TrayIcon  # noqa: E402

log = logging.getLogger(__name__)

_RECONNECT = ReconnectPolicy()
_ACTIVE_STATES = {"preparing", "reconnecting", "connecting", "connected", "disconnecting"}


class CredentialsWindow(Adw.Window):
    def __init__(self, parent, store: CredentialStore, settings: Settings, on_saved):
        super().__init__()
        self._store = store
        self._settings = settings
        self._on_saved = on_saved
        self.set_title("Account")
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_default_size(460, 390)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        save = Gtk.Button(label="Save")
        save.add_css_class("suggested-action")
        save.connect("clicked", self._save)
        header.pack_start(cancel)
        header.pack_end(save)
        toolbar.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_top(18)
        box.set_margin_bottom(18)
        box.set_margin_start(18)
        box.set_margin_end(18)

        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup()
        group.set_title("FastVPN account")
        group.set_description(
            "The password is sent to NetworkManager only when the VPN is activated. "
            "It is never written to the NetworkManager profile."
        )
        self.username_row = Adw.EntryRow()
        self.username_row.set_title("Username")
        self.username_row.set_text(settings.username)
        self.password_row = Adw.PasswordEntryRow()
        self.password_row.set_title("Password")
        self.save_row = Adw.SwitchRow()
        self.save_row.set_title("Save password in the desktop keyring")
        self.save_row.set_subtitle(
            "If unavailable, the password is kept only for this session."
            if store.persistence_available
            else "The desktop keyring is unavailable; the password will be session-only."
        )
        self.save_row.set_active(bool(settings.save_password and store.persistence_available))
        self.save_row.set_sensitive(store.persistence_available)
        group.add(self.username_row)
        group.add(self.password_row)
        group.add(self.save_row)
        page.add(group)
        box.append(page)

        self.error_label = Gtk.Label()
        self.error_label.set_wrap(True)
        self.error_label.set_xalign(0.0)
        self.error_label.add_css_class("error")
        self.error_label.set_visible(False)
        box.append(self.error_label)

        note = Gtk.Label()
        note.set_wrap(True)
        note.set_xalign(0.0)
        note.add_css_class("dim-label")
        note.set_label(
            "Credentials are not verified until a connection succeeds. "
            "Nothing is sent to Solvetus Labs; Pervius has no servers of its own."
        )
        box.append(note)

        clamp = Adw.Clamp()
        clamp.set_maximum_size(560)
        clamp.set_child(box)
        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        scroller.set_child(clamp)
        toolbar.set_content(scroller)
        self.set_content(toolbar)

        username = settings.username.strip()
        if username:
            remembered = store.lookup(username)
            if remembered:
                self.password_row.set_text(remembered)
        self.username_row.grab_focus()

    def _show_error(self, message: str) -> None:
        self.error_label.set_label(message)
        self.error_label.set_visible(True)

    def _save(self, *_args) -> None:
        username = self.username_row.get_text().strip()
        password = self.password_row.get_text()
        if not username:
            self._show_error("Enter your VPN username.")
            return
        if not password:
            self._show_error("Enter your VPN password.")
            return

        persist = bool(self.save_row.get_active())
        if persist and not self._store.persistence_available:
            persist = False
            self._store.remember(username, password)
            self._settings.username = username
            self._settings.save_password = False
            SettingsStore().save(self._settings)
            self._on_saved()
            self.close()
            return
        try:
            self._store.store(username, password, persist=persist)
        except CredentialError as exc:
            self._show_error(
                f"The password is in memory for this session, but could not be saved: {exc}"
            )
            self.save_row.set_active(False)
            return
        self._settings.username = username
        self._settings.save_password = persist
        SettingsStore().save(self._settings)
        self._on_saved()
        self.close()


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
        self.set_title("Choose Location")
        self.set_transient_for(parent)
        self.set_modal(True)
        self.set_default_size(500, 650)

        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        close = Gtk.Button(label="Close")
        close.connect("clicked", lambda *_: self.close())
        header.pack_end(close)
        toolbar.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)

        self.search = Gtk.SearchEntry()
        self.search.set_placeholder_text("Search city or country")
        self.search.connect("search-changed", lambda *_: self.listbox.invalidate_filter())
        search_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.search.set_hexpand(True)
        search_row.append(self.search)
        self.favorites_only = Gtk.ToggleButton()
        self.favorites_only.set_icon_name("starred-symbolic")
        self.favorites_only.set_tooltip_text("Show favorites only")
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
            "Locations come from the provider's public catalogue. "
            "Star a location to add it to Favorites and the tray menu; search "
            "understands city names, country names, codes, and common aliases."
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
            "Remove from favorites" if favorite else "Add to favorites"
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
            "Remove from favorites" if enabled else "Add to favorites"
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
        self.set_default_size(520, 760)

        self.settings_store = SettingsStore()
        self.settings: Settings = self.settings_store.load()
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
            ("credentials", lambda *_: self._open_credentials(False)),
            ("forget_password", lambda *_: self._forget_saved_password()),
            ("settings", lambda *_: self._show_settings()),
            ("protocols", lambda *_: self._show_protocol_help()),
            ("about", lambda *_: self._show_about()),
            ("quit", lambda *_: self._request_quit(None)),
        ):
            action = Gio.SimpleAction.new(name, None)
            action.connect("activate", callback)
            self.add_action(action)

    def _build_ui(self):
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar()
        title = Adw.WindowTitle(title=APP_NAME, subtitle="for FastVPN · via NetworkManager")
        header.set_title_widget(title)

        menu = Gio.Menu()
        menu.append("Refresh Locations", "win.refresh")
        menu.append("Credentials", "win.credentials")
        menu.append("Forget Saved Password", "win.forget_password")
        menu.append("Settings", "win.settings")
        menu.append("Protocol Guide", "win.protocols")
        menu.append("About", "win.about")
        menu.append("Quit", "win.quit")
        menu_button = Gtk.MenuButton()
        menu_button.set_icon_name("open-menu-symbolic")
        menu_button.set_menu_model(menu)
        menu_button.set_tooltip_text("Main menu")
        header.pack_end(menu_button)
        toolbar.add_top_bar(header)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        root.set_margin_top(18)
        root.set_margin_bottom(24)
        root.set_margin_start(18)
        root.set_margin_end(18)

        self.banner = Adw.Banner.new("")
        self.banner.set_revealed(False)
        root.append(self.banner)

        status_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        status_card.add_css_class("card")
        status_card.set_margin_top(4)
        status_card.set_margin_bottom(4)
        status_card.set_margin_start(18)
        status_card.set_margin_end(18)
        status_card.set_valign(Gtk.Align.CENTER)

        self.status_stack = Gtk.Stack()
        self.status_stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.status_stack.set_margin_top(20)
        self.status_stack.set_margin_start(18)
        self.status_stack.set_margin_end(18)
        self.status_icon = Gtk.Image.new_from_icon_name("network-vpn-symbolic")
        self.status_icon.set_pixel_size(72)
        self.status_icon.set_opacity(0.55)
        self.status_spinner = Gtk.Spinner()
        self.status_spinner.set_size_request(48, 48)
        self.status_stack.add_named(self.status_icon, "icon")
        spinner_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        spinner_box.set_halign(Gtk.Align.CENTER)
        spinner_box.append(self.status_spinner)
        self.status_stack.add_named(spinner_box, "spinner")
        self.status_stack.set_size_request(-1, 80)
        status_card.append(self.status_stack)

        self.status_title = Gtk.Label(label="Starting…")
        self.status_title.add_css_class("title-1")
        self.status_title.set_wrap(True)
        self.status_title.set_margin_start(18)
        self.status_title.set_margin_end(18)
        status_card.append(self.status_title)

        self.status_subtitle = Gtk.Label(label="")
        self.status_subtitle.add_css_class("dim-label")
        self.status_subtitle.set_wrap(True)
        self.status_subtitle.set_justify(Gtk.Justification.CENTER)
        self.status_subtitle.set_margin_start(22)
        self.status_subtitle.set_margin_end(22)
        self.status_subtitle.set_margin_bottom(8)
        status_card.append(self.status_subtitle)

        self.connect_button = Gtk.Button(label="Connect")
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
        self.connection_details.set_visible(True)

        ip_caption = Gtk.Label(label="IP ADDRESSES")
        ip_caption.add_css_class("caption")
        ip_caption.add_css_class("dim-label")
        ip_caption.set_xalign(0.0)
        self.connection_details.append(ip_caption)

        ip_grid = Gtk.Grid()
        ip_grid.set_column_spacing(14)
        ip_grid.set_row_spacing(4)
        ip_grid.set_halign(Gtk.Align.CENTER)
        isp_name = Gtk.Label(label="ISP IP")
        isp_name.add_css_class("dim-label")
        isp_name.set_xalign(1.0)
        self.isp_ip_value = Gtk.Label(label="—")
        self.isp_ip_value.set_xalign(0.0)
        self.isp_ip_value.set_selectable(True)
        vpn_name = Gtk.Label(label="VPN exit IP")
        vpn_name.add_css_class("dim-label")
        vpn_name.set_xalign(1.0)
        self.vpn_ip_value = Gtk.Label(label="—")
        self.vpn_ip_value.set_xalign(0.0)
        self.vpn_ip_value.set_selectable(True)
        ip_grid.attach(isp_name, 0, 0, 1, 1)
        ip_grid.attach(self.isp_ip_value, 1, 0, 1, 1)
        ip_grid.attach(vpn_name, 0, 1, 1, 1)
        ip_grid.attach(self.vpn_ip_value, 1, 1, 1, 1)
        self.connection_details.append(ip_grid)

        self.switch_ip_button = Gtk.Button(label="Switch IP")
        self.switch_ip_button.add_css_class("flat")
        self.switch_ip_button.set_halign(Gtk.Align.CENTER)
        self.switch_ip_button.set_tooltip_text(
            "Reconnect the VPN to request a different server IP."
        )
        self.switch_ip_button.connect("clicked", lambda *_: self._switch_ip())
        self.connection_details.append(self.switch_ip_button)

        self.connection_details.append(Gtk.Separator())

        stats = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
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
        self.download_value.set_tooltip_text("Traffic received since this connection")
        self.upload_value = Gtk.Label(label="—")
        self.upload_value.set_tooltip_text("Traffic sent since this connection")
        self.protocol_value = Gtk.Label(label="OpenVPN")
        stats.append(stat_column("go-down-symbolic", "Download", self.download_value))
        stats.append(stat_column("go-up-symbolic", "Upload", self.upload_value))
        stats.append(stat_column("network-vpn-symbolic", "Protocol", self.protocol_value))
        self.connection_details.append(stats)
        status_card.append(self.connection_details)
        root.append(status_card)

        group = Adw.PreferencesGroup()
        group.set_title("Connection")
        self.location_row = Adw.ActionRow()
        self.location_row.set_title("Location")
        self.location_row.set_subtitle("Not selected")
        self.location_row.set_icon_name("mark-location-symbolic")
        change = Gtk.Button(label="Change")
        change.add_css_class("flat")
        change.connect("clicked", lambda *_: self._open_locations())
        self.location_row.add_suffix(change)
        self.location_button = change
        group.add(self.location_row)

        self.protocol_row = Adw.ActionRow()
        self.protocol_row.set_title("Protocol")
        self.protocol_row.set_subtitle(
            "UDP is the usual default. Try TCP only when UDP is blocked."
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
        self.udp_button.set_tooltip_text("UDP — lower latency; the usual choice.")
        self.tcp_button.set_tooltip_text(
            "TCP — use when the network blocks or filters UDP."
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
        self.account_row.set_title("Account")
        self.account_row.set_subtitle("Credentials not set")
        self.account_row.set_icon_name("avatar-default-symbolic")
        edit = Gtk.Button(label="Edit")
        edit.add_css_class("flat")
        edit.connect("clicked", lambda *_: self._open_credentials(False))
        self.account_row.add_suffix(edit)
        self.account_button = edit
        group.add(self.account_row)

        self.auto_reconnect_row = Adw.SwitchRow()
        self.auto_reconnect_row.set_title("Reconnect automatically")
        self.auto_reconnect_row.set_subtitle(
            "Retry after an unexpected drop, with increasing delays. "
            "Manual disconnects and failed first attempts never retry."
        )
        self.auto_reconnect_row.set_icon_name("emblem-synchronizing-symbolic")
        self.auto_reconnect_row.set_active(bool(self.settings.auto_reconnect))
        self.auto_reconnect_row.connect(
            "notify::active", self._on_auto_reconnect_changed
        )
        group.add(self.auto_reconnect_row)
        root.append(group)

        security = Adw.PreferencesGroup()
        security.set_title("Security")
        self.killswitch_row = Adw.SwitchRow()
        self.killswitch_row.set_title("Kill switch")
        self.killswitch_row.set_subtitle("Checking the system service…")
        self.killswitch_row.set_icon_name("security-high-symbolic")
        self.killswitch_row.set_sensitive(False)
        self.killswitch_row.connect("notify::active", self._on_killswitch_switch)
        security.add(self.killswitch_row)

        self.allow_lan_row = Adw.SwitchRow()
        self.allow_lan_row.set_title("Allow local network")
        self.allow_lan_row.set_subtitle(
            "Permit RFC1918/ULA traffic while the kill switch is armed."
        )
        self.allow_lan_row.set_icon_name("network-workgroup-symbolic")
        self.allow_lan_row.set_active(bool(self.settings.killswitch_allow_lan))
        self.allow_lan_row.set_sensitive(False)
        self.allow_lan_row.connect("notify::active", self._on_allow_lan_changed)
        security.add(self.allow_lan_row)

        killswitch_note = Adw.ActionRow()
        killswitch_note.set_title("Traffic outside the VPN is blocked")
        killswitch_note.set_subtitle(
            "Rules allow only the VPN server, the tunnel, DHCP, and link control. "
            "DNS outside the tunnel and global IPv6 are blocked. The root service "
            "is idle until armed."
        )
        killswitch_note.set_icon_name("dialog-warning-symbolic")
        security.add(killswitch_note)
        root.append(security)

        self.footer = Gtk.Label()
        self.footer.set_wrap(True)
        self.footer.set_justify(Gtk.Justification.CENTER)
        self.footer.add_css_class("caption")
        self.footer.add_css_class("dim-label")
        self.footer.set_label(
            f"{APP_NAME} {VERSION} · independent project, not affiliated with the VPN provider · "
            "catalogue source: vpn.ncapi.io"
        )
        root.append(self.footer)

        scroller = Gtk.ScrolledWindow()
        scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        clamp = Adw.Clamp()
        clamp.set_maximum_size(620)
        clamp.set_child(root)
        scroller.set_child(clamp)
        toolbar.set_content(scroller)
        self.set_content(toolbar)

        self.connect("close-request", self._on_close_request)
        self._set_state("loading")
        self._update_account_row()
        self._update_location_row()

    def _init_backend(self):
        try:
            self.client = new_client()
        except NetworkManagerError as exc:
            self._blocked(f"NetworkManager is unavailable: {exc}")
            return
        try:
            self.agent = NetworkManagerSecretAgent(
                lambda _local_user: self.credentials.lookup(
                    self.settings.username.strip()
                ),
                store_provider=OwnershipStore.load,
            )
            self.agent.register()
        except AgentError as exc:
            log.warning("secret agent unavailable: %s", exc)
            self.agent = None
            self._blocked(str(exc))
            return
        self._reconcile_active()

    # ------------------------------------------------------------------ tray

    def _init_tray(self):
        try:
            self.tray = TrayIcon(
                app_id=APP_ID,
                title=APP_NAME,
                icon_name=APP_ID,
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
        self._killswitch_ready = True
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
                self._killswitch_last_error
                or "System service unavailable; the optional package is not active."
            )
            self._set_allow_lan_switch(bool(self.settings.killswitch_allow_lan))
            self.allow_lan_row.set_sensitive(False)
            self._update_controls()
            return

        armed = bool(status.get("armed"))
        state = str(status.get("state", "off"))
        detail = str(status.get("detail", ""))
        endpoints = int(status.get("endpoints", 0) or 0)
        self._killswitch_armed = armed
        self._set_killswitch_switch(armed)
        self.killswitch_row.set_sensitive(not self._killswitch_busy)
        if self._killswitch_busy:
            subtitle = "Applying…"
        elif state == "error":
            subtitle = detail or "The system service reported an error."
        elif armed:
            if self._state == "connected":
                subtitle = (
                    f"Armed — {endpoints} VPN endpoints allowed; all other "
                    "traffic is blocked."
                )
            else:
                subtitle = (
                    "Armed — VPN not connected; internet traffic is blocked. "
                    "Disarm before changing location or protocol."
                )
        else:
            subtitle = "Off — normal network traffic is allowed."
        self.killswitch_row.set_subtitle(subtitle)

        if armed:
            self._set_allow_lan_switch(bool(status.get("allow_lan")))
            self.allow_lan_row.set_sensitive(False)
            self.allow_lan_row.set_subtitle("Locked while armed; disarm to change.")
        else:
            self._set_allow_lan_switch(bool(self.settings.killswitch_allow_lan))
            self.allow_lan_row.set_sensitive(not self._killswitch_busy)
            self.allow_lan_row.set_subtitle(
                "Permit RFC1918/ULA traffic while the kill switch is armed."
            )
        self._update_controls()

    def _on_killswitch_switch(self, row, _pspec):
        if self._killswitch_syncing:
            return
        desired = bool(row.get_active())
        if desired == self._killswitch_armed:
            return
        self._set_killswitch_switch(self._killswitch_armed)
        if self._killswitch_busy:
            self._show_banner("A kill-switch operation is already in progress.")
        elif desired:
            self._confirm_enable_killswitch()
        else:
            self._confirm_disable_killswitch()

    def _on_allow_lan_changed(self, row, _pspec):
        if self._killswitch_syncing:
            return
        if self._killswitch_armed:
            self._set_allow_lan_switch(bool(self.settings.killswitch_allow_lan))
            self._show_banner("Disarm the kill switch before changing LAN access.")
            return
        self.settings.killswitch_allow_lan = bool(row.get_active())
        try:
            self.settings_store.save(self.settings)
        except Exception as exc:
            log.warning("could not save kill-switch LAN preference: %s", exc)
        self._refresh_tray()

    def _confirm_enable_killswitch(self):
        local = (
            "Local network traffic will remain allowed."
            if self.settings.killswitch_allow_lan
            else "Local network traffic will also be blocked."
        )
        dialog = Adw.MessageDialog.new(
            self,
            "Enable the kill switch?",
            "All traffic outside the VPN will be blocked, including DNS and "
            "global IPv6. If the VPN is not connected, normal internet access "
            f"will stop until you disarm it or connect. {local}",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("enable", "Enable")
        dialog.set_close_response("cancel")
        dialog.set_default_response("cancel")
        dialog.set_response_appearance("enable", Adw.ResponseAppearance.SUGGESTED)
        dialog.set_transient_for(self)

        def response(_dialog, response_id):
            if response_id == "enable":
                self._arm_killswitch()
            dialog.destroy()

        dialog.connect("response", response)
        dialog.present()

    def _confirm_disable_killswitch(self):
        dialog = Adw.MessageDialog.new(
            self,
            "Disable the kill switch?",
            "The firewall rules will be removed and normal network traffic will "
            "be allowed again, even if the VPN is down.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("disable", "Disable")
        dialog.set_close_response("cancel")
        dialog.set_default_response("cancel")
        dialog.set_response_appearance("disable", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_transient_for(self)

        def response(_dialog, response_id):
            if response_id == "disable":
                self._disarm_killswitch()
            dialog.destroy()

        dialog.connect("response", response)
        dialog.present()

    def _arm_killswitch(self):
        if self._killswitch_busy:
            return
        self._killswitch_busy = True
        self._killswitch_pending = "arm"
        self._render_killswitch_state()
        self._refresh_tray()
        call_async(
            lambda: self.killswitch.arm(self.settings.killswitch_allow_lan),
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
            self._show_banner(f"Kill-switch operation failed: {error}")
            self._refresh_killswitch_status()
            return
        self._killswitch_status = status
        self._killswitch_last_error = ""
        self._render_killswitch_state()
        self._refresh_tray()
        if pending == "arm":
            self._isp_ip_checked = True
            self._update_ip_labels()
            self._show_banner("Kill switch armed. Traffic outside the VPN is blocked.")
        elif pending == "disarm":
            self._isp_ip_checked = False
            self._maybe_fetch_ip("isp")
            self._update_ip_labels()
            self._show_banner("Kill switch disabled. Normal traffic is allowed.")
        self._refresh_killswitch_status()

    def _toggle_killswitch_from_tray(self):
        self._present_from_tray()
        if self._killswitch_busy:
            self._show_banner("A kill-switch operation is already in progress.")
            return
        if self._killswitch_status is None:
            self._show_banner("The kill-switch service is unavailable.")
            self._refresh_killswitch_status()
            return
        if self._killswitch_armed:
            self._confirm_disable_killswitch()
        else:
            self._confirm_enable_killswitch()

    # ------------------------------------------------------- connection details

    def _refresh_connection_details(self):
        self.connection_details.set_visible(True)
        self.protocol_value.set_label(f"OpenVPN · {self.settings.protocol.upper()}")
        if self._state != "connected":
            self._stop_stats()
            self._vpn_exit_ip = ""
            self.download_value.set_text("—")
            self.upload_value.set_text("—")
            self._update_ip_labels()
            self._maybe_fetch_ip("isp")
            return
        self._update_ip_labels()
        self._start_stats()
        self._maybe_fetch_ip("vpn")

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
            ip = fetch_public_ip()
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
        isp = self._isp_ip
        if not isp:
            if self._state == "connected" and not self._isp_ip_checked:
                isp = "Not captured"
            elif self._isp_ip_checked:
                isp = "Unavailable"
            else:
                isp = "Checking…"
        self.isp_ip_value.set_text(isp)
        if self._state == "connected":
            vpn = self._vpn_exit_ip
            if not vpn:
                vpn = "Checking…" if self._ip_fetching == "vpn" else "Unavailable"
        else:
            vpn = "—"
        self.vpn_ip_value.set_text(vpn)
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
        active = self.active
        if active is None:
            return None
        try:
            devices = active.get_devices()
        except Exception:
            return None
        for device in devices:
            try:
                iface = device.get_iface() or device.get_ip_iface()
            except Exception:
                continue
            if not iface:
                continue
            base = Path("/sys/class/net") / iface / "statistics"
            try:
                rx = int((base / "rx_bytes").read_text(encoding="ascii").strip())
                tx = int((base / "tx_bytes").read_text(encoding="ascii").strip())
            except (OSError, ValueError):
                continue
            return rx, tx, iface
        return None

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
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024.0 or unit == "TB":
                if unit == "B":
                    return f"{int(size)} B"
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def _present_from_tray(self):
        self.present()
        app = self.get_application()
        if app is not None:
            app.withdraw_notification(NOTIFICATION_ID)

    def _tray_icon_name(self) -> str:
        return (
            TRAY_ICON_CONNECTED
            if self._state == "connected"
            else TRAY_ICON_DISCONNECTED
        )

    def _tray_tooltip(self) -> tuple[str, str]:
        location = self._selected_location()
        where = (
            f"{location.display_city}, {location.display_country}"
            if location is not None
            else ""
        )
        if self._state == "connected":
            detail = f"Connected · {where} · {self.settings.protocol.upper()}"
        elif self._state == "reconnecting":
            detail = "Reconnecting…"
        elif self._state in {"preparing", "connecting", "disconnecting"}:
            detail = "Connecting…"
        elif self._state == "error":
            detail = "Connection failed"
        else:
            detail = f"Not connected · {where}" if where else "Not connected"
        return (APP_NAME, detail)

    def _tray_favorite_items(self) -> tuple[MenuItem, ...]:
        children: list[MenuItem] = []
        if self.catalogue is not None:
            for index, key in enumerate(self.settings.favorites[:20]):
                location = self.catalogue.location_by_key(key)
                if location is None:
                    continue
                children.append(
                    MenuItem(
                        201 + index,
                        f"{location.flag} {location.display_city}, {location.display_country}",
                        action=f"favorite|{key}",
                    )
                )
        if children:
            children.append(MenuItem(298, separator=True))
        else:
            children.append(MenuItem(297, "No favorites yet", enabled=False))
        children.append(MenuItem(299, "Manage Favorites…", action="locations"))
        return tuple(children)

    def _tray_menu(self) -> tuple[MenuItem, ...]:
        state = self._state
        location = self._selected_location()
        where = (
            f"{location.display_city}, {location.display_country}"
            if location is not None
            else ""
        )
        if state == "connected":
            primary = "Disconnect"
            primary_enabled = True
        elif state == "reconnecting":
            primary = "Stop Retrying"
            primary_enabled = True
        elif state in {"preparing", "connecting", "disconnecting"}:
            primary = (
                "Disconnecting…"
                if state == "disconnecting"
                else "Preparing…" if state == "preparing" else "Connecting…"
            )
            primary_enabled = False
        elif state == "error":
            primary = f"Try Again — {where}" if where else "Try Again"
            primary_enabled = location is not None
        else:
            primary = f"Connect — {where}" if where else "Connect…"
            primary_enabled = bool(
                location is not None
                and self.catalogue is not None
                and self.client is not None
                and self.agent is not None
            )

        controls_enabled = state not in _ACTIVE_STATES and not self._killswitch_armed
        return (
            MenuItem(1, "Connect to:", enabled=False),
            MenuItem(2, primary, enabled=primary_enabled, action="toggle"),
            MenuItem(
                3,
                "Favorites",
                enabled=self.catalogue is not None,
                children=self._tray_favorite_items(),
            ),
            MenuItem(
                4,
                "Choose Location…",
                enabled=self.catalogue is not None and controls_enabled,
                action="locations",
            ),
            MenuItem(5, separator=True),
            MenuItem(6, f"Show {APP_NAME}", action="show"),
            MenuItem(7, separator=True),
            MenuItem(8, "Settings…", action="settings"),
            MenuItem(
                9,
                "Notifications",
                toggle_state=1 if self.settings.notifications_enabled else 0,
                action="notifications",
            ),
            MenuItem(
                10,
                "Kill switch",
                enabled=self._killswitch_status is not None
                and not self._killswitch_busy,
                toggle_state=1 if self._killswitch_armed else 0,
                action="killswitch",
            ),
            MenuItem(11, separator=True),
            MenuItem(
                12,
                "Help",
                children=(
                    MenuItem(121, "Protocol Guide", action="protocols"),
                    MenuItem(122, f"About {APP_NAME}", action="about"),
                ),
            ),
            MenuItem(
                13,
                "Legal Information",
                children=(
                    MenuItem(131, "License", action="legal_license"),
                    MenuItem(132, "Third-party components", action="legal_components"),
                ),
            ),
            MenuItem(14, separator=True),
            MenuItem(
                15,
                "Forget Saved Password…",
                enabled=bool(self.settings.username.strip()),
                action="forget",
            ),
            MenuItem(16, "Quit", action="quit"),
        )

    def _tray_action(self, action: str):
        if action == "toggle":
            self._tray_toggle_connection()
            return
        if action == "quit":
            self._present_from_tray()
            self._request_quit(None)
            return
        if action == "notifications":
            self._set_notifications(not self.settings.notifications_enabled)
            return
        if action == "killswitch":
            self._toggle_killswitch_from_tray()
            return
        if action.startswith("favorite|"):
            self._tray_select_favorite(action.split("|", 1)[1])
            return
        self._present_from_tray()
        if action == "show":
            return
        if action == "locations":
            self._open_locations()
        elif action == "settings":
            self._show_settings()
        elif action == "protocols":
            self._show_protocol_help()
        elif action == "about":
            self._show_about()
        elif action == "legal_license":
            self._show_legal("license")
        elif action == "legal_components":
            self._show_legal("components")
        elif action == "forget":
            self._forget_saved_password()

    def _tray_toggle_connection(self):
        self._present_from_tray()
        if self._state == "connected":
            self._disconnect()
        elif self._state == "reconnecting":
            self._cancel_reconnect("Automatic reconnection stopped.")
        elif self._state in {"idle", "error"}:
            self._connect()
        else:
            self._show_banner("Wait for the current connection operation to finish.")

    def _tray_select_favorite(self, key: str):
        self._present_from_tray()
        if self._killswitch_armed:
            self._show_banner(
                "Disarm the kill switch before switching to another location."
            )
            return
        if self.catalogue is None:
            self._show_banner("The location list is not loaded yet.")
            return
        location = self.catalogue.location_by_key(key)
        if location is None:
            self._set_favorite(key, False)
            self._show_banner(
                "That favorite is no longer in the catalogue and was removed."
            )
            return
        where = f"{location.flag} {location.display_city}, {location.display_country}"
        if self._state in {"preparing", "connecting", "disconnecting"}:
            self._show_banner("Wait for the current connection operation to finish.")
            return
        current = self._selected_location()
        if self._state == "connected":
            if current is not None and current.key == location.key:
                self._show_banner(f"Already connected to {where}.")
                return
            dialog = Adw.MessageDialog.new(
                self,
                "Switch VPN location?",
                f"Disconnect from the current VPN and connect to {where}?",
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("switch", "Switch")
            dialog.set_close_response("cancel")
            dialog.set_default_response("cancel")
            dialog.set_response_appearance("switch", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_transient_for(self)

            def response(_dialog, response_id):
                if response_id == "switch":
                    self._select_location(location)
                    self._pending_switch_key = location.key
                    self._disconnect()
                dialog.destroy()

            dialog.connect("response", response)
            dialog.present()
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
        dialog.set_title("Settings")
        page = Adw.PreferencesPage()
        group = Adw.PreferencesGroup(title="Connection")
        reconnect = Adw.SwitchRow()
        reconnect.set_title("Reconnect automatically")
        reconnect.set_subtitle(
            "Retry after an unexpected drop, with increasing delays. "
            "Manual disconnects and failed first attempts never retry."
        )
        reconnect.set_active(bool(self.settings.auto_reconnect))
        reconnect.connect(
            "notify::active",
            lambda row, _pspec: self._set_auto_reconnect(bool(row.get_active())),
        )
        group.add(reconnect)
        notifications = Adw.SwitchRow()
        notifications.set_title("Desktop notifications")
        notifications.set_subtitle(
            "Show connection loss, recovery, and background status while the window is hidden."
        )
        notifications.set_active(bool(self.settings.notifications_enabled))
        notifications.connect(
            "notify::active",
            lambda row, _pspec: self._set_notifications(bool(row.get_active())),
        )
        group.add(notifications)
        page.add(group)

        privacy = Adw.PreferencesGroup(title="Credentials")
        keyring = Adw.ActionRow()
        keyring.set_title("Password storage")
        keyring.set_subtitle(
            "Saved only in the desktop keyring when you enable it in the Account "
            "dialog. Use Forget Saved Password to remove it."
        )
        keyring.set_icon_name("channel-secure-symbolic")
        privacy.add(keyring)
        page.add(privacy)
        dialog.add(page)
        dialog.present(self)

    def _show_legal(self, topic: str):
        if topic == "components":
            title = "Third-party components"
            body = (
                f"{APP_NAME} is an independent front end. It uses the installed "
                "NetworkManager, NetworkManager-openvpn, OpenVPN, nftables, polkit, "
                "GTK, libadwaita, libsecret, and libsoup components. Those projects "
                "are distributed under their own licenses and are not bundled in "
                "this package."
            )
        else:
            title = "License"
            body = (
                f"{APP_NAME} is free software, licensed under the Apache License, "
                f"Version 2.0. Source code: {HOMEPAGE_URL}\n\n{DISCLAIMER}"
            )
        dialog = Adw.MessageDialog.new(self, title, body)
        dialog.add_response("close", "Close")
        dialog.set_close_response("close")
        dialog.set_default_response("close")
        dialog.set_transient_for(self)
        dialog.present()

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
                "A VPN connection uses the reserved Pervius UUID, but its ownership "
                f"cannot be verified: {exc}"
            )
            return
        if lookup.connection is None:
            self._blocked(
                "A VPN connection uses the reserved Pervius UUID, but no owned "
                "profile was found; refusing to manage it."
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
            self._fail(f"The VPN connection is in a failed state: {vpn_state_reason(active)}")
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
        self.banner.set_revealed(False)

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
            message = f"Could not load the location list: {error}"
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
        if error is not None:
            self._show_banner(f"Using the saved location list; refresh failed: {error}")
        elif refreshed and self.active is None:
            self._show_banner(
                f"Loaded {catalogue.profile_count} profiles in {len(catalogue.locations)} locations."
            )
            GLib.timeout_add_seconds(6, self._hide_banner)

    def _hide_banner(self):
        self.banner.set_revealed(False)
        return False

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
        if self._killswitch_armed:
            self._set_protocol(self.settings.protocol)
            self._show_banner("Disarm the kill switch before changing protocol.")
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
        self._update_location_row()
        if self._state not in _ACTIVE_STATES:
            self.settings_store.save(self.settings)

    def _update_location_row(self):
        location = self._selected_location()
        if location is None:
            self.location_row.set_subtitle("Not selected")
        else:
            proto = self.settings.protocol.upper()
            prefix = f"{location.flag} " if location.flag else ""
            self.location_row.set_subtitle(
                f"{prefix}{location.display_city}, {location.display_country} · {proto}"
            )
        if self._state == "idle":
            self._refresh_idle_subtitle()
        self._refresh_tray()

    def _update_account_row(self):
        username = self.settings.username.strip()
        self.account_row.set_subtitle(username if username else "Credentials not set")

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
            self._cancel_reconnect("Automatic reconnection disabled.")
        self._refresh_tray()

    def _forget_saved_password(self):
        username = self.settings.username.strip()
        if not username:
            self._show_banner("No VPN username is set; there is no saved password to forget.")
            return
        dialog = Adw.MessageDialog.new(
            self,
            "Forget saved password?",
            f"This removes the desktop-keyring entry and the in-memory copy for "
            f"{username}. An already-connected VPN stays up, but reauthentication "
            "may fail until you enter the password again.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("forget", "Forget Password")
        dialog.set_close_response("cancel")
        dialog.set_default_response("cancel")
        dialog.set_response_appearance("forget", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_transient_for(self)

        def response(_dialog, response_id):
            if response_id == "forget":
                try:
                    removed = self.credentials.forget(username)
                except CredentialError as exc:
                    self._show_banner(f"Could not remove the saved password: {exc}")
                else:
                    self._show_banner(
                        "Saved password removed."
                        if removed
                        else "Password removed from this session; no keyring entry was present."
                    )
            dialog.destroy()

        dialog.connect("response", response)
        dialog.present()

    # --------------------------------------------------------------- actions

    def _on_connect_clicked(self, *_args):
        if self._state == "connected":
            self._disconnect()
        elif self._state == "reconnecting":
            self._cancel_reconnect("Automatic reconnection stopped.")
        elif self._state in {"idle", "error"}:
            self._connect()

    def _ensure_credentials(self) -> bool:
        username = self.settings.username.strip()
        if not username:
            self._open_credentials(True)
            return False
        if self.credentials.lookup(username):
            return True
        self._open_credentials(True)
        return False

    def _connect(self):
        if self.client is None:
            self._blocked("NetworkManager is unavailable.")
            return
        if self.agent is None or not self.agent.registered:
            self._blocked("The NetworkManager secret agent is not registered; reconnect after restarting the app.")
            return
        ref = self._selected_ref()
        if ref is None:
            self._show_banner("Choose a location and protocol first.")
            return
        if self.active is not None:
            self._show_banner("A VPN connection is already active. Disconnect it first.")
            return
        if not self._ensure_credentials():
            return
        vpn_username = self.settings.username.strip()
        try:
            store = OwnershipStore.load()
            lookup: ManagedLookup = find_managed_connection(
                self.client.get_connections(), store, self.local_username
            )
        except OwnershipError as exc:
            self._blocked(str(exc))
            return
        self.ownership = store
        self._existing_connection = lookup.connection
        self._old_entry = lookup.entry
        self._warning = ""
        self.banner.set_revealed(False)

        if lookup.connection is not None:
            try:
                verify_managed_profile(lookup.connection, ref.profile, certificate_dir())
            except (ImportVerificationError, OSError) as exc:
                log.info("existing profile will be re-imported: %s", exc)
            else:
                self._intent_connected = True
                self._activate(lookup.connection)
                return

        self._intent_connected = True
        self._set_state("preparing")
        self.footer.set_label(
            f"{APP_NAME} {VERSION} · importing and verifying the selected profile…"
        )
        prepare_managed_profile_async(
            ref, vpn_username, self.local_username, self._on_prepared
        )

    def _on_prepared(self, prepared, error):
        if self._disposed:
            return
        self.footer.set_label(
            f"{APP_NAME} {VERSION} · independent project, not affiliated with the VPN provider · "
            "catalogue source: vpn.ncapi.io"
        )
        if error is not None:
            self._fail(f"Could not prepare the VPN profile: {error}")
            return
        self._prepared = prepared
        self._apply_prepared(prepared)

    def _apply_prepared(self, prepared):
        try:
            lookup = find_managed_connection(
                self.client.get_connections(), self.ownership, self.local_username
            )
        except OwnershipError as exc:
            self._cleanup_unreferenced_ca(prepared.ca_path)
            self._blocked(str(exc))
            return
        existing = lookup.connection
        self._existing_connection = existing
        self._old_entry = lookup.entry

        def done(connection, error):
            if self._disposed:
                return
            if error is not None:
                self._cleanup_unreferenced_ca(prepared.ca_path)
                self._fail(f"Could not save the managed profile: {error}")
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
                self._fail(
                    "The NetworkManager profile was created, but the ownership manifest "
                    f"could not be saved: {exc}. The profile will not be used."
                )
                return
            if lookup.entry and lookup.entry.ca_path and lookup.entry.ca_path != prepared.ca_path:
                self._cleanup_old_ca(lookup.entry.ca_path, prepared.ca_path)
            self._existing_connection = connection
            self._warning = " ".join(prepared.warnings)
            self._activate(connection)

        if existing is not None:
            update_connection_async(existing, prepared.variant, done)
        else:
            try:
                check_create_collision(self.client.get_connections(), self.local_username)
            except OwnershipError as exc:
                self._cleanup_unreferenced_ca(prepared.ca_path)
                self._blocked(str(exc))
                return
            add_connection_async(self.client, prepared.variant, done)

    def _activate(self, connection, *, reconnecting: bool = False):
        self._reconnect_in_flight = reconnecting
        self._set_state("connecting")
        self._connect_deadline = time.monotonic() + 90
        self._start_poll()

        def done(active, error):
            if self._disposed:
                return
            if error is not None:
                if self._should_retry_after_failure():
                    self._reconnect_in_flight = False
                    self._stop_poll()
                    self._schedule_next_reconnect(str(error))
                else:
                    self._fail(str(error))
                return
            self.active = active
            state = vpn_state_name(active)
            if state == "activated":
                self._set_connected()
            elif state == "failed":
                reason = f"The VPN connection failed: {vpn_state_reason(active)}"
                if self._should_retry_after_failure():
                    self._reconnect_in_flight = False
                    self._stop_poll()
                    self._schedule_next_reconnect(reason)
                else:
                    self._fail(reason)
            else:
                self._set_state("connecting")

        activate_async(self.client, connection, done)

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
            self._cancel_reconnect("Automatic reconnection stopped.")
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
                self._fail(str(error))
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
            self._show_banner(message)
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
        self.status_icon.set_opacity(1.0 if state == "connected" else 0.55)

        if state == "loading":
            self.status_title.set_label("Loading locations…")
            self.status_subtitle.set_label("Reading the public catalogue.")
            self.connect_button.set_label("Connect")
            self.connect_button.set_sensitive(False)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "idle":
            self.status_title.set_label("Not connected")
            self._refresh_idle_subtitle()
            self.connect_button.set_label("Connect")
            self.connect_button.set_sensitive(
                self.catalogue is not None
                and self.client is not None
                and self.agent is not None
                and self.agent.registered
            )
            self.connect_button.remove_css_class("destructive-action")
        elif state == "preparing":
            self.status_title.set_label("Preparing VPN profile…")
            self.status_subtitle.set_label("Importing and verifying the selected profile.")
            self.connect_button.set_label("Connecting…")
            self.connect_button.set_sensitive(False)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "connecting":
            self.status_title.set_label("Connecting…")
            self.status_subtitle.set_label("Waiting for NetworkManager and the OpenVPN plugin.")
            self.connect_button.set_label("Connecting…")
            self.connect_button.set_sensitive(False)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "reconnecting":
            self.status_title.set_label("Reconnecting…")
            self._update_reconnect_subtitle()
            self.connect_button.set_label("Stop Retrying")
            self.connect_button.set_sensitive(True)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "connected":
            self.status_title.set_label("Connected")
            self._refresh_connected_subtitle()
            self.connect_button.set_label("Disconnect")
            self.connect_button.set_sensitive(True)
            self.connect_button.add_css_class("destructive-action")
            self.connect_button.remove_css_class("suggested-action")
        elif state == "disconnecting":
            self.status_title.set_label("Disconnecting…")
            self.status_subtitle.set_label("Telling NetworkManager to stop the tunnel.")
            self.connect_button.set_label("Disconnecting…")
            self.connect_button.set_sensitive(False)
            self.connect_button.remove_css_class("destructive-action")
        elif state == "error":
            self.status_title.set_label("Connection failed" if self.active else "Not connected")
            self.status_subtitle.set_label(detail or "The last operation failed.")
            self.connect_button.set_label("Try Again")
            self.connect_button.set_sensitive(
                self.catalogue is not None
                and self.client is not None
                and self.agent is not None
                and self.agent.registered
            )
            self.connect_button.remove_css_class("destructive-action")
        elif state == "blocked":
            self.status_title.set_label("Setup problem")
            self.status_subtitle.set_label(detail or "The app cannot safely continue.")
            self.connect_button.set_label("Unavailable")
            self.connect_button.set_sensitive(False)
            self.connect_button.remove_css_class("destructive-action")

        if state == "connected":
            self.connect_button.add_css_class("destructive-action")
            self.connect_button.remove_css_class("suggested-action")
        else:
            self.connect_button.add_css_class("suggested-action")
            self.connect_button.remove_css_class("destructive-action")

        controls_enabled = (
            state not in _ACTIVE_STATES
            and state not in {"loading", "blocked"}
            and not self._killswitch_armed
        )
        self._update_controls()
        self._refresh_connection_details()
        self._refresh_tray()

    def _update_controls(self):
        state = self._state
        controls_enabled = (
            state not in _ACTIVE_STATES
            and state not in {"loading", "blocked"}
            and not self._killswitch_armed
        )
        self.location_button.set_sensitive(controls_enabled)
        self.protocol_switch.set_sensitive(controls_enabled)
        self.account_button.set_sensitive(state not in _ACTIVE_STATES)

    def _set_connected(self):
        was_reconnecting = self._reconnect_in_flight
        self._reset_reconnect_state()
        if self._state != "connected":
            self._vpn_exit_ip = ""
            self._connected_since = time.monotonic()
            self._set_state("connected")
            self._start_timer()
            location = self._selected_location()
            where = (
                f"{location.display_city}, {location.display_country}"
                if location is not None
                else "the selected server"
            )
            if was_reconnecting:
                self._show_banner("VPN reconnected automatically.")
                self._notify_if_background(
                    "VPN reconnected",
                    f"Connected to {where} over {self.settings.protocol.upper()}.",
                )
            elif self._warning:
                self._show_banner(f"Profile imported with notes: {self._warning}")
            else:
                self._notify_if_background(
                    "VPN connected",
                    f"Connected to {where} over {self.settings.protocol.upper()}.",
                )
        self._start_poll()

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
        return True

    def _refresh_idle_subtitle(self):
        location = self._selected_location()
        if location is None:
            self.status_subtitle.set_label("Choose a location to begin.")
            return
        prefix = f"{location.flag} " if location.flag else ""
        self.status_subtitle.set_label(
            f"{prefix}{location.display_city}, {location.display_country} · "
            f"{self.settings.protocol.upper()}"
        )

    def _refresh_connected_subtitle(self):
        location = self._selected_location()
        elapsed = 0
        if self._connected_since is not None:
            elapsed = int(time.monotonic() - self._connected_since)
        minutes, seconds = divmod(elapsed, 60)
        hours, minutes = divmod(minutes, 60)
        duration = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        where = (
            f"{location.flag} {location.display_city}, {location.display_country}"
            if location is not None
            else "VPN"
        )
        self.status_subtitle.set_label(
            f"{where} · {self.settings.protocol.upper()} · connected {duration}"
        )

    # ------------------------------------------------------------- reconnect

    def _reconnect_problem(self) -> str | None:
        if self._quitting:
            return "the application is shutting down"
        if self.client is None:
            return "NetworkManager is unavailable"
        if self.agent is None or not self.agent.registered:
            return "the secret agent is not registered"
        connection = self._existing_connection
        if connection is None:
            return "the managed profile is missing"
        ref = self._selected_ref()
        if ref is None:
            return "the selected location or protocol is no longer available"
        try:
            verify_managed_profile(connection, ref.profile, certificate_dir())
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
            self._show_banner("The VPN connection ended.")
            self._notify_if_background("VPN disconnected", "The VPN connection ended.")
            return
        if not self.settings.auto_reconnect:
            self._intent_connected = False
            self._set_state("idle")
            self._show_banner("The VPN connection ended. Automatic reconnect is off.")
            self._notify_if_background(
                "VPN disconnected", "The VPN connection ended; automatic reconnect is off."
            )
            return

        problem = self._reconnect_problem()
        if problem is not None:
            self._intent_connected = False
            message = (
                "The VPN connection ended and cannot be safely reconnected: "
                f"{problem}. Press Try Again to rebuild it."
            )
            self._set_state("error", message)
            self._show_banner(message)
            self._notify_if_background("VPN reconnection stopped", message)
            return

        self._reconnect_attempt = 0
        self._reconnect_reason = reason
        self._show_banner("The VPN connection was lost. Reconnecting automatically…")
        self._notify_if_background(
            "VPN connection lost", "Reconnecting automatically in a few seconds."
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
            message = f"Automatic reconnection stopped: {problem}."
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
            self._activate(connection, reconnecting=True)
            return False
        self._update_reconnect_subtitle()
        return True

    def _update_reconnect_subtitle(self):
        remaining = 1
        if self._reconnect_deadline is not None:
            remaining = max(1, math.ceil(self._reconnect_deadline - time.monotonic()))
        self.status_subtitle.set_label(
            f"Connection lost. Retrying in {remaining}s "
            f"(attempt {self._reconnect_attempt} of {_RECONNECT.max_attempts})."
        )

    def _cancel_reconnect(self, message: str = ""):
        self._intent_connected = False
        self._reset_reconnect_state()
        self._set_state("idle")
        if message:
            self._show_banner(message)

    def _give_up(self, reason: str):
        self._intent_connected = False
        self._reset_reconnect_state()
        message = (
            "The VPN connection was lost and automatic reconnection stopped "
            f"after {_RECONNECT.max_attempts} attempts: {reason}"
        )
        self._set_state("error", message)
        self._show_banner(message)
        self._notify_if_background("Automatic reconnection stopped", message)

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
                self._connection_lost("The VPN connection ended.")
                return False
            if self._state == "connecting":
                if self._connect_deadline is None:
                    self._connect_deadline = time.monotonic() + 90
                if time.monotonic() > self._connect_deadline:
                    self._poll_source = None
                    if self._reconnect_in_flight:
                        self._reconnect_in_flight = False
                        self._schedule_next_reconnect("The connection attempt timed out.")
                    else:
                        self._fail("The connection attempt timed out.")
                    return False
            return True
        self.active = active
        state = vpn_state_name(active)
        if state == "activated":
            self._set_connected()
        elif state == "failed":
            self._poll_source = None
            reason = f"The VPN connection failed: {vpn_state_reason(active)}"
            if self._reconnect_in_flight:
                self._reconnect_in_flight = False
                self._schedule_next_reconnect(reason)
            else:
                self._fail(reason)
            return False
        elif state in {"disconnected", "deactivated"}:
            self._poll_source = None
            self._connection_lost("NetworkManager reports the tunnel is gone.")
            return False
        elif state == "need-auth":
            self.status_subtitle.set_label("Waiting for the secret agent to supply credentials…")
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
        if self._killswitch_armed:
            self._show_banner(
                "Disarm the kill switch before changing location or protocol."
            )
            return
        if self.catalogue is None:
            self._show_banner("The location list is not loaded yet.")
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
        if self._killswitch_armed:
            self._show_banner(
                "Disarm the kill switch before changing location or protocol."
            )
            return
        self._select_location(location, save=True)
        self._update_location_row()

    def _show_protocol_help(self):
        dialog = Adw.MessageDialog.new(
            self,
            "TCP vs UDP",
            "Both choices carry the same encrypted OpenVPN tunnel, with the same "
            "certificate checks and authentication. Neither is more private or more secure.\n\n"
            "UDP sends packets without a connection handshake or retransmission. That "
            "usually means lower overhead and lower latency, which is why it is the "
            "default for VPNs, games, and calls.\n\n"
            "TCP adds ordered delivery and retransmission. Use it when a network blocks "
            "UDP or only lets TCP through. Because OpenVPN over TCP carries TCP inside "
            "TCP, packet loss can cause duplicate retransmissions and stalls, so it is "
            "often slower and less responsive on unstable connections.\n\n"
            "Practical rule: use UDP first. Switch to TCP only if UDP cannot connect or "
            "is unstable because the local network filters it.",
        )
        dialog.add_response("close", "Close")
        dialog.set_close_response("close")
        dialog.set_default_response("close")
        dialog.set_transient_for(self)
        dialog.present()

    def _show_about(self):
        dialog = Adw.AboutDialog()
        dialog.set_application_name(APP_NAME)
        dialog.set_application_icon(APP_ID)
        dialog.set_version(VERSION)
        dialog.set_developer_name(DEVELOPER_NAME)
        dialog.set_website(HOMEPAGE_URL)
        dialog.set_issue_url(ISSUES_URL)
        dialog.set_comments(
            f"{APP_TAGLINE} It manages an existing FastVPN (OpenVPN) subscription "
            "through NetworkManager and its OpenVPN plugin. The application never "
            "runs as root; NetworkManager performs privileged network operations, "
            "and the optional kill switch is a separate system service.\n\n"
            f"{DISCLAIMER}"
        )
        dialog.set_copyright("© 2026 Solvetus Labs")
        dialog.set_developers([DEVELOPER_NAME])
        dialog.set_license_type(Gtk.License.APACHE_2_0)
        dialog.present(self)

    def _show_banner(self, text: str):
        self.banner.set_title(text)
        self.banner.set_revealed(True)

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

    def _on_close_request(self, *_args):
        if self._quitting or self._allow_close:
            return False
        if self._state == "reconnecting" or (
            self._state == "connecting" and self._reconnect_in_flight
        ):
            dialog = Adw.MessageDialog.new(
                self,
                "VPN is reconnecting",
                "The tunnel is currently down and the app is waiting to retry. "
                "Closing this window hides it and keeps retrying in the background. "
                "Quit stops automatic reconnection.",
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("hide", "Keep Retrying")
            dialog.add_response("quit", "Quit")
            dialog.set_close_response("cancel")
            dialog.set_default_response("hide")
            dialog.set_response_appearance("quit", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_transient_for(self)

            def response(_dialog, response_id):
                if response_id == "hide":
                    self.hide()
                    self._send_notification(
                        "VPN is reconnecting",
                        f"{APP_NAME} is still retrying in the background. "
                        "Open it from the app menu to see the status.",
                    )
                elif response_id == "quit":
                    if self._killswitch_armed:
                        self._request_quit_with_killswitch()
                    else:
                        self._quit_now()
                dialog.destroy()

            dialog.connect("response", response)
            dialog.present()
            return True
        if self._state in {"preparing", "connecting", "disconnecting"}:
            self._show_banner("Wait for the current connection operation to finish.")
            return True
        if self._killswitch_armed:
            dialog = Adw.MessageDialog.new(
                self,
                "Kill switch is armed",
                "Closing hides the window and keeps the app and firewall rules "
                "running. Quitting can disarm first, or leave protection active; "
                "while armed, traffic outside the VPN stays blocked. If the VPN is "
                "not connected, normal internet access remains blocked.",
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("hide", "Hide Window")
            dialog.add_response("disarm_quit", "Disarm and Quit")
            dialog.add_response("keep_quit", "Quit and Keep Protection")
            dialog.set_close_response("cancel")
            dialog.set_default_response("hide")
            dialog.set_response_appearance(
                "keep_quit", Adw.ResponseAppearance.DESTRUCTIVE
            )
            dialog.set_transient_for(self)

            def response(_dialog, response_id):
                if response_id == "hide":
                    self.hide()
                    self._send_notification(
                        "Kill switch is armed",
                        f"{APP_NAME} is running in the background with "
                        "firewall protection active.",
                    )
                elif response_id == "disarm_quit":
                    self._disarm_and_quit()
                elif response_id == "keep_quit":
                    self._quit_now()
                dialog.destroy()

            dialog.connect("response", response)
            dialog.present()
            return True
        if self.active is None:
            self._quitting = True
            return False

        dialog = Adw.MessageDialog.new(
            self,
            "VPN is still connected",
            "Closing this window hides it and leaves the app process running so it "
            f"can answer reauthentication requests. Open {APP_NAME} "
            "again from the app menu to show the window. If the process exits, the tunnel "
            "may stay up without the secret agent.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("hide", "Keep VPN Connected")
        dialog.add_response("quit", "Disconnect and Quit")
        dialog.set_close_response("cancel")
        dialog.set_default_response("hide")
        dialog.set_response_appearance("quit", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_transient_for(self)

        def response(_dialog, response_id):
            if response_id == "hide":
                self.hide()
                self._send_notification(
                    "VPN is still connected",
                    f"{APP_NAME} is running in the background. "
                    "Open it from the app menu to disconnect or quit.",
                )
            elif response_id == "quit":
                self._quit_after_disconnect = True
                self._disconnect()
            dialog.destroy()

        dialog.connect("response", response)
        dialog.present()
        return True

    def _request_quit(self, disconnect: bool | None):
        if self._state == "reconnecting" or (
            self._state == "connecting" and self._reconnect_in_flight
        ):
            dialog = Adw.MessageDialog.new(
                self,
                "Quit while reconnecting?",
                "Automatic reconnection will stop if the app exits. The VPN is not "
                "connected at this moment.",
            )
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("quit", "Quit")
            dialog.set_close_response("cancel")
            dialog.set_default_response("cancel")
            dialog.set_response_appearance("quit", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_transient_for(self)

            def response(_dialog, response_id):
                if response_id == "quit":
                    if self._killswitch_armed:
                        self._request_quit_with_killswitch()
                    else:
                        self._quit_now()
                dialog.destroy()

            dialog.connect("response", response)
            dialog.present()
            return
        if self._state in {"preparing", "connecting", "disconnecting"}:
            self._show_banner("Wait for the current connection operation to finish.")
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
        dialog = Adw.MessageDialog.new(
            self,
            "Quit while connected?",
            "The tunnel can stay up after the app exits, but the secret agent will also "
            "exit. If the VPN asks for credentials again, reauthentication cannot succeed "
            "until you reopen the app. Quit and disconnect if you want a clean stop.",
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("leave", "Quit and Leave Connected")
        dialog.add_response("disconnect", "Disconnect and Quit")
        dialog.set_close_response("cancel")
        dialog.set_default_response("cancel")
        dialog.set_response_appearance("disconnect", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_transient_for(self)

        def response(_dialog, response_id):
            if response_id == "disconnect":
                self._quit_after_disconnect = True
                self._disconnect()
            elif response_id == "leave":
                self._quit_now()
            dialog.destroy()

        dialog.connect("response", response)
        dialog.present()

    def _request_quit_with_killswitch(self):
        connected = self.active is not None or self._state == "connected"
        detail = (
            " The VPN is connected; quitting can leave the tunnel up."
            if connected
            else " The VPN is not connected; normal internet access remains blocked."
        )
        dialog = Adw.MessageDialog.new(
            self,
            "Quit with the kill switch armed?",
            "The system firewall rules will stay active if you quit without "
            "disarming. That keeps traffic blocked outside the VPN, but you may "
            "need the pervius-killswitch CLI to disarm later."
            + detail,
        )
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("disarm_quit", "Disarm and Quit")
        dialog.add_response("keep_quit", "Quit and Keep Protection")
        dialog.set_close_response("cancel")
        dialog.set_default_response("cancel")
        dialog.set_response_appearance(
            "keep_quit", Adw.ResponseAppearance.DESTRUCTIVE
        )
        dialog.set_transient_for(self)

        def response(_dialog, response_id):
            if response_id == "disarm_quit":
                self._disarm_and_quit()
            elif response_id == "keep_quit":
                self._quit_now()
            dialog.destroy()

        dialog.connect("response", response)
        dialog.present()

    def _disarm_and_quit(self):
        if self._killswitch_busy:
            self._show_banner("A kill-switch operation is already in progress.")
            return
        self._killswitch_busy = True
        self._killswitch_pending = "disarm_quit"
        self._render_killswitch_state()
        self._refresh_tray()
        self._show_banner("Disarming the kill switch before quitting…")
        call_async(self.killswitch.disarm, self._on_disarm_for_quit)

    def _on_disarm_for_quit(self, status, error):
        self._killswitch_pending = ""
        self._killswitch_busy = False
        if self._disposed:
            return
        if error is not None:
            self._show_banner(f"Could not disarm the kill switch: {error}")
            self._refresh_killswitch_status()
            return
        self._killswitch_status = status
        self._killswitch_armed = bool(status.get("armed", False))
        self._render_killswitch_state()
        self._quit_now()

    def _quit_now(self):
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
        self.destroy()
        if self.get_application() is not None:
            self.get_application().quit()

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
