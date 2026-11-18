"""StatusNotifierItem tray icon with a DBusMenu.

Desktops with StatusNotifierItem support (for example GNOME with the
AppIndicator extension) expose a StatusNotifierWatcher, so no extra Python
package is needed.  The tray is a
secondary control surface: NetworkManager's own VPN indicator remains the
system source of truth.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

log = logging.getLogger(__name__)

SNI_PATH = "/StatusNotifierItem"
MENU_PATH = "/MenuBar"
SNI_INTERFACE = "org.kde.StatusNotifierItem"
MENU_INTERFACE = "com.canonical.dbusmenu"
WATCHER_NAME = "org.kde.StatusNotifierWatcher"
WATCHER_PATH = "/StatusNotifierWatcher"
WATCHER_INTERFACE = "org.kde.StatusNotifierWatcher"

_SNI_XML = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="i" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconPixmap" type="a(iiay)" access="read"/>
    <property name="OverlayIconName" type="s" access="read"/>
    <property name="OverlayIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionIconName" type="s" access="read"/>
    <property name="AttentionIconPixmap" type="a(iiay)" access="read"/>
    <property name="AttentionMovieName" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
    <method name="ContextMenu">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Activate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg name="x" type="i" direction="in"/>
      <arg name="y" type="i" direction="in"/>
    </method>
    <method name="Scroll">
      <arg name="delta" type="i" direction="in"/>
      <arg name="orientation" type="s" direction="in"/>
    </method>
    <signal name="NewTitle"/>
    <signal name="NewIcon"/>
    <signal name="NewAttentionIcon"/>
    <signal name="NewOverlayIcon"/>
    <signal name="NewToolTip"/>
    <signal name="NewStatus">
      <arg name="status" type="s"/>
    </signal>
  </interface>
</node>
"""

_MENU_XML = """
<node>
  <interface name="com.canonical.dbusmenu">
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
    <method name="GetLayout">
      <arg name="parentId" type="i" direction="in"/>
      <arg name="recursionDepth" type="i" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="revision" type="u" direction="out"/>
      <arg name="layout" type="(ia{sv}av)" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg name="ids" type="as" direction="in"/>
      <arg name="propertyNames" type="as" direction="in"/>
      <arg name="properties" type="a(ia{sv})" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg name="id" type="i" direction="in"/>
      <arg name="name" type="s" direction="in"/>
      <arg name="value" type="v" direction="out"/>
    </method>
    <method name="Event">
      <arg name="id" type="i" direction="in"/>
      <arg name="eventId" type="s" direction="in"/>
      <arg name="data" type="v" direction="in"/>
      <arg name="timestamp" type="u" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg name="events" type="a(isvu)" direction="in"/>
      <arg name="idErrors" type="as" direction="out"/>
    </method>
    <method name="AboutToShow">
      <arg name="id" type="i" direction="in"/>
      <arg name="needUpdate" type="b" direction="out"/>
    </method>
    <method name="AboutToShowGroup">
      <arg name="ids" type="as" direction="in"/>
      <arg name="updatesNeeded" type="as" direction="out"/>
      <arg name="idErrors" type="as" direction="out"/>
    </method>
    <signal name="ItemsPropertiesUpdated">
      <arg name="updatedProps" type="a(ia{sv})"/>
      <arg name="removedProps" type="a(as)"/>
    </signal>
    <signal name="LayoutUpdated">
      <arg name="revision" type="u"/>
      <arg name="parent" type="i"/>
    </signal>
    <signal name="ItemActivationRequested">
      <arg name="id" type="i"/>
      <arg name="timestamp" type="u"/>
    </signal>
  </interface>
</node>
"""


class TrayError(RuntimeError):
    pass


@dataclass(frozen=True)
class MenuItem:
    id: int
    label: str = ""
    enabled: bool = True
    visible: bool = True
    separator: bool = False
    toggle_state: int | None = None
    children: tuple["MenuItem", ...] = ()
    action: str = ""
    # Optional suffix used by GetLayout; short labels are easier to scan.
    icon_name: str = ""


def _empty_pixmaps() -> GLib.Variant:
    return GLib.Variant.new_array(GLib.VariantType("(iiay)"), [])


class TrayIcon:
    def __init__(
        self,
        *,
        app_id: str,
        title: str,
        icon_name: str,
        menu_provider: Callable[[], tuple[MenuItem, ...]],
        tooltip_provider: Callable[[], tuple[str, str]],
        action_handler: Callable[[str], None],
        activate_handler: Callable[[], None],
        secondary_handler: Callable[[], None],
        icon_provider: Callable[[], str] | None = None,
    ):
        self._app_id = app_id
        self._title = title
        self._icon_name = icon_name
        self._icon_provider = icon_provider
        self._last_icon = icon_name
        self._menu_provider = menu_provider
        self._tooltip_provider = tooltip_provider
        self._action_handler = action_handler
        self._activate_handler = activate_handler
        self._secondary_handler = secondary_handler
        self._connection: Gio.DBusConnection | None = None
        self._sni_registration: int | None = None
        self._menu_registration: int | None = None
        self._revision = 1
        self._registered = False
        self._nodes: dict[int, MenuItem] = {}

    @property
    def registered(self) -> bool:
        return self._registered

    def register(self) -> bool:
        if self._registered:
            return True
        try:
            self._connection = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        except GLib.Error as exc:
            raise TrayError(f"could not connect to the session bus: {exc.message}") from exc
        if self._connection is None:
            raise TrayError("could not connect to the session bus")

        sni_info = Gio.DBusNodeInfo.new_for_xml(_SNI_XML)
        menu_info = Gio.DBusNodeInfo.new_for_xml(_MENU_XML)
        try:
            self._sni_registration = self._connection.register_object(
                SNI_PATH,
                sni_info.interfaces[0],
                self._on_sni_method,
                self._on_sni_property,
                None,
            )
            self._menu_registration = self._connection.register_object(
                MENU_PATH,
                menu_info.interfaces[0],
                self._on_menu_method,
                self._on_menu_property,
                None,
            )
        except GLib.Error as exc:
            self.shutdown()
            raise TrayError(f"could not export tray objects: {exc.message}") from exc

        registered = self._register_with_watcher()
        if not registered:
            self.shutdown()
            raise TrayError("the StatusNotifierWatcher rejected the tray item")
        self._registered = True
        log.info("tray icon registered")
        return True

    def _register_with_watcher(self) -> bool:
        assert self._connection is not None
        unique = self._connection.get_unique_name()
        candidates = (SNI_PATH, unique) if unique else (SNI_PATH,)
        for candidate in candidates:
            try:
                self._connection.call_sync(
                    WATCHER_NAME,
                    WATCHER_PATH,
                    WATCHER_INTERFACE,
                    "RegisterStatusNotifierItem",
                    GLib.Variant("(s)", (candidate,)),
                    None,
                    Gio.DBusCallFlags.NONE,
                    5000,
                    None,
                )
            except GLib.Error as exc:
                log.warning("tray registration with %r failed: %s", candidate, exc.message)
                continue
            if self._watcher_recognizes(candidate):
                return True
            log.info("watcher did not list %r after registration; trying next form", candidate)
        return False

    def _watcher_recognizes(self, candidate: str) -> bool:
        assert self._connection is not None
        try:
            reply = self._connection.call_sync(
                WATCHER_NAME,
                WATCHER_PATH,
                "org.freedesktop.DBus.Properties",
                "Get",
                GLib.Variant("(ss)", (WATCHER_INTERFACE, "RegisteredStatusNotifierItems")),
                GLib.VariantType("(v)"),
                Gio.DBusCallFlags.NONE,
                2000,
                None,
            )
        except GLib.Error:
            return True
        try:
            items = reply.get_child_value(0).get_variant().unpack()
        except Exception:
            return True
        return candidate in items

    def shutdown(self) -> None:
        if self._connection is not None:
            for registration in (self._sni_registration, self._menu_registration):
                if registration is not None:
                    try:
                        self._connection.unregister_object(registration)
                    except Exception:
                        pass
        self._sni_registration = None
        self._menu_registration = None
        self._registered = False

    def refresh(self) -> None:
        self._revision += 1
        if not self._registered or self._connection is None:
            return
        try:
            icon = self._current_icon()
            if icon != self._last_icon:
                self._last_icon = icon
                self._connection.emit_signal(None, SNI_PATH, SNI_INTERFACE, "NewIcon", None)
            self._connection.emit_signal(
                None,
                MENU_PATH,
                MENU_INTERFACE,
                "LayoutUpdated",
                GLib.Variant("(ui)", (self._revision, 0)),
            )
            self._connection.emit_signal(None, SNI_PATH, SNI_INTERFACE, "NewToolTip", None)
        except GLib.Error as exc:
            log.warning("could not refresh tray: %s", exc.message)

    def update_item(self, item_id: int) -> None:
        """Push one item's properties (e.g. a ticking status line) without a relayout."""
        if not self._registered or self._connection is None:
            return
        self._rebuild_nodes()
        item = self._nodes.get(item_id)
        if item is None:
            return
        try:
            self._connection.emit_signal(
                None,
                MENU_PATH,
                MENU_INTERFACE,
                "ItemsPropertiesUpdated",
                GLib.Variant(
                    "(a(ia{sv})a(ias))",
                    ([(item_id, self._item_properties(item))], []),
                ),
            )
        except GLib.Error as exc:
            log.warning("could not update tray item: %s", exc.message)

    def _current_icon(self) -> str:
        if self._icon_provider is not None:
            try:
                return self._icon_provider()
            except Exception:
                log.exception("tray icon provider failed; using the default icon")
        return self._icon_name

    # ------------------------------------------------------------- SNI side

    def _on_sni_method(
        self,
        _connection,
        _sender,
        _path,
        _interface,
        method_name,
        _parameters,
        invocation,
    ):
        try:
            if method_name == "Activate":
                self._activate_handler()
            elif method_name == "SecondaryActivate":
                self._secondary_handler()
            # ContextMenu and Scroll are deliberately no-ops: the host owns
            # the menu and scroll does not have a useful action here.
        except Exception:
            log.exception("tray action failed")
        invocation.return_value(None)
        return None

    def _sni_tooltip(self) -> tuple[str, str]:
        try:
            return self._tooltip_provider()
        except Exception:
            return (self._title, "")

    def _on_sni_property(
        self,
        _connection,
        _sender,
        _path,
        interface_name,
        property_name,
    ):
        if interface_name != SNI_INTERFACE:
            return None
        if property_name == "Category":
            return GLib.Variant("s", "ApplicationStatus")
        if property_name == "Id":
            return GLib.Variant("s", self._app_id)
        if property_name == "Title":
            return GLib.Variant("s", self._title)
        if property_name == "Status":
            return GLib.Variant("s", "Active")
        if property_name == "WindowId":
            return GLib.Variant("i", 0)
        if property_name == "IconName":
            return GLib.Variant("s", self._current_icon())
        if property_name in {"IconPixmap", "OverlayIconPixmap", "AttentionIconPixmap"}:
            return _empty_pixmaps()
        if property_name in {
            "OverlayIconName",
            "AttentionIconName",
            "AttentionMovieName",
        }:
            return GLib.Variant("s", "")
        if property_name == "ToolTip":
            title, body = self._sni_tooltip()
            return GLib.Variant.new_tuple(
                GLib.Variant("s", self._current_icon()),
                _empty_pixmaps(),
                GLib.Variant("s", title),
                GLib.Variant("s", body),
            )
        if property_name == "ItemIsMenu":
            return GLib.Variant("b", True)
        if property_name == "Menu":
            return GLib.Variant("o", MENU_PATH)
        return None

    # ------------------------------------------------------------ menu side

    def _menu_root(self) -> MenuItem:
        try:
            children = self._menu_provider()
        except Exception:
            log.exception("could not build tray menu")
            children = ()
        return MenuItem(0, children=tuple(children))

    def _rebuild_nodes(self) -> MenuItem:
        root = self._menu_root()
        nodes: dict[int, MenuItem] = {}

        def visit(item: MenuItem) -> None:
            nodes[item.id] = item
            for child in item.children:
                visit(child)

        visit(root)
        self._nodes = nodes
        return root

    def _on_menu_property(
        self,
        _connection,
        _sender,
        _path,
        interface_name,
        property_name,
    ):
        if interface_name != MENU_INTERFACE:
            return None
        if property_name == "Version":
            return GLib.Variant("u", 3)
        if property_name == "TextDirection":
            return GLib.Variant("s", "ltr")
        if property_name == "Status":
            return GLib.Variant("s", "normal")
        if property_name == "IconThemePath":
            return GLib.Variant("as", [])
        return None

    @staticmethod
    def _item_properties(item: MenuItem) -> dict[str, GLib.Variant]:
        props: dict[str, GLib.Variant] = {
            "visible": GLib.Variant("b", item.visible),
        }
        if item.separator:
            props["type"] = GLib.Variant("s", "separator")
            return props
        props["label"] = GLib.Variant("s", item.label)
        props["enabled"] = GLib.Variant("b", item.enabled)
        props["type"] = GLib.Variant("s", "standard")
        if item.children:
            props["children-display"] = GLib.Variant("s", "submenu")
        if item.toggle_state is not None:
            props["toggle-type"] = GLib.Variant("s", "checkmark")
            props["toggle-state"] = GLib.Variant("i", int(item.toggle_state))
        if item.icon_name:
            props["icon-name"] = GLib.Variant("s", item.icon_name)
        return props

    def _item_variant(self, item: MenuItem, depth: int) -> GLib.Variant:
        children: list[GLib.Variant] = []
        if depth != 0:
            child_depth = -1 if depth < 0 else depth - 1
            for child in item.children:
                children.append(self._item_variant(child, child_depth))
        props = GLib.Variant("a{sv}", self._item_properties(item))
        return GLib.Variant.new_tuple(
            GLib.Variant("i", item.id),
            props,
            GLib.Variant("av", children),
        )

    def _on_menu_method(
        self,
        _connection,
        _sender,
        _path,
        _interface,
        method_name,
        parameters,
        invocation,
    ):
        try:
            if method_name == "GetLayout":
                parent_id, depth, _names = parameters.unpack()
                root = self._rebuild_nodes()
                parent = self._nodes.get(parent_id, root)
                layout = self._item_variant(parent, depth)
                invocation.return_value(
                    GLib.Variant.new_tuple(
                        GLib.Variant("u", self._revision),
                        layout,
                    )
                )
                return None

            if method_name == "GetGroupProperties":
                ids, _names = parameters.unpack()
                self._rebuild_nodes()
                items = []
                for item_id in ids:
                    item = self._nodes.get(item_id)
                    if item is not None:
                        items.append((item_id, self._item_properties(item)))
                invocation.return_value(GLib.Variant("(a(ia{sv}))", (items,)))
                return None

            if method_name == "GetProperty":
                item_id, name = parameters.unpack()
                self._rebuild_nodes()
                item = self._nodes.get(item_id)
                props = self._item_properties(item) if item is not None else {}
                value = props.get(name)
                if value is None:
                    invocation.return_dbus_error(
                        "com.canonical.dbusmenu.Error", "unknown menu property"
                    )
                    return None
                invocation.return_value(GLib.Variant("(v)", (value,)))
                return None

            if method_name == "Event":
                item_id, event_id, _data, _timestamp = parameters.unpack()
                self._dispatch_event(item_id, event_id)
                invocation.return_value(None)
                return None

            if method_name == "EventGroup":
                (events,) = parameters.unpack()
                for item_id, event_id, _data, _timestamp in events:
                    self._dispatch_event(int(item_id), str(event_id))
                invocation.return_value(GLib.Variant("(as)", ([],)))
                return None

            if method_name == "AboutToShow":
                invocation.return_value(GLib.Variant("(b)", (False,)))
                return None

            if method_name == "AboutToShowGroup":
                invocation.return_value(GLib.Variant("(asas)", ([], [])))
                return None

            invocation.return_dbus_error(
                "com.canonical.dbusmenu.Error", "unsupported menu method"
            )
        except Exception:
            log.exception("tray menu method %s failed", method_name)
            try:
                invocation.return_dbus_error(
                    "com.canonical.dbusmenu.Error", "menu operation failed"
                )
            except Exception:
                pass
        return None

    def _dispatch_event(self, item_id: int, event_id: str) -> None:
        if event_id not in {"clicked", "Activate"}:
            return
        self._rebuild_nodes()
        item = self._nodes.get(item_id)
        if item is None or not item.enabled or item.separator:
            return
        if item.action:
            try:
                self._action_handler(item.action)
            except Exception:
                log.exception("tray menu action %r failed", item.action)
