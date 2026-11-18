"""Standalone StatusNotifierItem self-test against the desktop's watcher.

Registers a test tray icon, checks its D-Bus properties and menu layout, and
exits.  Pass --interactive to keep it running so you can click it in the top
bar; clicks are printed to stdout.
"""

import sys
import threading

from harness import Checks, require_sandbox

require_sandbox()

import gi  # noqa: E402

gi.require_version("GLib", "2.0")
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from solvetus.ui.tray import MENU_INTERFACE, MENU_PATH, SNI_INTERFACE, SNI_PATH, MenuItem, TrayIcon  # noqa: E402

checks = Checks("tray_sni")


def menu():
    return (
        MenuItem(1, "Connect to:", enabled=False),
        MenuItem(2, "Connect — Lisbon, Portugal", action="toggle"),
        MenuItem(3, separator=True),
        MenuItem(4, "Notifications", toggle_state=1, action="notifications"),
        MenuItem(5, "Help", children=(MenuItem(51, "About", action="about"),)),
    )


tray = TrayIcon(
    app_id="org.example.TraySelfTest",
    title="Tray self-test",
    icon_name="network-vpn-symbolic",
    menu_provider=menu,
    tooltip_provider=lambda: ("Tray self-test", "Not connected"),
    action_handler=lambda action: print("CLICK", action, flush=True),
    activate_handler=lambda: print("CLICK activate", flush=True),
    secondary_handler=lambda: print("CLICK secondary", flush=True),
)
tray.register()
bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
name = tray._connection.get_unique_name()


def prop(interface, path, key):
    reply = bus.call_sync(name, path, "org.freedesktop.DBus.Properties", "Get",
                          GLib.Variant("(ss)", (interface, key)), GLib.VariantType("(v)"),
                          Gio.DBusCallFlags.NONE, 3000, None)
    return reply.unpack()[0]


def run_checks():
    # D-Bus calls to our own object must not block the thread that serves it.
    try:
        checks.equal("Id", prop(SNI_INTERFACE, SNI_PATH, "Id"), "org.example.TraySelfTest")
        checks.equal("Title", prop(SNI_INTERFACE, SNI_PATH, "Title"), "Tray self-test")
        checks.equal("Menu path", prop(SNI_INTERFACE, SNI_PATH, "Menu"), MENU_PATH)
        layout = bus.call_sync(name, MENU_PATH, MENU_INTERFACE, "GetLayout",
                               GLib.Variant("(iias)", (0, -1, [])), None,
                               Gio.DBusCallFlags.NONE, 3000, None).unpack()
        top = [child[1].get("label", "") for child in layout[1][2]]
        checks.equal("top-level labels", top,
                      ["Connect to:", "Connect — Lisbon, Portugal", "", "Notifications", "Help"])
    except Exception as exc:
        checks.failures.append(f"D-Bus check raised {exc}")
        print(f"FAIL D-Bus check raised {exc}", flush=True)
    if "--interactive" not in sys.argv:
        GLib.idle_add(loop.quit)


loop = GLib.MainLoop()
threading.Thread(target=run_checks, daemon=True).start()
if "--interactive" in sys.argv:
    print("Running; click the icon in the top bar. Ctrl+C to stop.", flush=True)
try:
    loop.run()
except KeyboardInterrupt:
    pass
tray.shutdown()
sys.exit(checks.exit_code())
