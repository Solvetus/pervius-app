"""Unprivileged client for the Pervius kill-switch service."""

from __future__ import annotations

import threading
from typing import Callable, TypeVar

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from .config import MANAGED_UUID  # noqa: E402
from .killswitchd.daemon import BUS_NAME, INTERFACE, OBJECT_PATH  # noqa: E402

T = TypeVar("T")
# The service answers within NFT_TIMEOUT plus at most one DNS window (5 s).
CALL_TIMEOUT_MS = 15000


class KillSwitchError(RuntimeError):
    """A failed call.  ``code`` is the short D-Bus error name, for example
    "PermissionDenied", "NotAvailable", "NotArmed", "ResolveFailed" or "Failed";
    the GUI maps it to a translated message."""

    def __init__(self, message: str, code: str = "Failed"):
        super().__init__(message)
        self.code = code


class KillSwitchClient:
    def __init__(self):
        pass

    def _bus(self) -> Gio.DBusConnection:
        try:
            connection = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        except GLib.Error as exc:
            raise KillSwitchError(f"could not connect to the system bus: {exc.message}") from exc
        if connection is None:
            raise KillSwitchError("could not connect to the system bus")
        return connection

    def _call(self, method: str, parameters: GLib.Variant) -> dict:
        connection = self._bus()
        try:
            reply = connection.call_sync(
                BUS_NAME,
                OBJECT_PATH,
                INTERFACE,
                method,
                parameters,
                GLib.VariantType("(a{sv})"),
                Gio.DBusCallFlags.NONE,
                CALL_TIMEOUT_MS,
                None,
            )
        except GLib.Error as exc:
            remote = Gio.DBusError.get_remote_error(exc) or ""
            if remote.startswith(INTERFACE + "."):
                code = remote[len(INTERFACE) + 1 :]
            elif remote.startswith("org.freedesktop.DBus.Error.ServiceUnknown"):
                code = "NotAvailable"
            else:
                code = "Failed"
            if Gio.DBusError.is_remote_error(exc):
                Gio.DBusError.strip_remote_error(exc)
            raise KillSwitchError(exc.message, code) from exc
        try:
            return dict(reply.unpack()[0])
        except (IndexError, TypeError, ValueError) as exc:
            raise KillSwitchError("kill-switch service returned a malformed reply") from exc

    def status(self) -> dict:
        return self._call("GetStatus", GLib.Variant("()", ()))

    def arm(self, allow_lan: bool, interfaces: list[str] | tuple[str, ...] = ()) -> dict:
        """Arm; the reply's "resolved" holds the endpoints for pinning."""
        return self._call(
            "Arm",
            GLib.Variant("(sbas)", (MANAGED_UUID, bool(allow_lan), list(interfaces))),
        )

    def configure(self, allow_lan: bool, interfaces: list[str] | tuple[str, ...] = ()) -> dict:
        return self._call(
            "Configure",
            GLib.Variant("(bas)", (bool(allow_lan), list(interfaces))),
        )

    def update_endpoints(self, replace: bool) -> dict:
        """Re-resolve the profile's servers and swap the endpoint set atomically."""
        return self._call(
            "UpdateEndpoints",
            GLib.Variant("(sb)", (MANAGED_UUID, bool(replace))),
        )

    def disarm(self) -> dict:
        return self._call("Disarm", GLib.Variant("()", ()))


def call_async(
    function: Callable[[], T],
    callback: Callable[[T | None, Exception | None], None],
) -> threading.Thread:
    def worker():
        try:
            result = function()
        except Exception as exc:
            GLib.idle_add(lambda exc=exc: callback(None, exc))
        else:
            GLib.idle_add(lambda result=result: callback(result, None))

    thread = threading.Thread(target=worker, name="pervius-killswitch", daemon=True)
    thread.start()
    return thread
