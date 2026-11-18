"""Unprivileged client for the optional Solvetus kill-switch service."""

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


class KillSwitchError(RuntimeError):
    pass


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
                30000,
                None,
            )
        except GLib.Error as exc:
            raise KillSwitchError(exc.message) from exc
        try:
            return dict(reply.unpack()[0])
        except (IndexError, TypeError, ValueError) as exc:
            raise KillSwitchError("kill-switch service returned a malformed reply") from exc

    def status(self) -> dict:
        return self._call("GetStatus", GLib.Variant("()", ()))

    def arm(self, allow_lan: bool) -> dict:
        return self._call(
            "Arm",
            GLib.Variant("(sb)", (MANAGED_UUID, bool(allow_lan))),
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

    thread = threading.Thread(target=worker, name="solvetus-killswitch", daemon=True)
    thread.start()
    return thread
