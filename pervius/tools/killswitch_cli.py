"""Small CLI for the Pervius kill-switch service.

This tool is unprivileged; polkit authorizes the request and the system service
applies the rules.  It is intended for diagnostics and recovery, not as a
replacement for the GUI.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys

import gi

gi.require_version("GLib", "2.0")
gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from ..config import MANAGED_UUID  # noqa: E402
from ..killswitchd.daemon import (  # noqa: E402
    BUS_NAME,
    INTERFACE,
    OBJECT_PATH,
    STATE_DIR,
)


class CliError(RuntimeError):
    pass


def _bus() -> Gio.DBusConnection:
    try:
        connection = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
    except GLib.Error as exc:
        raise CliError(f"could not connect to the system bus: {exc.message}") from exc
    if connection is None:
        raise CliError("could not connect to the system bus")
    return connection


def _call(method: str, parameters: GLib.Variant, reply_type: str) -> dict:
    connection = _bus()
    try:
        reply = connection.call_sync(
            BUS_NAME,
            OBJECT_PATH,
            INTERFACE,
            method,
            parameters,
            GLib.VariantType(reply_type),
            Gio.DBusCallFlags.NONE,
            30000,
            None,
        )
    except GLib.Error as exc:
        raise CliError(exc.message) from exc
    return reply.unpack()[0]


def _print_status(status: dict):
    print(json.dumps(status, indent=2, sort_keys=True, default=str))


def _service_available() -> bool:
    connection = _bus()
    try:
        reply = connection.call_sync(
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "NameHasOwner",
            GLib.Variant("(s)", (BUS_NAME,)),
            GLib.VariantType("(b)"),
            Gio.DBusCallFlags.NONE,
            3000,
            None,
        )
        return bool(reply.unpack()[0])
    except GLib.Error:
        return False


def command_status(_args) -> int:
    _print_status(_call("GetStatus", GLib.Variant("()", ()), "(a{sv})"))
    return 0


def command_arm(args) -> int:
    status = _call(
        "Arm",
        GLib.Variant("(sb)", (MANAGED_UUID, bool(args.allow_lan))),
        "(a{sv})",
    )
    _print_status(status)
    return 0


def command_disarm(_args) -> int:
    status = _call("Disarm", GLib.Variant("()", ()), "(a{sv})")
    _print_status(status)
    return 0


def command_diagnose(_args) -> int:
    nft = shutil.which("nft")
    print("user:", os.getuid())
    print("nft:", nft or "missing")
    if nft:
        try:
            result = subprocess.run(
                [nft, "--version"],
                text=True,
                capture_output=True,
                timeout=5,
                check=False,
            )
            version = (result.stdout or result.stderr).strip()
        except Exception:
            version = "unknown"
        print("nft version:", version or "unknown")
    print("service installed/active:", _service_available())
    print("reserved profile UUID:", MANAGED_UUID)
    print("state directory:", STATE_DIR)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pervius-killswitch",
        description="Control or inspect the Pervius kill-switch service",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show the service state")
    arm = sub.add_parser("arm", help="install kill-switch rules for the managed profile")
    arm.add_argument(
        "--allow-lan",
        action="store_true",
        help="also allow RFC1918/ULA local-network traffic",
    )
    sub.add_parser("disarm", help="remove the kill-switch rules")
    sub.add_parser("diagnose", help="read-only environment checks")
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            return command_status(args)
        if args.command == "arm":
            return command_arm(args)
        if args.command == "disarm":
            return command_disarm(args)
        if args.command == "diagnose":
            return command_diagnose(args)
    except CliError as exc:
        print(f"pervius-killswitch: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
