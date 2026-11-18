"""Resolve the provider's server names without blocking the UI.

The managed profile is always pinned to IP addresses, so OpenVPN never needs
DNS to (re)connect while the leak guard or the kill switch blocks DNS
outside the tunnel.  Without the kill switch the app resolves the names
itself, before connecting, with the system resolver (GLib, asynchronous).
"""

from __future__ import annotations

import ipaddress
from typing import Callable, Iterable

import gi

gi.require_version("Gio", "2.0")
from gi.repository import Gio, GLib  # noqa: E402

from .killswitchd.rules import Endpoint, RulesError  # noqa: E402

RESOLVE_TIMEOUT = 10


def resolve_endpoints_async(
    remotes: Iterable[tuple[str, int]],
    protocol: str,
    callback: Callable[[tuple[Endpoint, ...], list[str]], None],
    *,
    resolver: Gio.Resolver | None = None,
    timeout: int = RESOLVE_TIMEOUT,
) -> None:
    """Resolve every ``(host, port)``; ``callback(endpoints, warnings)`` once, on the main loop."""
    remotes = list(remotes)
    resolver = resolver or Gio.Resolver.get_default()
    cancellable = Gio.Cancellable()
    endpoints: list[Endpoint] = []
    warnings: list[str] = []
    state = {"pending": 0, "done": False}

    def finish():
        if state["done"]:
            return
        state["done"] = True
        GLib.source_remove(timer) if state.get("timer_live") else None
        unique: list[Endpoint] = []
        for endpoint in endpoints:
            if endpoint not in unique:
                unique.append(endpoint)
        callback(tuple(unique), warnings)

    def add(address: str, port: int, host: str):
        try:
            endpoints.append(Endpoint(address, port, protocol))
        except RulesError as exc:
            warnings.append(f"{host}: {exc}")

    def expire():
        state["timer_live"] = False
        if not state["done"]:
            cancellable.cancel()
            warnings.append("name resolution timed out")
            finish()
        return False

    timer = GLib.timeout_add_seconds(timeout, expire)
    state["timer_live"] = True

    for host, port in remotes:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            add(host, port, host)
            continue
        state["pending"] += 1

        def done(source, result, _data=None, host=host, port=port):
            try:
                for address in source.lookup_by_name_finish(result):
                    add(address.to_string(), port, host)
            except GLib.Error as exc:
                if not state["done"]:
                    warnings.append(f"{host}: {exc.message}")
            state["pending"] -= 1
            if state["pending"] == 0:
                finish()

        resolver.lookup_by_name_async(host, cancellable, done, None)

    if state["pending"] == 0:
        GLib.idle_add(lambda: finish() and False)
