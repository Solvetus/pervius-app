"""Validate the app-owned NetworkManager profile before arming firewall rules."""

from __future__ import annotations

from typing import Callable, Iterable, Mapping

from .rules import DEFAULT_OPENVPN_PORT, Resolution, RulesError, parse_remote_list, resolve_remotes


class ProfileError(RulesError):
    pass


def permissions_restricted_to_user(permissions: Iterable[str] | None, username: str) -> bool:
    if not username or permissions is None:
        return False
    items = list(permissions)
    if len(items) != 1:
        return False
    parts = items[0].split(":", 2)
    if len(parts) < 2:
        return False
    ptype, pitem = parts[0], parts[1]
    detail = parts[2] if len(parts) == 3 else ""
    return ptype == "user" and pitem == username and detail == ""


def _default_port(data: Mapping[str, str]) -> int:
    raw = data.get("port")
    if raw in (None, ""):
        return DEFAULT_OPENVPN_PORT
    try:
        port = int(str(raw), 10)
    except (TypeError, ValueError) as exc:
        raise ProfileError(f"invalid profile port: {raw!r}") from exc
    if not (1 <= port <= 65535):
        raise ProfileError(f"invalid profile port: {raw!r}")
    return port


def remotes_from_profile_data(
    data: Mapping[str, str],
    permissions: Iterable[str] | None,
    local_username: str,
) -> tuple[tuple[tuple[str, int], ...], str]:
    """Validate ownership and return the profile's ``(host, port)`` remotes and protocol.

    The remotes are host names right after an import, or the IP addresses
    the app pinned; the app writes the names back before asking for a new
    resolution.
    """
    if not permissions_restricted_to_user(permissions, local_username):
        raise ProfileError("profile is not restricted to the current local user")
    if not isinstance(data, Mapping):
        raise ProfileError("profile data is malformed")
    if data.get("password") is not None:
        raise ProfileError("profile contains a password in non-secret data")
    remote = data.get("remote")
    if not isinstance(remote, str):
        raise ProfileError("profile has no remote servers")
    protocol = "tcp" if data.get("proto-tcp") == "yes" else "udp"
    port = _default_port(data)
    return parse_remote_list(remote, port), protocol


def endpoints_from_profile_data(
    data: Mapping[str, str],
    permissions: Iterable[str] | None,
    local_username: str,
    *,
    resolver: Callable[[str, int, int, int], Iterable] | None = None,
) -> Resolution:
    """Validate ownership and turn the profile remotes into IP endpoints."""
    remotes, protocol = remotes_from_profile_data(data, permissions, local_username)
    return resolve_remotes(
        ", ".join(_format_remote(host, port) for host, port in remotes),
        protocol,
        resolver=resolver,
    )


def _format_remote(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
