"""Validate the app-owned NetworkManager profile before arming firewall rules."""

from __future__ import annotations

from typing import Callable, Iterable, Mapping

from .rules import DEFAULT_OPENVPN_PORT, Resolution, RulesError, resolve_remotes


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


def endpoints_from_profile_data(
    data: Mapping[str, str],
    permissions: Iterable[str] | None,
    local_username: str,
    *,
    resolver: Callable[[str, int, int, int], Iterable] | None = None,
) -> Resolution:
    """Validate ownership and turn the profile remote field into IP endpoints."""
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
    return resolve_remotes(remote, protocol, port, resolver=resolver)
