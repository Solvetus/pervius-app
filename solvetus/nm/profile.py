"""Build the single reusable, app-owned NetworkManager profile."""

from __future__ import annotations

from dataclasses import dataclass

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

from ..config import (  # noqa: E402
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
)
from ..catalogue.models import ParsedProfile  # noqa: E402


class ProfileBuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class PreparedProfile:
    variant: GLib.Variant
    source_sha256: str
    ca_path: str
    ca_sha256: str
    warnings: tuple[str, ...]

    @property
    def has_warnings(self) -> bool:
        return bool(self.warnings)


def _setting(connection: NM.Connection, name: str):
    return connection.get_setting(name)


def build_managed_connection(
    imported: NM.Connection,
    *,
    local_username: str,
    vpn_username: str,
) -> NM.Connection:
    """Copy an imported profile into our reserved, user-restricted profile.

    ``local_username`` owns the NetworkManager profile.  ``vpn_username`` is
    the account name sent to the VPN server; the two are never interchangeable.
    """
    if not local_username:
        raise ProfileBuildError("a local username is required")
    if not vpn_username:
        raise ProfileBuildError("a VPN username is required")
    variant = imported.to_dbus(NM.ConnectionSerializationFlags.WITH_NON_SECRET)
    connection = NM.SimpleConnection.new_from_dbus(variant)
    if not isinstance(connection, NM.SimpleConnection):
        raise ProfileBuildError("could not clone the imported connection")

    s_con = connection.get_setting_connection()
    s_vpn = connection.get_setting_vpn()
    if not isinstance(s_con, NM.SettingConnection):
        raise ProfileBuildError("imported profile has no connection setting")
    if not isinstance(s_vpn, NM.SettingVpn):
        raise ProfileBuildError("imported profile has no VPN setting")
    if s_vpn.get_service_type() != OPENVPN_SERVICE_TYPE:
        raise ProfileBuildError("imported profile is not an OpenVPN connection")

    s_con.props.id = MANAGED_CONNECTION_ID
    s_con.props.uuid = MANAGED_UUID
    s_con.props.autoconnect = False
    while s_con.get_num_permissions():
        s_con.remove_permission(0)
    if not s_con.add_permission("user", local_username, None):
        raise ProfileBuildError("could not restrict the profile to the current user")

    s_vpn.props.user_name = vpn_username
    connection.clear_secrets()
    if not s_vpn.set_secret_flags("password", NM.SettingSecretFlags.AGENT_OWNED):
        raise ProfileBuildError("could not mark the password as agent-owned")
    if s_vpn.get_num_secrets() != 0:
        raise ProfileBuildError("imported profile still contains secrets")

    data = s_vpn.props.data
    if data.get("password"):
        raise ProfileBuildError("imported profile contains a password in non-secret data")
    if data.get("password-flags") not in (None, str(int(NM.SettingSecretFlags.AGENT_OWNED))):
        raise ProfileBuildError("imported profile has unexpected password secret flags")

    if not connection.verify():
        raise ProfileBuildError("the generated NetworkManager profile is not valid")
    return connection


def build_variant(connection: NM.Connection) -> GLib.Variant:
    variant = connection.to_dbus(NM.ConnectionSerializationFlags.WITH_NON_SECRET)
    # Defensive: inspect the serialized form rather than trusting a flag.
    text = variant.print_(False)
    if "password" in text and "password-flags" not in text:
        raise ProfileBuildError("refusing to serialize a profile with an unexpected password field")
    return variant


def low_risk_warnings(parsed: ParsedProfile, imported: NM.Connection) -> tuple[str, ...]:
    s_vpn = imported.get_setting_vpn()
    warnings: list[str] = []
    if not isinstance(s_vpn, NM.SettingVpn):
        return ("imported profile has no VPN settings",)
    data = s_vpn.props.data
    for directive in parsed.low_risk_directives:
        if directive == "remote-random":
            if data.get("remote-random") != "yes":
                warnings.append("remote-random was not represented in the NetworkManager profile")
        elif directive not in {
            "nobind",
            "persist-key",
            "persist-tun",
            "persist-remote-ip",
            "resolv-retry",
            "verb",
        }:
            warnings.append(f"low-risk directive '{directive}' is not represented")
        # nobind/persist/resolv-retry/verb are OpenVPN runtime details handled
        # by the plugin or intentionally irrelevant to NM; they are recorded
        # in the parser but not treated as failures.
    return tuple(warnings)
