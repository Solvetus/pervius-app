"""Build the single reusable, app-owned NetworkManager profile."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import gi

gi.require_version("NM", "1.0")
from gi.repository import GLib, NM  # noqa: E402

from ..config import (  # noqa: E402
    MANAGED_CONNECTION_ID,
    MANAGED_UUID,
    OPENVPN_SERVICE_TYPE,
    TUNNEL_INTERFACE,
    USER_DATA_ALLOWED_INTERFACES,
    USER_DATA_BLOCK_IPV6,
    USER_DATA_REMOTE_NAMES,
)

# Exclusive VPN DNS with NetworkManager: a negative priority excludes DNS
# servers of every other connection with a higher value, and the "~." routing
# domain makes the tunnel the default DNS route under systemd-resolved.
VPN_DNS_PRIORITY = -1
VPN_DNS_ROUTING_DOMAIN = "~."
from ..catalogue.models import ParsedProfile  # noqa: E402


class ProfileBuildError(RuntimeError):
    pass


@dataclass(frozen=True)
class GuardOptions:
    """Settings the root components read from the profile's user-data.

    The NetworkManager dispatcher hook (IPv6 guard) receives them as
    CONNECTION_USER_* environment variables and validates them itself.
    """

    block_ipv6: bool = True
    allowed_interfaces: tuple[str, ...] = field(default_factory=tuple)


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
    guard: GuardOptions | None = None,
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

    remote = data.get("remote")
    if not remote:
        raise ProfileBuildError("imported profile has no remote servers")
    apply_tunnel_settings(connection)
    sync_user_data(connection, guard or GuardOptions(), remote_names=remote)

    if not connection.verify():
        raise ProfileBuildError("the generated NetworkManager profile is not valid")
    return connection


def _ip_setting(connection: NM.Connection, family: int):
    setting = connection.get_setting_ip4_config() if family == 4 else connection.get_setting_ip6_config()
    if setting is None:
        setting = NM.SettingIP4Config.new() if family == 4 else NM.SettingIP6Config.new()
        setting.props.method = "auto"
        connection.add_setting(setting)
    return setting


def apply_tunnel_settings(connection: NM.Connection) -> None:
    """Pin the tunnel device name and route all DNS through the tunnel."""
    s_vpn = connection.get_setting_vpn()
    if not isinstance(s_vpn, NM.SettingVpn):
        raise ProfileBuildError("profile has no VPN setting")
    s_vpn.add_data_item("dev", TUNNEL_INTERFACE)
    s_vpn.add_data_item("dev-type", "tun")
    for family in (4, 6):
        setting = _ip_setting(connection, family)
        setting.props.dns_priority = VPN_DNS_PRIORITY
    s_ip4 = _ip_setting(connection, 4)
    if VPN_DNS_ROUTING_DOMAIN not in list(s_ip4.props.dns_search or []):
        s_ip4.add_dns_search(VPN_DNS_ROUTING_DOMAIN)


def tunnel_settings_problem(connection: NM.Connection) -> str | None:
    """Explain why a stored profile lacks the pinned device or exclusive DNS."""
    s_vpn = connection.get_setting_vpn()
    if not isinstance(s_vpn, NM.SettingVpn):
        return "profile has no VPN setting"
    if s_vpn.get_data_item("dev") != TUNNEL_INTERFACE or s_vpn.get_data_item("dev-type") != "tun":
        return "the tunnel device is not pinned"
    s_ip4 = connection.get_setting_ip4_config()
    s_ip6 = connection.get_setting_ip6_config()
    if s_ip4 is None or s_ip4.props.dns_priority != VPN_DNS_PRIORITY:
        return "VPN DNS is not exclusive"
    if s_ip6 is not None and s_ip6.props.dns_priority != VPN_DNS_PRIORITY:
        return "VPN DNS is not exclusive"
    if VPN_DNS_ROUTING_DOMAIN not in list(s_ip4.props.dns_search or []):
        return "the tunnel is not the default DNS route"
    return None


def _user_setting(connection: NM.Connection) -> NM.SettingUser:
    setting = connection.get_setting_by_name(NM.SETTING_USER_SETTING_NAME)
    if setting is None:
        setting = NM.SettingUser.new()
        connection.add_setting(setting)
    return setting


def user_data(connection: NM.Connection, key: str) -> str | None:
    setting = connection.get_setting_by_name(NM.SETTING_USER_SETTING_NAME)
    if setting is None:
        return None
    return setting.get_data(key)


def sync_user_data(
    connection: NM.Connection,
    guard: GuardOptions,
    *,
    remote_names: str | None = None,
) -> bool:
    """Write the guard options (and, once, the original server names).

    Returns True if anything changed.  The interface list is joined with
    commas; every consumer validates each name again.
    """
    setting = _user_setting(connection)
    wanted = {
        USER_DATA_BLOCK_IPV6: "yes" if guard.block_ipv6 else "no",
        USER_DATA_ALLOWED_INTERFACES: ",".join(guard.allowed_interfaces),
    }
    if remote_names is not None:
        wanted[USER_DATA_REMOTE_NAMES] = remote_names
    changed = False
    for key, value in wanted.items():
        current = setting.get_data(key)
        if value == "" and key == USER_DATA_ALLOWED_INTERFACES:
            if current is not None:
                setting.set_data(key, None)
                changed = True
            continue
        if current != value:
            setting.set_data(key, value)
            changed = True
    return changed


def guard_options_match(connection: NM.Connection, guard: GuardOptions) -> bool:
    return (
        user_data(connection, USER_DATA_BLOCK_IPV6) == ("yes" if guard.block_ipv6 else "no")
        and (user_data(connection, USER_DATA_ALLOWED_INTERFACES) or "")
        == ",".join(guard.allowed_interfaces)
    )


def format_remote(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def pinned_remote_value(endpoints) -> str:
    """The OpenVPN remote list for resolved endpoints (IP literals)."""
    values = []
    for endpoint in endpoints:
        ipaddress.ip_address(endpoint.address)  # defensive: literals only
        value = format_remote(endpoint.address, endpoint.port)
        if value not in values:
            values.append(value)
    if not values:
        raise ProfileBuildError("no resolved endpoints to pin")
    return ", ".join(values)


def is_pinned(connection: NM.Connection) -> bool:
    s_vpn = connection.get_setting_vpn()
    names = user_data(connection, USER_DATA_REMOTE_NAMES)
    return bool(isinstance(s_vpn, NM.SettingVpn) and names and s_vpn.get_data_item("remote") != names)


def clone(connection: NM.Connection) -> NM.SimpleConnection:
    copy = NM.SimpleConnection.new_clone(connection)
    if not isinstance(copy, NM.SimpleConnection):
        raise ProfileBuildError("could not copy the managed profile")
    return copy


def pin_remote(connection: NM.Connection, endpoints, protocol: str) -> NM.SimpleConnection:
    """A copy whose remote list holds the resolved IPs (kill switch armed).

    OpenVPN then needs no DNS while the tunnel is down.  The CA and
    verify-x509-name checks still decide whether a server is genuine.
    """
    copy = clone(connection)
    s_vpn = copy.get_setting_vpn()
    if not isinstance(s_vpn, NM.SettingVpn):
        raise ProfileBuildError("profile has no VPN setting")
    names = user_data(copy, USER_DATA_REMOTE_NAMES)
    if not names:
        raise ProfileBuildError("profile has no recorded server names")
    selected = [e for e in endpoints if e.protocol == protocol]
    s_vpn.add_data_item("remote", pinned_remote_value(selected))
    return copy


def unpin_remote(connection: NM.Connection) -> NM.SimpleConnection:
    """A copy whose remote list is the provider's server names again."""
    copy = clone(connection)
    s_vpn = copy.get_setting_vpn()
    names = user_data(copy, USER_DATA_REMOTE_NAMES)
    if not isinstance(s_vpn, NM.SettingVpn) or not names:
        raise ProfileBuildError("profile has no recorded server names")
    s_vpn.add_data_item("remote", names)
    return copy


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
