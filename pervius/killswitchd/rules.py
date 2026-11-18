"""Pure kill-switch rule generation and remote endpoint parsing.

This module is deliberately free of root-only operations so it can be unit
tested as an ordinary user.  The daemon is the only caller that applies the
generated rules.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable

from ..config import TUNNEL_INTERFACE

TABLE_NAME = "pervius_ks"
TABLE_SPEC = f"inet {TABLE_NAME}"
# The leak guard's table (DNS and IPv6 outside the tunnel while connected),
# owned by the NetworkManager dispatcher hook.
GUARD_TABLE_SPEC = "inet pervius_guard"
DEFAULT_OPENVPN_PORT = 1194
MAX_ENDPOINTS = 256
MAX_INTERFACES = 16
MAX_RESOLVERS = 8
MAX_CGROUP_DEPTH = 6
DNS_WINDOW_SECONDS = 5

_IFNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")
_CGROUP_COMPONENT = re.compile(r"[A-Za-z0-9_.@:-]{1,128}")

_LAN_V4 = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)
_LAN_V6 = ("fc00::/7", "fe80::/10")


class RulesError(RuntimeError):
    pass


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int
    protocol: str  # "udp" or "tcp"

    def __post_init__(self):
        try:
            ip = ipaddress.ip_address(self.address)
        except ValueError as exc:
            raise RulesError(f"invalid endpoint address: {self.address!r}") from exc
        if ip.is_unspecified or ip.is_multicast:
            raise RulesError(f"unusable endpoint address: {self.address!r}")
        if not isinstance(self.port, int) or not (1 <= self.port <= 65535):
            raise RulesError(f"invalid endpoint port: {self.port!r}")
        protocol = self.protocol.lower()
        if protocol not in {"udp", "tcp"}:
            raise RulesError(f"invalid endpoint protocol: {self.protocol!r}")
        object.__setattr__(self, "protocol", protocol)

    @property
    def family(self) -> int:
        return ipaddress.ip_address(self.address).version


@dataclass(frozen=True)
class Resolution:
    endpoints: tuple[Endpoint, ...]
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return bool(self.endpoints)


def parse_remote_list(remote_value: str, default_port: int = DEFAULT_OPENVPN_PORT) -> tuple[tuple[str, int], ...]:
    """Parse NetworkManager's comma-joined OpenVPN remote field safely.

    Accepts ``host:port``, bracketed IPv6 ``[addr]:port``, and a bare IPv6
    literal with the default port.  Hostnames are left for resolution; no
    shell or nft syntax is accepted into the rule text until it has become a
    validated IP address.
    """
    if not isinstance(remote_value, str) or not remote_value.strip():
        raise RulesError("profile has no remote servers")
    if not isinstance(default_port, int) or not (1 <= default_port <= 65535):
        raise RulesError("profile has an invalid default port")

    result: list[tuple[str, int]] = []
    for raw in remote_value.split(","):
        part = raw.strip()
        if not part:
            continue
        host: str
        port = default_port
        if part.startswith("["):
            close = part.find("]")
            if close < 0:
                raise RulesError(f"unterminated IPv6 remote: {part!r}")
            host = part[1:close]
            remainder = part[close + 1 :]
            if remainder:
                if not remainder.startswith(":"):
                    raise RulesError(f"invalid remote suffix: {part!r}")
                port = _parse_port(remainder[1:])
        elif part.count(":") == 1:
            host, port_text = part.rsplit(":", 1)
            port = _parse_port(port_text)
        else:
            # Bare IPv6 literal; colons are part of the address.
            host = part
        host = host.strip()
        if not host or len(host) > 253 or any(char.isspace() for char in host):
            raise RulesError(f"invalid remote host: {host!r}")
        if (host, port) not in result:
            result.append((host, port))
    if not result:
        raise RulesError("profile has no usable remote servers")
    if len(result) > 64:
        raise RulesError("profile has too many remote servers")
    return tuple(result)


def _parse_port(value: str) -> int:
    try:
        port = int(value, 10)
    except (TypeError, ValueError) as exc:
        raise RulesError(f"invalid remote port: {value!r}") from exc
    if not (1 <= port <= 65535):
        raise RulesError(f"invalid remote port: {value!r}")
    return port


def _default_resolver(host: str, port: int, family: int, socktype: int):
    return socket.getaddrinfo(host, port, family, socktype)


def resolve_remotes(
    remote_value: str,
    protocol: str,
    default_port: int = DEFAULT_OPENVPN_PORT,
    *,
    resolver: Callable[[str, int, int, int], Iterable] | None = None,
) -> Resolution:
    protocol = protocol.lower()
    if protocol not in {"udp", "tcp"}:
        raise RulesError(f"invalid protocol: {protocol!r}")
    remotes = parse_remote_list(remote_value, default_port)
    socktype = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    resolve = resolver or _default_resolver
    endpoints: list[Endpoint] = []
    warnings: list[str] = []
    seen: set[tuple[str, int, str]] = set()

    for host, port in remotes:
        try:
            records = resolve(host, port, socket.AF_UNSPEC, socktype)
        except OSError as exc:
            warnings.append(f"could not resolve {host}: {exc}")
            continue
        for record in records:
            try:
                address = record[4][0]
            except (IndexError, TypeError):
                continue
            try:
                endpoint = Endpoint(address, port, protocol)
            except RulesError as exc:
                warnings.append(f"ignored resolved address for {host}: {exc}")
                continue
            key = (endpoint.address, endpoint.port, endpoint.protocol)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(endpoint)
            if len(endpoints) > MAX_ENDPOINTS:
                raise RulesError("profile resolves to too many endpoints")

    if not endpoints:
        raise RulesError("could not resolve any VPN server endpoint")
    return Resolution(tuple(endpoints), tuple(warnings))


def validate_ifname(name) -> str:
    """Validate a Linux interface name strictly before it reaches rule text.

    Linux allows up to IFNAMSIZ-1 (15) bytes and forbids "/", ":" and
    whitespace; Pervius is stricter and accepts only a safe ASCII charset
    starting with a letter or digit, and never "." or "..".
    """
    if not isinstance(name, str) or not _IFNAME.fullmatch(name) or name in {".", ".."}:
        raise RulesError(f"invalid interface name: {name!r}")
    return name


def validate_interfaces(names: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for name in names:
        validated = validate_ifname(name)
        if validated not in result:
            result.append(validated)
    if len(result) > MAX_INTERFACES:
        raise RulesError(f"too many allowed interfaces (at most {MAX_INTERFACES})")
    return tuple(result)


def cgroup_match(path) -> str | None:
    """Return the nft expression matching sockets of one cgroup, or None.

    ``path`` is relative to the cgroup v2 root, as in ``/proc/self/cgroup``
    ("system.slice/pervius-killswitchd.service").  The match level is the
    path depth.  Anything that is not a plain, shallow path is refused, so
    no rule is generated rather than a wrong one.
    """
    if not isinstance(path, str):
        return None
    parts = path.strip("/").split("/")
    if not parts or len(parts) > MAX_CGROUP_DEPTH:
        return None
    for part in parts:
        if not _CGROUP_COMPONENT.fullmatch(part) or part in {".", ".."}:
            return None
    clean = "/".join(parts)
    return f'socket cgroupv2 level {len(parts)} "{clean}"'


def _unique_endpoints(endpoints: Iterable[Endpoint]) -> list[tuple[str, int, str]]:
    return sorted(
        {(endpoint.address, endpoint.port, endpoint.protocol) for endpoint in endpoints},
        key=lambda item: (ipaddress.ip_address(item[0]).version, item[0], item[1], item[2]),
    )


def _endpoint_elements(unique, family: int) -> list[str]:
    return [
        f"{address} . {protocol} . {port}"
        for address, port, protocol in unique
        if ipaddress.ip_address(address).version == family
    ]


def _set_lines(name: str, type_text: str, elements: list[str], flags: str = "") -> list[str]:
    lines = [f"  set {name} {{", f"    type {type_text};"]
    if flags:
        lines.append(f"    flags {flags};")
    if elements:
        lines.append(f"    elements = {{ {', '.join(elements)} }}")
    lines.append("  }")
    return lines


def build_ruleset(
    endpoints: Iterable[Endpoint],
    *,
    allow_lan: bool = False,
    interfaces: Iterable[str] = (),
    service_cgroup: str | None = None,
) -> str:
    """Build the whole kill-switch table as one atomic replacement.

    The script creates the table if needed, deletes it and defines it again
    in a single ``nft -f`` transaction, so there is never a moment without
    rules.  It only touches its own table; it never flushes the global
    ruleset (see ``pervius.distro`` for firewall front ends).

    Allowed output: loopback; the pinned tunnel and the user's extra
    interfaces (named set ``allowed_ifaces``); DHCP and IPv6 neighbour
    discovery; the VPN server endpoints (named sets, swapped atomically by
    ``build_endpoint_swap``); while a DNS window is open, plain DNS from the
    kill-switch service's own cgroup to the link's resolvers; optionally the
    LAN.  Everything else is dropped.
    """
    unique = _unique_endpoints(endpoints)
    if not unique:
        raise RulesError("refusing to build an empty kill-switch allowlist")
    allowed = (TUNNEL_INTERFACE, *[i for i in validate_interfaces(interfaces) if i != TUNNEL_INTERFACE])
    window = cgroup_match(service_cgroup) if service_cgroup is not None else None

    lines = [
        f"table {TABLE_SPEC} {{}}",
        f"delete table {TABLE_SPEC}",
        f"table {TABLE_SPEC} {{",
    ]
    lines += _set_lines("allowed_ifaces", "ifname", [f'"{name}"' for name in allowed])
    lines += _set_lines(
        "endpoints_v4", "ipv4_addr . inet_proto . inet_service", _endpoint_elements(unique, 4)
    )
    lines += _set_lines(
        "endpoints_v6", "ipv6_addr . inet_proto . inet_service", _endpoint_elements(unique, 6)
    )
    lines += _set_lines("dns_window_v4", "ipv4_addr", [], "timeout")
    lines += _set_lines("dns_window_v6", "ipv6_addr", [], "timeout")
    lines += [
        "  chain output {",
        "    type filter hook output priority -10; policy accept;",
        '    oifname "lo" accept',
        "    oifname @allowed_ifaces accept",
        "    meta nfproto ipv4 udp sport 68 udp dport 67 accept",
        "    meta nfproto ipv6 udp sport 546 udp dport 547 accept",
        "    meta nfproto ipv6 icmpv6 type { 133, 134, 135, 136 } accept",
        "    ip daddr . meta l4proto . th dport @endpoints_v4 accept",
        "    ip6 daddr . meta l4proto . th dport @endpoints_v6 accept",
    ]
    if window:
        lines.append(f"    {window} ip daddr @dns_window_v4 meta l4proto {{ udp, tcp }} th dport 53 accept")
        lines.append(f"    {window} ip6 daddr @dns_window_v6 meta l4proto {{ udp, tcp }} th dport 53 accept")
    # No DNS outside the tunnel, not even to the LAN's resolver when the LAN
    # is allowed: only loopback, the tunnel, allowed interfaces and the
    # service's own DNS window may carry it.
    lines.append("    meta l4proto { udp, tcp } th dport 53 drop")
    lines.append("    tcp dport 853 drop")
    if allow_lan:
        lines.append(f"    ip daddr {{ {', '.join(_LAN_V4)} }} accept")
        lines.append(f"    ip6 daddr {{ {', '.join(_LAN_V6)} }} accept")
    lines += [
        "    meta nfproto ipv4 drop",
        "    meta nfproto ipv6 drop",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority -10; policy drop;",
        "  }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def build_endpoint_swap(endpoints: Iterable[Endpoint]) -> str:
    """Replace both endpoint sets and close any DNS window, atomically."""
    unique = _unique_endpoints(endpoints)
    if not unique:
        raise RulesError("refusing to swap in an empty endpoint set")
    lines = []
    for family, name in ((4, "endpoints_v4"), (6, "endpoints_v6")):
        lines.append(f"flush set {TABLE_SPEC} {name}")
        elements = _endpoint_elements(unique, family)
        if elements:
            lines.append(f"add element {TABLE_SPEC} {name} {{ {', '.join(elements)} }}")
    lines += _window_close_lines()
    return "\n".join(lines) + "\n"


def _window_close_lines() -> list[str]:
    return [f"flush set {TABLE_SPEC} dns_window_v4", f"flush set {TABLE_SPEC} dns_window_v6"]


def build_dns_window_close() -> str:
    return "\n".join(_window_close_lines()) + "\n"


def resolver_addresses(values: Iterable[str]) -> tuple[str, ...]:
    """Validate resolver addresses for the DNS window (scope ids dropped)."""
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.split("%", 1)[0].strip()
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
            continue
        if str(ip) not in result:
            result.append(str(ip))
    return tuple(result[:MAX_RESOLVERS])


def build_dns_window(resolvers: Iterable[str], seconds: int = DNS_WINDOW_SECONDS) -> str:
    """Open the DNS window: resolver addresses that expire on their own.

    The kernel removes each element after ``seconds`` even if the service
    dies mid-lookup, so the window always closes.
    """
    if not isinstance(seconds, int) or not (1 <= seconds <= DNS_WINDOW_SECONDS):
        raise RulesError("invalid DNS window duration")
    addresses = resolver_addresses(resolvers)
    if not addresses:
        raise RulesError("no usable resolver for the DNS window")
    lines = []
    for family, name in ((4, "dns_window_v4"), (6, "dns_window_v6")):
        elements = [
            f"{address} timeout {seconds}s"
            for address in addresses
            if ipaddress.ip_address(address).version == family
        ]
        if elements:
            lines.append(f"add element {TABLE_SPEC} {name} {{ {', '.join(elements)} }}")
    return "\n".join(lines) + "\n"


def merge_endpoints(fresh, current) -> tuple[Endpoint, ...]:
    """Fresh endpoints first, then the current ones (kept for the live tunnel)."""
    merged: list[Endpoint] = []
    seen = set()
    for endpoint in (*fresh, *current):
        key = (endpoint.address, endpoint.port, endpoint.protocol)
        if key in seen:
            continue
        seen.add(key)
        merged.append(endpoint)
        if len(merged) >= MAX_ENDPOINTS:
            break
    return tuple(merged)


def endpoints_from_state(items: Iterable[dict]) -> tuple[Endpoint, ...]:
    endpoints = []
    for item in items:
        if not isinstance(item, dict):
            raise RulesError("malformed saved endpoint")
        endpoints.append(
            Endpoint(
                address=str(item.get("address", "")),
                port=int(item.get("port", 0)),
                protocol=str(item.get("protocol", "")),
            )
        )
    if not endpoints:
        raise RulesError("saved state has no endpoints")
    return tuple(endpoints)
