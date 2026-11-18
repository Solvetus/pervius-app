"""Pure kill-switch rule generation and remote endpoint parsing.

This module is deliberately free of root-only operations so it can be unit
tested as an ordinary user.  The daemon is the only caller that applies the
generated rules.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable

TABLE_NAME = "pervius_ks"
TABLE_SPEC = f"inet {TABLE_NAME}"
DEFAULT_OPENVPN_PORT = 1194
MAX_ENDPOINTS = 256

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


def build_ruleset(endpoints: Iterable[Endpoint], *, allow_lan: bool = False) -> str:
    """Build the dedicated nftables table.

    The table is independent of any firewall front end (see ``pervius.distro``).
    It only ever adds or deletes its own table; it never flushes the global
    ruleset.
    """
    unique = sorted(
        {(endpoint.address, endpoint.port, endpoint.protocol) for endpoint in endpoints},
        key=lambda item: (ipaddress.ip_address(item[0]).version, item[0], item[1], item[2]),
    )
    if not unique:
        raise RulesError("refusing to build an empty kill-switch allowlist")

    lines = [
        f"table {TABLE_SPEC} {{",
        "  chain output {",
        "    type filter hook output priority -10; policy accept;",
        '    oifname "lo" accept',
        '    oifname "tun*" accept',
        "    meta nfproto ipv4 udp sport 68 udp dport 67 accept",
        "    meta nfproto ipv6 udp sport 546 udp dport 547 accept",
        "    meta nfproto ipv6 icmpv6 type { 133, 134, 135, 136 } accept",
    ]
    for address, port, protocol in unique:
        family = ipaddress.ip_address(address).version
        prefix = "ip daddr" if family == 4 else "ip6 daddr"
        lines.append(f"    {prefix} {address} {protocol} dport {port} accept")
    if allow_lan:
        lines.append(f"    ip daddr {{ {', '.join(_LAN_V4)} }} accept")
        lines.append(f"    ip6 daddr {{ {', '.join(_LAN_V6)} }} accept")
    lines.extend(
        [
            "    meta nfproto ipv4 drop",
            "    meta nfproto ipv6 drop",
            "  }",
            "  chain forward {",
            "    type filter hook forward priority -10; policy drop;",
            "  }",
            "}",
        ]
    )
    return "\n".join(lines) + "\n"


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
