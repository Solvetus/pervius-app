"""Direct DNS lookups for the kill-switch service, built on dnspython.

While the kill switch is armed and the tunnel is down, DNS is blocked.  To
resolve VPN server names (a new location, or provider IP rotation before a
reconnect) the service opens a DNS window that admits only packets from its
own cgroup.  ``getaddrinfo`` would go through the local stub resolver and be
sent by *its* process instead, so the service queries the link's resolvers
itself, here.

The lookups are deliberately narrow: A and AAAA only, a random query ID
(dnspython) and a random ephemeral source port (bind to port 0), a strict
per-server and overall timeout, a reply size cap, and rejection of truncated,
malformed or mismatched replies.  No parsing is hand-written.  The addresses
only become kill-switch allowlist entries and pinned OpenVPN remotes; the
server's identity is still enforced by the CA and verify-x509-name checks.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from typing import Callable, Iterable

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype

from .rules import Endpoint, Resolution, RulesError

DNS_PORT = 53
MAX_REPLY_BYTES = 1232
PER_SERVER_TIMEOUT = 2.0
TOTAL_TIMEOUT = 5.0
QUERY_TYPES = (dns.rdatatype.A, dns.rdatatype.AAAA)


class DnsLookupError(RuntimeError):
    pass


class NoSuchName(DnsLookupError):
    pass


def _same_address(left: str, right: str) -> bool:
    try:
        return ipaddress.ip_address(left.split("%", 1)[0]) == ipaddress.ip_address(right.split("%", 1)[0])
    except ValueError:
        return False


def _addresses_from(reply: dns.message.Message, rdtype) -> list[str]:
    """Take the A/AAAA answer for the question, following CNAMEs inside the reply."""
    try:
        chain = reply.resolve_chaining()
    except dns.exception.DNSException as exc:
        raise DnsLookupError(f"unusable answer: {exc}") from exc
    answer = chain.answer
    if answer is None or answer.rdtype != rdtype:
        return []
    addresses = []
    for rdata in answer:
        address = getattr(rdata, "address", None)
        if isinstance(address, str):
            addresses.append(address)
    return addresses


def query(
    hostname: str,
    rdtype,
    nameservers: Iterable[str],
    *,
    deadline: float,
    socket_factory: Callable[..., socket.socket] = socket.socket,
    clock: Callable[[], float] = time.monotonic,
) -> list[str]:
    """Ask each resolver in turn for one record type; return the addresses.

    Raises NoSuchName on NXDOMAIN and DnsLookupError when no resolver gave a
    usable answer in time.
    """
    if rdtype not in QUERY_TYPES:
        raise DnsLookupError("only A and AAAA lookups are allowed")
    qname = dns.name.from_text(hostname)
    last_error = "no resolver answered"
    for server in nameservers:
        remaining = deadline - clock()
        if remaining <= 0:
            last_error = "timed out"
            break
        server_deadline = clock() + min(PER_SERVER_TIMEOUT, remaining)
        message = dns.message.make_query(qname, rdtype)  # random ID, RD set
        wire = message.to_wire()
        try:
            family = socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET
        except ValueError:
            continue
        sock = socket_factory(family, socket.SOCK_DGRAM)
        try:
            sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", 0))
            sock.sendto(wire, (server, DNS_PORT))
            while True:
                wait = server_deadline - clock()
                if wait <= 0:
                    last_error = "timed out"
                    break
                sock.settimeout(wait)
                try:
                    data, source = sock.recvfrom(MAX_REPLY_BYTES + 1)
                except (socket.timeout, TimeoutError):
                    last_error = "timed out"
                    break
                # Anything that is not exactly the reply to this query is
                # ignored, and the wait continues until the deadline.
                if not _same_address(str(source[0]), server) or source[1] != DNS_PORT:
                    continue
                if len(data) > MAX_REPLY_BYTES:
                    continue
                try:
                    reply = dns.message.from_wire(data)
                except dns.exception.DNSException:
                    continue
                if not message.is_response(reply):
                    continue
                if reply.flags & dns.flags.TC:
                    last_error = "truncated reply"
                    break
                code = reply.rcode()
                if code == dns.rcode.NXDOMAIN:
                    raise NoSuchName(f"{hostname} does not exist")
                if code != dns.rcode.NOERROR:
                    last_error = f"resolver returned {dns.rcode.to_text(code)}"
                    break
                return _addresses_from(reply, rdtype)
        except OSError as exc:
            last_error = f"could not query a resolver: {exc.strerror or exc}"
        finally:
            sock.close()
    raise DnsLookupError(last_error)


def resolve_remotes_direct(
    remotes: Iterable[tuple[str, int]],
    protocol: str,
    nameservers: Iterable[str],
    *,
    timeout: float = TOTAL_TIMEOUT,
    socket_factory: Callable[..., socket.socket] = socket.socket,
    clock: Callable[[], float] = time.monotonic,
) -> Resolution:
    """Resolve parsed ``(host, port)`` remotes into endpoints within ``timeout``."""
    servers = tuple(nameservers)
    if not servers:
        raise RulesError("no resolver is available for the DNS window")
    deadline = clock() + timeout
    endpoints: list[Endpoint] = []
    warnings: list[str] = []
    seen: set[tuple[str, int, str]] = set()

    def add(address: str, port: int, host: str) -> None:
        try:
            endpoint = Endpoint(address, port, protocol)
        except RulesError as exc:
            warnings.append(f"ignored resolved address for {host}: {exc}")
            return
        key = (endpoint.address, endpoint.port, endpoint.protocol)
        if key not in seen:
            seen.add(key)
            endpoints.append(endpoint)

    for host, port in remotes:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            add(host, port, host)
            continue
        for rdtype in QUERY_TYPES:
            try:
                for address in query(
                    host,
                    rdtype,
                    servers,
                    deadline=deadline,
                    socket_factory=socket_factory,
                    clock=clock,
                ):
                    add(address, port, host)
            except NoSuchName as exc:
                warnings.append(str(exc))
                break
            except (DnsLookupError, dns.exception.DNSException) as exc:
                warnings.append(f"could not resolve {host} ({dns.rdatatype.to_text(rdtype)}): {exc}")
    if not endpoints:
        raise RulesError("could not resolve any VPN server endpoint")
    return Resolution(tuple(endpoints), tuple(warnings))
