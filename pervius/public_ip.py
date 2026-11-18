"""Fetch the current public IP address over HTTPS.

This is used only to display the ISP address while disconnected and the VPN
exit address while connected.  No identifiers are sent beyond the request
itself; the endpoint sees the same public address as any other HTTPS request.
"""

from __future__ import annotations

import ipaddress
import json
from typing import Callable

import gi

gi.require_version("Soup", "3.0")
from gi.repository import GLib, Soup  # noqa: E402

from .config import PUBLIC_IP_URL, USER_AGENT  # noqa: E402

MAX_RESPONSE_BYTES = 8192


class PublicIPError(RuntimeError):
    pass


def fetch_public_ip(
    url: str = PUBLIC_IP_URL,
    *,
    timeout: int = 6,
    session_factory: Callable[[], Soup.Session] = Soup.Session,
) -> str:
    if not url.startswith("https://"):
        raise PublicIPError("refusing a non-HTTPS public-IP endpoint")
    if timeout < 1 or timeout > 30:
        raise PublicIPError("invalid public-IP timeout")

    session = session_factory()
    try:
        session.props.timeout = timeout
        session.props.user_agent = USER_AGENT
    except Exception:
        pass

    message = Soup.Message.new("GET", url)
    if message is None:
        raise PublicIPError("could not construct the public-IP request")
    headers = message.get_request_headers()
    if headers is None:
        raise PublicIPError("could not prepare the public-IP request")
    headers.append("Accept", "application/json")
    headers.append("Cache-Control", "no-cache")

    try:
        body = session.send_and_read(message, None)
    except GLib.Error as exc:
        raise PublicIPError(f"public-IP request failed: {exc.message}") from exc
    except Exception as exc:
        raise PublicIPError(f"public-IP request failed: {exc}") from exc

    if message.get_status() != Soup.Status.OK:
        raise PublicIPError(f"public-IP server returned HTTP {int(message.get_status())}")
    if body is None:
        raise PublicIPError("public-IP server returned an empty body")
    data = bytes(body.get_data())
    if not data:
        raise PublicIPError("public-IP server returned an empty body")
    if len(data) > MAX_RESPONSE_BYTES:
        raise PublicIPError("public-IP response is too large")
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise PublicIPError("public-IP response is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise PublicIPError("public-IP response has an unexpected shape")
    value = payload.get("ip")
    if not isinstance(value, str):
        raise PublicIPError("public-IP response has no address")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise PublicIPError("public-IP response has an invalid address") from exc
    return str(address)


# ---------------------------------------------------------------- tunnel only

RESOLVE1 = ("org.freedesktop.resolve1", "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager")
# systemd-resolved flags: classic DNS only, and never append search domains
# (a search domain on another link, e.g. NetBird's, would route the query
# to that link's resolver).
SD_RESOLVED_DNS = 1 << 0
SD_RESOLVED_NO_SEARCH = 1 << 8


def resolve_on_interface(host: str, interface: str, *, timeout: int = 5) -> list[str]:
    """Resolve ``host`` only through the DNS servers of ``interface`` (systemd-resolved)."""
    import socket

    gi.require_version("Gio", "2.0")
    from gi.repository import Gio

    try:
        ifindex = socket.if_nametoindex(interface)
    except OSError as exc:
        raise PublicIPError(f"{interface} is not up") from exc
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        reply = bus.call_sync(
            *RESOLVE1,
            "ResolveHostname",
            GLib.Variant("(isit)", (ifindex, host, 0, SD_RESOLVED_DNS | SD_RESOLVED_NO_SEARCH)),
            GLib.VariantType("(a(iiay)st)"),
            Gio.DBusCallFlags.NONE,
            timeout * 1000,
            None,
        )
    except GLib.Error as exc:
        raise PublicIPError(f"could not resolve {host} through the tunnel: {exc.message}") from exc
    addresses = []
    for _ifindex, _family, raw in reply.unpack()[0]:
        try:
            addresses.append(str(ipaddress.ip_address(bytes(raw))))
        except ValueError:
            continue
    if not addresses:
        raise PublicIPError(f"{host} has no address")
    return addresses


def _parse_payload(data: bytes) -> str:
    if not data or len(data) > MAX_RESPONSE_BYTES:
        raise PublicIPError("public-IP response is empty or too large")
    try:
        payload = json.loads(data.decode("utf-8"))
        value = payload.get("ip") if isinstance(payload, dict) else None
        return str(ipaddress.ip_address(str(value).strip()))
    except (UnicodeDecodeError, ValueError, AttributeError) as exc:
        raise PublicIPError("public-IP response is not a valid address") from exc


def fetch_public_ip_through(
    interface: str,
    url: str = PUBLIC_IP_URL,
    *,
    timeout: int = 6,
    resolver: Callable[[str, str], list[str]] | None = None,
    connect: Callable | None = None,
) -> str:
    """The public IP as seen through ``interface`` (the VPN tunnel).

    The name is resolved only with that interface's DNS servers, never with
    the physical link's; if that is impossible the lookup fails instead of
    leaking.  The request itself follows the default route (the tunnel) and
    uses certificate-verified TLS for the endpoint's host name.
    """
    import socket
    import ssl
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise PublicIPError("refusing a non-HTTPS public-IP endpoint")
    host = parts.hostname
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    addresses = (resolver or (lambda h, i: resolve_on_interface(h, i, timeout=timeout)))(host, interface)
    context = ssl.create_default_context()
    opener = connect or (lambda address: socket.create_connection((address, 443), timeout=timeout))
    last_error: Exception | None = None
    for address in addresses[:4]:
        try:
            with opener(address) as raw, context.wrap_socket(raw, server_hostname=host) as tls:
                request = (
                    f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
                    "Accept: application/json\r\nConnection: close\r\n\r\n"
                )
                tls.sendall(request.encode("ascii"))
                response = b""
                while len(response) <= MAX_RESPONSE_BYTES * 2:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            continue
        head, _, body = response.partition(b"\r\n\r\n")
        status = head.split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[1] != b"200":
            raise PublicIPError("public-IP server returned an error")
        if b"transfer-encoding: chunked" in head.lower():
            body = _dechunk(body)
        return _parse_payload(body)
    raise PublicIPError(f"public-IP request failed: {last_error}")


def _dechunk(body: bytes) -> bytes:
    out = b""
    while body:
        size_line, _, rest = body.partition(b"\r\n")
        try:
            size = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2 :]
    return out
