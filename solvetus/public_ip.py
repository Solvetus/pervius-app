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
