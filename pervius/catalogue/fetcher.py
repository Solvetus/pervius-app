"""HTTPS catalogue fetcher using libsoup 3.

TLS verification is never disabled.  Redirects are not followed silently by
this wrapper; the configured endpoint is used directly.  The response size is
capped after reading because libsoup's sync API buffers the body.
"""

from __future__ import annotations

from typing import Callable

import gi

gi.require_version("Soup", "3.0")
from gi.repository import GLib, Soup  # noqa: E402

from ..config import MAX_ARCHIVE_BYTES, USER_AGENT  # noqa: E402


class FetchError(RuntimeError):
    pass


def _status_phrase(message: Soup.Message) -> str:
    try:
        return message.get_reason_phrase() or ""
    except Exception:
        return ""


def fetch_bytes(
    url: str,
    *,
    timeout: int = 30,
    max_bytes: int = MAX_ARCHIVE_BYTES,
    session_factory: Callable[[], Soup.Session] = Soup.Session,
) -> bytes:
    if not url.startswith("https://"):
        raise FetchError("refusing non-HTTPS catalogue URL")
    if timeout < 1 or timeout > 120:
        raise FetchError("invalid timeout")

    session = session_factory()
    try:
        session.props.timeout = timeout
        session.props.user_agent = USER_AGENT
    except Exception:
        # Older libsoup builds may expose these differently; the request still
        # uses system TLS defaults.
        pass

    message = Soup.Message.new("GET", url)
    if message is None:
        raise FetchError("could not construct HTTP request")
    headers = message.get_request_headers()
    if headers is None:
        raise FetchError("could not prepare HTTP request headers")
    headers.append("Accept", "application/zip")

    try:
        body = session.send_and_read(message, None)
    except GLib.Error as exc:
        raise FetchError(f"catalogue download failed: {exc.message}") from exc
    except Exception as exc:
        raise FetchError(f"catalogue download failed: {exc}") from exc

    status = message.get_status()
    if status != Soup.Status.OK:
        phrase = _status_phrase(message)
        raise FetchError(f"catalogue server returned HTTP {int(status)} {phrase}".strip())

    if body is None:
        raise FetchError("catalogue server returned an empty body")
    data = bytes(body.get_data())
    if not data:
        raise FetchError("catalogue server returned an empty body")
    if len(data) > max_bytes:
        raise FetchError(f"catalogue response exceeds {max_bytes} bytes")
    return data


def fetch_catalogue() -> bytes:
    from ..config import CATALOGUE_URL

    return fetch_bytes(CATALOGUE_URL)
