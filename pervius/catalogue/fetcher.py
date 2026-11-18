"""HTTPS catalogue fetcher using libsoup 3.

TLS verification is never disabled.  Redirects are never followed
(``NO_REDIRECT``; a 3xx answer is an error), so only the configured endpoint
is used.  The body is read as a stream and the download stops as soon as it
exceeds the size cap, so a hostile server cannot make the app buffer more.
"""

from __future__ import annotations

from typing import Callable

import gi

gi.require_version("Soup", "3.0")
from gi.repository import GLib, Soup  # noqa: E402

from ..config import MAX_ARCHIVE_BYTES, USER_AGENT  # noqa: E402

CHUNK_BYTES = 64 * 1024


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
    message.add_flags(Soup.MessageFlags.NO_REDIRECT)

    try:
        stream = session.send(message, None)
    except GLib.Error as exc:
        raise FetchError(f"catalogue download failed: {exc.message}") from exc
    except Exception as exc:
        raise FetchError(f"catalogue download failed: {exc}") from exc
    if stream is None:
        raise FetchError("catalogue server returned an empty body")

    try:
        status = message.get_status()
        if status != Soup.Status.OK:
            phrase = _status_phrase(message)
            raise FetchError(f"catalogue server returned HTTP {int(status)} {phrase}".strip())
        data = _read_capped(stream, max_bytes)
    finally:
        try:
            stream.close(None)
        except Exception:
            pass

    if not data:
        raise FetchError("catalogue server returned an empty body")
    return data


def _read_capped(stream, max_bytes: int) -> bytes:
    """Read the whole stream, stopping as soon as it exceeds ``max_bytes``."""
    parts: list[bytes] = []
    total = 0
    while True:
        try:
            chunk = stream.read_bytes(min(CHUNK_BYTES, max_bytes + 1 - total), None)
        except GLib.Error as exc:
            raise FetchError(f"catalogue download failed: {exc.message}") from exc
        data = bytes(chunk.get_data() or b"") if chunk is not None else b""
        if not data:
            break
        total += len(data)
        if total > max_bytes:
            raise FetchError(f"catalogue response exceeds {max_bytes} bytes")
        parts.append(data)
    return b"".join(parts)


def fetch_catalogue() -> bytes:
    from ..config import CATALOGUE_URL

    return fetch_bytes(CATALOGUE_URL)
