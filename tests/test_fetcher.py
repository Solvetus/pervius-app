from __future__ import annotations

import types
import unittest
from unittest.mock import patch

from gi.repository import GLib

from pervius.catalogue import fetcher
from pervius.catalogue.fetcher import FetchError, fetch_bytes


class FakeProps:
    timeout = 0
    user_agent = ""


class FakeBody:
    def __init__(self, data: bytes):
        self._data = data

    def get_data(self):
        return self._data


class FakeSession:
    def __init__(self, body: bytes, status: int = 200):
        self.props = FakeProps()
        self._body = body
        self._status = status

    def send_and_read(self, _message, _cancellable):
        return FakeBody(self._body)


class FakeHeaders:
    def __init__(self):
        self.appended = []

    def append(self, name, value):
        self.appended.append((name, value))


class FakeMessage:
    """Mimics the real libsoup 3 API.

    In particular it exposes headers only through ``get_request_headers()``.
    The previous fake provided a ``request_headers`` attribute that real
    libsoup does not have, which hid a runtime failure from the test suite.
    """

    def __init__(self, status: int = 200):
        self._headers = FakeHeaders()
        self._status = status

    def get_request_headers(self):
        return self._headers

    def get_status(self):
        return self._status

    def get_reason_phrase(self):
        return "OK" if self._status == 200 else "Failure"


def fake_soup(status: int = 200):
    class Message:
        @staticmethod
        def new(_method, _url):
            return FakeMessage(status)

    return types.SimpleNamespace(Message=Message, Status=types.SimpleNamespace(OK=200))


class FetcherTests(unittest.TestCase):
    def test_real_libsoup_message_header_api(self):
        # Contract check against the installed libsoup: the fetcher must use an
        # accessor that actually exists at runtime.
        message = fetcher.Soup.Message.new("GET", "https://example.com/catalogue.zip")
        headers = message.get_request_headers()
        self.assertIsNotNone(headers)
        headers.append("Accept", "application/zip")

    def test_non_https_rejected(self):
        with self.assertRaisesRegex(FetchError, "non-HTTPS"):
            fetch_bytes("http://example.com/catalogue.zip")

    def test_invalid_timeout_rejected(self):
        with self.assertRaisesRegex(FetchError, "invalid timeout"):
            fetch_bytes("https://example.com/catalogue.zip", timeout=0)

    def test_successful_fetch(self):
        with patch.object(fetcher, "Soup", fake_soup()):
            data = fetch_bytes(
                "https://example.com/catalogue.zip", session_factory=lambda: FakeSession(b"zipdata")
            )
        self.assertEqual(data, b"zipdata")

    def test_http_error_rejected(self):
        with patch.object(fetcher, "Soup", fake_soup(status=404)):
            with self.assertRaisesRegex(FetchError, "HTTP 404"):
                fetch_bytes(
                    "https://example.com/catalogue.zip",
                    session_factory=lambda: FakeSession(b"missing", status=404),
                )

    def test_empty_body_rejected(self):
        with patch.object(fetcher, "Soup", fake_soup()):
            with self.assertRaisesRegex(FetchError, "empty body"):
                fetch_bytes(
                    "https://example.com/catalogue.zip",
                    session_factory=lambda: FakeSession(b""),
                )

    def test_oversized_body_rejected(self):
        with patch.object(fetcher, "Soup", fake_soup()):
            with self.assertRaisesRegex(FetchError, "exceeds"):
                fetch_bytes(
                    "https://example.com/catalogue.zip",
                    session_factory=lambda: FakeSession(b"x" * 11),
                    max_bytes=10,
                )

    def test_transport_error_is_wrapped(self):
        class BrokenSession:
            props = FakeProps()

            def send_and_read(self, _message, _cancellable):
                raise GLib.Error("connection refused")

        with patch.object(fetcher, "Soup", fake_soup()):
            with self.assertRaisesRegex(FetchError, "download failed"):
                fetch_bytes(
                    "https://example.com/catalogue.zip", session_factory=lambda: BrokenSession()
                )


if __name__ == "__main__":
    unittest.main()
