from __future__ import annotations

import types
import unittest
from unittest.mock import patch

from gi.repository import GLib

from solvetus import public_ip
from solvetus.public_ip import PublicIPError, fetch_public_ip


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
    def append(self, _name, _value):
        pass


class FakeMessage:
    def __init__(self, status: int = 200):
        self._headers = FakeHeaders()
        self._status = status

    def get_request_headers(self):
        return self._headers

    def get_status(self):
        return self._status


def fake_soup(status: int = 200):
    class Message:
        @staticmethod
        def new(_method, _url):
            return FakeMessage(status)

    return types.SimpleNamespace(Message=Message, Status=types.SimpleNamespace(OK=200))


class PublicIPTests(unittest.TestCase):
    def test_valid_ipv4(self):
        with patch.object(public_ip, "Soup", fake_soup()):
            value = fetch_public_ip(
                "https://example.test/ip",
                session_factory=lambda: FakeSession(b'{"ip":"203.0.113.9"}'),
            )
        self.assertEqual(value, "203.0.113.9")

    def test_valid_ipv6(self):
        with patch.object(public_ip, "Soup", fake_soup()):
            value = fetch_public_ip(
                "https://example.test/ip",
                session_factory=lambda: FakeSession(b'{"ip":"2001:db8::1"}'),
            )
        self.assertEqual(value, "2001:db8::1")

    def test_non_https_rejected(self):
        with self.assertRaisesRegex(PublicIPError, "non-HTTPS"):
            fetch_public_ip("http://example.test/ip")

    def test_invalid_json_rejected(self):
        with patch.object(public_ip, "Soup", fake_soup()):
            with self.assertRaisesRegex(PublicIPError, "not valid JSON"):
                fetch_public_ip(
                    "https://example.test/ip",
                    session_factory=lambda: FakeSession(b"{broken"),
                )

    def test_invalid_address_rejected(self):
        with patch.object(public_ip, "Soup", fake_soup()):
            with self.assertRaisesRegex(PublicIPError, "invalid address"):
                fetch_public_ip(
                    "https://example.test/ip",
                    session_factory=lambda: FakeSession(b'{"ip":"not-an-ip"}'),
                )

    def test_http_error_rejected(self):
        with patch.object(public_ip, "Soup", fake_soup(status=500)):
            with self.assertRaisesRegex(PublicIPError, "HTTP 500"):
                fetch_public_ip(
                    "https://example.test/ip",
                    session_factory=lambda: FakeSession(b"error", status=500),
                )

    def test_oversized_response_rejected(self):
        with patch.object(public_ip, "Soup", fake_soup()):
            with self.assertRaisesRegex(PublicIPError, "too large"):
                fetch_public_ip(
                    "https://example.test/ip",
                    session_factory=lambda: FakeSession(b"x" * 9000),
                )


if __name__ == "__main__":
    unittest.main()
