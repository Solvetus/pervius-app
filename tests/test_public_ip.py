from __future__ import annotations

import types
import unittest
from unittest.mock import patch


from pervius import public_ip
from pervius.public_ip import PublicIPError, fetch_public_ip


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




class TunnelLookupTests(unittest.TestCase):
    """While connected, our own lookup resolves through the tunnel only."""

    def test_resolution_is_asked_for_the_tunnel_interface(self):
        from unittest import mock

        from pervius import public_ip

        asked = []

        def resolver(host, interface):
            asked.append((host, interface))
            raise public_ip.PublicIPError("tunnel DNS unavailable")

        with mock.patch("socket.getaddrinfo", side_effect=AssertionError("system resolver used")):
            with self.assertRaises(public_ip.PublicIPError):
                public_ip.fetch_public_ip_through("pervius0", resolver=resolver)
        self.assertEqual(asked, [("api64.ipify.org", "pervius0")])

    def test_resolved_query_disables_search_domains(self):
        from pervius import public_ip

        self.assertEqual(public_ip.SD_RESOLVED_NO_SEARCH, 256)
        self.assertEqual(public_ip.SD_RESOLVED_DNS, 1)

    def test_payload_parsing(self):
        from pervius import public_ip

        self.assertEqual(public_ip._parse_payload(b'{"ip": "198.51.100.7"}'), "198.51.100.7")
        for bad in (b"", b"{}", b'{"ip": "nope"}', b"x" * 9000):
            with self.assertRaises(public_ip.PublicIPError):
                public_ip._parse_payload(bad)
        self.assertEqual(public_ip._dechunk(b"10\r\n{\"ip\": \"1.2.3.4\"\r\n0\r\n\r\n"), b'{"ip": "1.2.3.4"')


if __name__ == "__main__":
    unittest.main()
