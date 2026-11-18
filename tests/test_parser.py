from __future__ import annotations

import hashlib
import unittest

from pervius.catalogue.parser import ProfileError, parse_profile

from .fixtures import CA_PEM, profile_text


class ParserTests(unittest.TestCase):
    def test_valid_profile(self):
        parsed = parse_profile(profile_text().encode(), "test.ovpn")
        self.assertEqual(parsed.protocol, "udp")
        self.assertEqual(parsed.remotes, (("vpn.example.com", 1194),))
        self.assertEqual(parsed.verify_x509_name, "name-prefix:example")
        self.assertEqual(parsed.auth, "SHA256")
        self.assertEqual(parsed.data_ciphers, "AES-256-GCM:AES-256-CBC")
        self.assertEqual(parsed.data_ciphers_fallback, "AES-256-CBC")
        self.assertIn("remote-random", parsed.low_risk_directives)
        self.assertEqual(parsed.ca_sha256, hashlib.sha256((CA_PEM).encode()).hexdigest())

    def test_tcp_profile(self):
        parsed = parse_profile(profile_text(protocol="tcp").encode(), "test.ovpn")
        self.assertEqual(parsed.protocol, "tcp")
        self.assertEqual(parsed.remotes[0][1], 443)

    def test_unknown_directive_rejected(self):
        text = profile_text() + "something-new value\n"
        with self.assertRaisesRegex(ProfileError, "unsupported directive 'something-new'"):
            parse_profile(text.encode(), "test.ovpn")

    def test_external_hook_rejected(self):
        text = profile_text() + "up /bin/sh\n"
        with self.assertRaisesRegex(ProfileError, "'up' rejected"):
            parse_profile(text.encode(), "test.ovpn")

    def test_auth_user_pass_file_rejected(self):
        text = profile_text().replace("auth-user-pass\n", "auth-user-pass /tmp/pass\n")
        with self.assertRaises(ProfileError):
            parse_profile(text.encode(), "test.ovpn")

    def test_weak_auth_rejected(self):
        text = profile_text().replace("auth SHA256", "auth SHA1")
        with self.assertRaisesRegex(ProfileError, "only 'auth SHA256'"):
            parse_profile(text.encode(), "test.ovpn")

    def test_remote_cert_missing_rejected(self):
        text = profile_text().replace("remote-cert-tls server\n", "")
        with self.assertRaisesRegex(ProfileError, "missing required"):
            parse_profile(text.encode(), "test.ovpn")

    def test_duplicate_proto_rejected(self):
        text = profile_text().replace("proto udp\n", "proto udp\nproto tcp\n")
        with self.assertRaisesRegex(ProfileError, "duplicate 'proto'"):
            parse_profile(text.encode(), "test.ovpn")

    def test_external_ca_rejected(self):
        text = profile_text().replace("<ca>", "ca /tmp/ca.pem\n#")
        with self.assertRaises(ProfileError):
            parse_profile(text.encode(), "test.ovpn")

    def test_private_key_in_ca_rejected(self):
        text = profile_text().replace(
            "-----END CERTIFICATE-----", "-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----"
        )
        with self.assertRaisesRegex(ProfileError, "private key"):
            parse_profile(text.encode(), "test.ovpn")

    def test_inline_cert_rejected(self):
        text = profile_text() + "<cert>\nAAAA\n</cert>\n"
        with self.assertRaisesRegex(ProfileError, "unsupported inline block"):
            parse_profile(text.encode(), "test.ovpn")

    def test_tls_auth_rejected(self):
        text = profile_text() + "tls-auth ta.key 1\n"
        with self.assertRaisesRegex(ProfileError, "'tls-auth' rejected"):
            parse_profile(text.encode(), "test.ovpn")

    def test_one_argument_verify_x509_uses_the_default_subject_type(self):
        # tcp/NCVPN-PK-Islamabad-TCP.ovpn:38 once used this form; it is valid OpenVPN.
        text = profile_text().replace("verify-x509-name example name-prefix", "verify-x509-name example")
        self.assertEqual(parse_profile(text.encode(), "test.ovpn").verify_x509_name, "subject:example")
        quoted = profile_text().replace(
            "verify-x509-name example name-prefix", 'verify-x509-name "C=US, O=Example, CN=vpn"'
        )
        self.assertEqual(
            parse_profile(quoted.encode(), "test.ovpn").verify_x509_name, "subject:C=US, O=Example, CN=vpn"
        )

    def test_bad_verify_x509_forms_are_rejected(self):
        for replacement in (
            "verify-x509-name example something",
            "verify-x509-name example name extra",
            "verify-x509-name",
            'verify-x509-name "has space" name',
        ):
            text = profile_text().replace("verify-x509-name example name-prefix", replacement)
            with self.assertRaises(ProfileError, msg=replacement):
                parse_profile(text.encode(), "test.ovpn")

    def test_inline_comment_rejected(self):
        text = profile_text().replace("verb 3", "verb 3 # hidden")
        with self.assertRaisesRegex(ProfileError, "inline comments"):
            parse_profile(text.encode(), "test.ovpn")

    def test_oversized_profile_rejected(self):
        with self.assertRaisesRegex(ProfileError, "exceeds"):
            parse_profile(b"x" * (512 * 1024 + 1), "test.ovpn")


if __name__ == "__main__":
    unittest.main()
