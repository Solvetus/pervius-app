from __future__ import annotations

import socket
import unittest

from pervius.killswitchd.profile import ProfileError, endpoints_from_profile_data


def resolver(*addresses):
    def resolve(host, port, family, socktype):
        records = []
        for address in addresses:
            family_value = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (
                (address, port, 0, 0)
                if family_value == socket.AF_INET6
                else (address, port)
            )
            records.append((family_value, socktype, 0, "", sockaddr))
        return records

    return resolve


VALID = {
    "remote": "vpn.example:1194",
    "proto-tcp": "no",
    "port": "1194",
}


class ProfileValidationTests(unittest.TestCase):
    def test_valid_profile(self):
        result = endpoints_from_profile_data(
            VALID, ["user:tester:"], "tester", resolver=resolver("192.0.2.10")
        )
        self.assertEqual(result.endpoints[0].address, "192.0.2.10")

    def test_tcp_profile_and_default_port(self):
        result = endpoints_from_profile_data(
            {"remote": "vpn.example", "proto-tcp": "yes"},
            ["user:tester"],
            "tester",
            resolver=resolver("192.0.2.10"),
        )
        self.assertEqual(result.endpoints[0].protocol, "tcp")
        self.assertEqual(result.endpoints[0].port, 1194)

    def test_permissions_must_be_exactly_one_local_user(self):
        for permissions in (
            None,
            [],
            ["user:tester:", "user:other:"],
            ["group:tester:"],
            ["user:other:"],
            ["user:tester:detail"],
        ):
            with self.assertRaisesRegex(ProfileError, "restricted"):
                endpoints_from_profile_data(
                    VALID, permissions, "tester", resolver=resolver("192.0.2.10")
                )

    def test_password_in_data_is_rejected(self):
        data = dict(VALID)
        data["password"] = "secret"
        with self.assertRaisesRegex(ProfileError, "password"):
            endpoints_from_profile_data(
                data, ["user:tester:"], "tester", resolver=resolver("192.0.2.10")
            )

    def test_bad_port_is_rejected(self):
        data = dict(VALID)
        data["port"] = "99999"
        with self.assertRaisesRegex(ProfileError, "port"):
            endpoints_from_profile_data(
                data, ["user:tester:"], "tester", resolver=resolver("192.0.2.10")
            )

    def test_missing_remote_is_rejected(self):
        with self.assertRaisesRegex(ProfileError, "remote"):
            endpoints_from_profile_data(
                {}, ["user:tester:"], "tester", resolver=resolver("192.0.2.10")
            )




class PinnedProfileTests(unittest.TestCase):
    def test_pinned_addresses_are_used_as_they_are(self):
        from pervius.killswitchd.profile import remotes_from_profile_data

        pinned = dict(VALID, remote="192.0.2.10:1194, [2001:db8::1]:1194")
        remotes, protocol = remotes_from_profile_data(pinned, ["user:tester:"], "tester")
        self.assertEqual(remotes, (("192.0.2.10", 1194), ("2001:db8::1", 1194)))
        self.assertEqual(protocol, "udp")

    def test_ownership_is_still_required(self):
        from pervius.killswitchd.profile import remotes_from_profile_data

        with self.assertRaises(ProfileError):
            remotes_from_profile_data(VALID, ["user:other:"], "tester")


if __name__ == "__main__":
    unittest.main()
