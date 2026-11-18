from __future__ import annotations

import socket
import unittest

from solvetus.killswitchd.rules import (
    Endpoint,
    RulesError,
    build_ruleset,
    endpoints_from_state,
    parse_remote_list,
    resolve_remotes,
)


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


class RemoteParsingTests(unittest.TestCase):
    def test_host_ports(self):
        self.assertEqual(
            parse_remote_list("vpn.example:1194, backup.example:443"),
            (("vpn.example", 1194), ("backup.example", 443)),
        )

    def test_default_port(self):
        self.assertEqual(parse_remote_list("vpn.example"), (("vpn.example", 1194),))

    def test_bracketed_and_bare_ipv6(self):
        self.assertEqual(
            parse_remote_list("[2001:db8::1]:443"),
            (("2001:db8::1", 443),),
        )
        self.assertEqual(
            parse_remote_list("2001:db8::2"),
            (("2001:db8::2", 1194),),
        )

    def test_invalid_values(self):
        for value in ("", "host:0", "host:70000", "host:abc", "host:1194, bad port:1194"):
            with self.assertRaises(RulesError):
                parse_remote_list(value)

    def test_duplicates_are_removed(self):
        self.assertEqual(
            parse_remote_list("vpn:1194, vpn:1194"),
            (("vpn", 1194),),
        )


class ResolutionTests(unittest.TestCase):
    def test_resolves_and_deduplicates(self):
        result = resolve_remotes(
            "vpn.example:1194",
            "udp",
            resolver=resolver("192.0.2.10", "192.0.2.10", "2001:db8::1"),
        )
        self.assertEqual(
            {(endpoint.address, endpoint.protocol) for endpoint in result.endpoints},
            {("192.0.2.10", "udp"), ("2001:db8::1", "udp")},
        )
        self.assertEqual(result.warnings, ())

    def test_partial_resolution_warns(self):
        def partial(host, port, family, socktype):
            if host == "bad.example":
                raise OSError("name not known")
            return resolver("192.0.2.10")(host, port, family, socktype)

        result = resolve_remotes("bad.example:1194, good.example:1194", "udp", resolver=partial)
        self.assertEqual(len(result.endpoints), 1)
        self.assertTrue(result.warnings)

    def test_no_resolution_is_an_error(self):
        def broken(host, port, family, socktype):
            raise OSError("name not known")

        with self.assertRaises(RulesError):
            resolve_remotes("vpn.example:1194", "udp", resolver=broken)

    def test_invalid_resolved_address_is_ignored(self):
        result = resolve_remotes(
            "vpn.example:1194",
            "tcp",
            resolver=resolver("not-an-ip", "192.0.2.10"),
        )
        self.assertEqual([endpoint.address for endpoint in result.endpoints], ["192.0.2.10"])
        self.assertTrue(result.warnings)


class RulesetTests(unittest.TestCase):
    def setUp(self):
        self.endpoints = (
            Endpoint("192.0.2.10", 1194, "udp"),
            Endpoint("2001:db8::1", 443, "tcp"),
        )

    def test_ruleset_has_isolated_table_and_drops(self):
        text = build_ruleset(self.endpoints)
        self.assertIn("table inet solvetus_ks {", text)
        self.assertIn('oifname "tun*" accept', text)
        self.assertIn("ip daddr 192.0.2.10 udp dport 1194 accept", text)
        self.assertIn("ip6 daddr 2001:db8::1 tcp dport 443 accept", text)
        self.assertIn("meta nfproto ipv4 drop", text)
        self.assertIn("meta nfproto ipv6 drop", text)
        self.assertIn("policy drop;", text)
        self.assertNotIn("flush ruleset", text)
        self.assertNotIn("ufw", text.lower())

    def test_lan_rules_are_opt_in(self):
        without = build_ruleset(self.endpoints)
        with_lan = build_ruleset(self.endpoints, allow_lan=True)
        self.assertNotIn("10.0.0.0/8", without)
        self.assertIn("10.0.0.0/8", with_lan)
        self.assertIn("fc00::/7", with_lan)

    def test_empty_allowlist_is_rejected(self):
        with self.assertRaises(RulesError):
            build_ruleset(())

    def test_endpoint_values_cannot_inject_rules(self):
        for address in ("192.0.2.10; flush ruleset", "192.0.2.10\n add table", ""):
            with self.assertRaises(RulesError):
                Endpoint(address, 1194, "udp")
        for port in (0, 65536, -1):
            with self.assertRaises(RulesError):
                Endpoint("192.0.2.10", port, "udp")
        with self.assertRaises(RulesError):
            Endpoint("192.0.2.10", 1194, "icmp")

    def test_saved_state_round_trip(self):
        endpoints = endpoints_from_state(
            [
                {"address": "192.0.2.10", "port": 1194, "protocol": "udp"},
                {"address": "2001:db8::1", "port": 443, "protocol": "tcp"},
            ]
        )
        self.assertEqual(len(endpoints), 2)
        with self.assertRaises(RulesError):
            endpoints_from_state([])


if __name__ == "__main__":
    unittest.main()
