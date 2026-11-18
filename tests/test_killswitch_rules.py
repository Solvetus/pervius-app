from __future__ import annotations

import socket
import unittest

from pervius.killswitchd.rules import (
    Endpoint,
    RulesError,
    build_dns_window,
    build_dns_window_close,
    build_endpoint_swap,
    build_ruleset,
    cgroup_match,
    endpoints_from_state,
    parse_remote_list,
    resolve_remotes,
    resolver_addresses,
    validate_ifname,
    validate_interfaces,
)

SERVICE_CGROUP = "system.slice/pervius-killswitchd.service"


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

    def test_ruleset_is_an_atomic_replacement_of_its_own_table(self):
        text = build_ruleset(self.endpoints)
        lines = text.splitlines()
        self.assertEqual(lines[0], "table inet pervius_ks {}")
        self.assertEqual(lines[1], "delete table inet pervius_ks")
        self.assertEqual(lines[2], "table inet pervius_ks {")
        self.assertNotIn("flush ruleset", text)
        self.assertNotIn("ufw", text.lower())
        self.assertEqual(text.count("table inet"), 3)

    def test_ipv4_and_ipv6_endpoints_live_in_named_sets(self):
        text = build_ruleset(self.endpoints)
        self.assertIn("elements = { 192.0.2.10 . udp . 1194 }", text)
        self.assertIn("elements = { 2001:db8::1 . tcp . 443 }", text)
        self.assertIn("ip daddr . meta l4proto . th dport @endpoints_v4 accept", text)
        self.assertIn("ip6 daddr . meta l4proto . th dport @endpoints_v6 accept", text)
        self.assertIn("meta nfproto ipv4 drop", text)
        self.assertIn("meta nfproto ipv6 drop", text)
        self.assertIn("type filter hook forward priority -10; policy drop;", text)

    def test_ipv4_only_endpoints_leave_the_ipv6_set_empty(self):
        text = build_ruleset((Endpoint("192.0.2.10", 1194, "udp"),))
        v6 = text[text.index("set endpoints_v6"):text.index("set dns_window_v4")]
        self.assertNotIn("elements", v6)
        self.assertIn("meta nfproto ipv6 drop", text)

    def test_ipv6_only_endpoints(self):
        text = build_ruleset((Endpoint("2001:db8::1", 1194, "udp"),))
        v4 = text[text.index("set endpoints_v4"):text.index("set endpoints_v6")]
        self.assertNotIn("elements", v4)
        self.assertIn("2001:db8::1 . udp . 1194", text)

    def test_tunnel_is_pinned_instead_of_tun_wildcard(self):
        text = build_ruleset(self.endpoints)
        self.assertNotIn("tun*", text)
        self.assertIn('elements = { "pervius0" }', text)
        self.assertIn("oifname @allowed_ifaces accept", text)

    def test_extra_interfaces_join_the_same_set(self):
        text = build_ruleset(self.endpoints, interfaces=["wt0", "pervius0", "wt0"])
        self.assertIn('elements = { "pervius0", "wt0" }', text)

    def test_invalid_interfaces_are_rejected(self):
        for bad in ("", ".", "..", "-x", "a" * 16, "wt0; flush ruleset", 'wt0"', "wt*", "a b", "é", "eth0\n", None, 5):
            with self.assertRaises(RulesError, msg=repr(bad)):
                build_ruleset(self.endpoints, interfaces=[bad])

    def test_lan_rules_are_opt_in(self):
        without = build_ruleset(self.endpoints)
        with_lan = build_ruleset(self.endpoints, allow_lan=True)
        self.assertNotIn("10.0.0.0/8", without)
        self.assertIn("ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept", with_lan)
        self.assertIn("ip6 daddr { fc00::/7, fe80::/10 } accept", with_lan)
        # LAN rules come before the final drops.
        self.assertLess(with_lan.index("10.0.0.0/8"), with_lan.index("meta nfproto ipv4 drop"))

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


class DnsOutsideTheTunnelTests(unittest.TestCase):
    """While armed, DNS may not reach the LAN's resolver, even with the LAN allowed."""

    def test_dns_is_dropped_before_lan_access(self):
        text = build_ruleset((Endpoint("192.0.2.10", 1194, "udp"),), allow_lan=True)
        drop = text.index("meta l4proto { udp, tcp } th dport 53 drop")
        self.assertLess(drop, text.index("ip daddr { 10.0.0.0/8"))
        self.assertLess(text.index("oifname @allowed_ifaces accept"), drop)
        self.assertIn("tcp dport 853 drop", text)

    def test_window_rule_comes_before_the_dns_drop(self):
        text = build_ruleset((Endpoint("192.0.2.10", 1194, "udp"),), service_cgroup="init.scope")
        self.assertLess(text.index("@dns_window_v4"), text.index("th dport 53 drop"))


class InterfaceNameTests(unittest.TestCase):
    def test_linux_names_are_accepted(self):
        for name in ("wt0", "eth0", "enp0s1", "wg-home", "br.10", "a" * 15, "tailscale0"):
            self.assertEqual(validate_ifname(name), name)

    def test_interface_list_is_deduplicated_and_capped(self):
        self.assertEqual(validate_interfaces(["wt0", "wt0", "eth1"]), ("wt0", "eth1"))
        with self.assertRaises(RulesError):
            validate_interfaces([f"if{index}" for index in range(17)])


class EndpointSwapTests(unittest.TestCase):
    def test_swap_flushes_and_refills_both_sets_and_closes_the_window(self):
        text = build_endpoint_swap(
            (Endpoint("192.0.2.20", 1194, "udp"), Endpoint("2001:db8::20", 1194, "udp"))
        )
        self.assertEqual(
            text.splitlines(),
            [
                "flush set inet pervius_ks endpoints_v4",
                "add element inet pervius_ks endpoints_v4 { 192.0.2.20 . udp . 1194 }",
                "flush set inet pervius_ks endpoints_v6",
                "add element inet pervius_ks endpoints_v6 { 2001:db8::20 . udp . 1194 }",
                "flush set inet pervius_ks dns_window_v4",
                "flush set inet pervius_ks dns_window_v6",
            ],
        )
        self.assertNotIn("delete", text)

    def test_swap_never_empties_the_allowlist(self):
        with self.assertRaises(RulesError):
            build_endpoint_swap(())

    def test_window_close(self):
        self.assertEqual(
            build_dns_window_close().splitlines(),
            ["flush set inet pervius_ks dns_window_v4", "flush set inet pervius_ks dns_window_v6"],
        )


class DnsWindowRuleTests(unittest.TestCase):
    def setUp(self):
        self.endpoints = (Endpoint("192.0.2.10", 1194, "udp"),)

    def test_window_rule_is_limited_to_the_service_cgroup_and_plain_dns(self):
        text = build_ruleset(self.endpoints, service_cgroup=SERVICE_CGROUP)
        rules = [line.strip() for line in text.splitlines() if "dns_window" in line and "socket" in line]
        self.assertEqual(
            rules,
            [
                'socket cgroupv2 level 2 "system.slice/pervius-killswitchd.service" '
                "ip daddr @dns_window_v4 meta l4proto { udp, tcp } th dport 53 accept",
                'socket cgroupv2 level 2 "system.slice/pervius-killswitchd.service" '
                "ip6 daddr @dns_window_v6 meta l4proto { udp, tcp } th dport 53 accept",
            ],
        )
        for line in rules:
            self.assertNotIn("853", line)
        # No rule admits DNS to the window resolvers without the cgroup match.
        for line in text.splitlines():
            if "@dns_window" in line:
                self.assertIn("socket cgroupv2", line)
        self.assertLess(text.index("@dns_window_v4"), text.index("meta nfproto ipv4 drop"))

    def test_no_cgroup_means_no_window_rule(self):
        text = build_ruleset(self.endpoints)
        self.assertNotIn("socket cgroupv2", text)
        self.assertNotIn("@dns_window", text)

    def test_level_follows_the_path_depth(self):
        self.assertEqual(cgroup_match("init.scope"), 'socket cgroupv2 level 1 "init.scope"')
        self.assertEqual(cgroup_match("/system.slice/x.service"), 'socket cgroupv2 level 2 "system.slice/x.service"')
        self.assertEqual(
            cgroup_match("user.slice/user-1000.slice/session-2.scope"),
            'socket cgroupv2 level 3 "user.slice/user-1000.slice/session-2.scope"',
        )

    def test_unsafe_cgroup_paths_generate_no_rule(self):
        for bad in (
            "",
            "/",
            'system.slice/x.service" accept',
            "system.slice/x.service accept",
            "system.slice/../x",
            "a/./b",
            "a/b/c/d/e/f/g",
            "system.slice/x\nflush ruleset",
            "system.slice/x;y",
            None,
            7,
        ):
            self.assertIsNone(cgroup_match(bad), repr(bad))
            text = build_ruleset(self.endpoints, service_cgroup=bad)
            self.assertNotIn("socket cgroupv2", text, repr(bad))

    def test_window_elements_expire_by_themselves(self):
        text = build_dns_window(["192.168.1.1", "fe80::1%enp0s1", "2001:db8::53"], 5)
        self.assertEqual(
            text.splitlines(),
            [
                "add element inet pervius_ks dns_window_v4 { 192.168.1.1 timeout 5s }",
                "add element inet pervius_ks dns_window_v6 { fe80::1 timeout 5s, 2001:db8::53 timeout 5s }",
            ],
        )

    def test_window_duration_is_bounded(self):
        for seconds in (0, 6, 60, "5"):
            with self.assertRaises(RulesError):
                build_dns_window(["192.168.1.1"], seconds)

    def test_window_needs_a_usable_resolver(self):
        with self.assertRaises(RulesError):
            build_dns_window(["127.0.0.53", "::1", "0.0.0.0", "224.0.0.1", "nonsense"])

    def test_resolver_addresses_are_validated(self):
        self.assertEqual(
            resolver_addresses(["192.168.1.1", "192.168.1.1", "bad", "127.0.0.53", "fe80::1 ; x", "fe80::2%eth0"]),
            ("192.168.1.1", "fe80::2"),
        )


if __name__ == "__main__":
    unittest.main()
