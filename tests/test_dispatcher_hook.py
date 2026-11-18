"""The NetworkManager dispatcher hook that guards against DNS and IPv6 leaks.

The real script runs under sh with a crafted environment.  Two lines are
substituted in a temporary copy: ``NFT=`` points at a fake nft that records
its arguments and input, and ``OPTIONS=``/``OPTIONS_OWNER=`` point at a
test-owned options file.  The script has no environment override.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from pervius.config import MANAGED_UUID

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / "data" / "networkmanager" / "90-pervius-guard"
NFT_LINE = "NFT=/usr/sbin/nft\n"
OPTIONS_LINE = "OPTIONS=/var/lib/pervius/guard.conf\n"
OWNER_LINE = "OPTIONS_OWNER=0\n"
TUNNEL_RULE = 'oifname "pervius0" oifkind { "tun", "ovpn", "ovpn-dco" } accept'
HOSTILE = '"; flush ruleset; table ip x { chain y { type filter hook output priority 0; policy drop; } }'


class HookTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "nft.log"
        self.options = self.tmp / "guard.conf"
        fake = self.tmp / "nft"
        fake.write_text(
            "#!/bin/sh\n"
            f'printf "ARGS %s\\n" "$*" >>"{self.log}"\n'
            f'if [ "$1" = "-f" ]; then cat >>"{self.log}"; fi\n'
            "exit 0\n"
        )
        fake.chmod(0o755)
        text = HOOK.read_text()
        for line in (NFT_LINE, OPTIONS_LINE, OWNER_LINE):
            self.assertEqual(text.count(line), 1, line)
        text = (
            text.replace(NFT_LINE, f"NFT={fake}\n")
            .replace(OPTIONS_LINE, f"OPTIONS={self.options}\n")
            .replace(OWNER_LINE, f"OPTIONS_OWNER={os.getuid()}\n")
        )
        self.hook = self.tmp / "hook"
        self.hook.write_text(text)
        self.hook.chmod(0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write_options(self, text: str, mode: int = 0o644):
        self.options.write_text(text)
        self.options.chmod(mode)

    def run_hook(self, action, *, uuid=MANAGED_UUID, **env):
        environment = {"PATH": "/usr/bin:/bin"}
        if uuid is not None:
            environment["CONNECTION_UUID"] = uuid
        environment.update(env)
        result = subprocess.run(
            ["sh", str(self.hook), "pervius0", action],
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.log.read_text() if self.log.exists() else ""


class UuidGateTests(HookTestCase):
    def test_foreign_or_missing_uuid_exits_before_doing_anything(self):
        self.write_options(f"block-ipv6=no\nallowed-interfaces={HOSTILE}\n")
        for uuid in (None, "", "11111111-1111-1111-1111-111111111111", MANAGED_UUID + "x", " " + MANAGED_UUID):
            for action in ("vpn-pre-up", "vpn-up", "vpn-down", "up", "down"):
                self.assertEqual(self.run_hook(action, uuid=uuid, VPN_IP_IFACE=HOSTILE), "", (uuid, action))

    def test_gate_is_the_first_statement_and_matches_the_reserved_uuid(self):
        lines = HOOK.read_text().splitlines()
        self.assertEqual(lines[0], "#!/bin/sh")
        statements = [line for line in lines if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(statements[0], f'[ "${{CONNECTION_UUID:-}}" = "{MANAGED_UUID}" ] || exit 0')


class ActionTests(HookTestCase):
    def test_pre_up_and_up_apply_the_guard_atomically(self):
        for action in ("vpn-pre-up", "vpn-up"):
            self.log.unlink(missing_ok=True)
            out = self.run_hook(action, VPN_IP_IFACE="pervius0")
            self.assertIn("ARGS -f -", out)
            self.assertIn(
                "table inet pervius_guard {}\ndelete table inet pervius_guard\ntable inet pervius_guard {", out
            )
            self.assertIn(TUNNEL_RULE, out)
            self.assertIn("ip6 daddr { fe80::/10, ff02::/16, fc00::/7 } accept", out)
            self.assertIn("icmpv6 type { 133, 134, 135, 136 } accept", out)
            self.assertIn("meta nfproto ipv6 drop", out)
            self.assertNotIn("pervius_ks", out)

    def test_dns_outside_the_tunnel_is_dropped_before_ipv4_is_accepted(self):
        out = self.run_hook("vpn-up", VPN_IP_IFACE="pervius0")
        dns = out.index("meta l4proto { udp, tcp } th dport { 53, 853 } drop")
        self.assertLess(out.index(TUNNEL_RULE), dns)
        self.assertLess(dns, out.index("meta nfproto ipv4 accept"))

    def test_dns_guard_stays_when_ipv6_blocking_is_off(self):
        self.write_options("block-ipv6=no\n")
        out = self.run_hook("vpn-up")
        self.assertIn("th dport { 53, 853 } drop", out)
        self.assertNotIn("meta nfproto ipv6 drop", out)
        # Forwarded DNS is guarded even with IPv6 blocking off.
        forward = out[out.index("chain forward"):]
        self.assertIn("th dport { 53, 853 } drop", forward)

    def test_tunnel_is_matched_by_name_and_kind(self):
        """Regression: any device named pervius0 (a VLAN, a dummy) was trusted."""
        out = self.run_hook("vpn-up", VPN_IP_IFACE="pervius0")
        self.assertNotIn('oifname { "pervius0" } accept', out)
        self.assertEqual(out.count(TUNNEL_RULE), 2)  # output and forward
        self.assertNotIn("oifname {  } accept", out)

    def test_forwarded_dns_is_dropped_outside_the_tunnel(self):
        for options in ("", "block-ipv6=no\n", "allowed-interfaces=wt0\n"):
            self.write_options(options)
            self.log.unlink(missing_ok=True)
            out = self.run_hook("vpn-up")
            forward = out[out.index("chain forward"):]
            drop = forward.index("meta l4proto { udp, tcp } th dport { 53, 853 } drop")
            self.assertLess(forward.index(TUNNEL_RULE), drop)
            self.assertLess(drop, forward.index("meta nfproto ipv4 accept"))
            if "wt0" in options:
                self.assertLess(forward.index('oifname { "wt0" } accept'), drop)

    def test_dns_over_quic_is_dropped(self):
        out = self.run_hook("vpn-up")
        self.assertNotIn("tcp dport 853 drop", out)
        self.assertEqual(out.count("meta l4proto { udp, tcp } th dport { 53, 853 } drop"), 2)

    def test_down_removes_the_guard(self):
        self.assertEqual(self.run_hook("vpn-down").strip().splitlines(), ["ARGS delete table inet pervius_guard"])

    def test_other_actions_do_nothing(self):
        for action in ("up", "down", "pre-up", "vpn-pre-down", "connectivity-change", "hostname", "", "vpn-up;x"):
            self.assertEqual(self.run_hook(action), "", action)

    def test_allowed_interfaces_from_the_options_file(self):
        self.write_options("allowed-interfaces=wt0,eth1,pervius0\n")
        out = self.run_hook("vpn-up", VPN_IP_IFACE="pervius0")
        self.assertIn(TUNNEL_RULE, out)
        self.assertIn('oifname { "wt0", "eth1" } accept', out)

    def test_options_file_must_be_owned_and_not_writable_by_others(self):
        self.write_options("block-ipv6=no\nallowed-interfaces=wt0\n", mode=0o666)
        out = self.run_hook("vpn-up")
        self.assertIn("meta nfproto ipv6 drop", out)
        self.assertNotIn('"wt0"', out)
        self.options.unlink()
        os.symlink(self.tmp / "elsewhere", self.options)
        (self.tmp / "elsewhere").write_text("block-ipv6=no\n")
        (self.tmp / "elsewhere").chmod(0o644)
        self.log.unlink()
        self.assertIn("meta nfproto ipv6 drop", self.run_hook("vpn-up"))

    def test_hostile_values_never_reach_nft(self):
        bad = ["wt0; flush ruleset", "*", "..", ".", "a" * 16, '"wt0"', "-x", "wt 0", "wt0}"]
        self.write_options("allowed-interfaces=" + ",".join(bad + ["wt0"]) + "\nblock-ipv6=" + HOSTILE + "\n")
        out = self.run_hook("vpn-up", VPN_IP_IFACE=HOSTILE)
        self.assertIn(TUNNEL_RULE, out)
        self.assertIn('oifname { "wt0" } accept', out)
        self.assertNotIn("flush ruleset", out)
        self.assertNotIn("table ip x", out)
        self.assertIn("meta nfproto ipv6 drop", out)

    def test_interface_list_is_capped(self):
        self.write_options("allowed-interfaces=" + ",".join(f"if{index}" for index in range(30)) + "\n")
        out = self.run_hook("vpn-up")
        listed = re.search(r"oifname \{ (.*?) \} accept", out).group(1).split(", ")
        self.assertEqual(len(listed), 16)


class PackagingTests(unittest.TestCase):
    def test_hook_is_executable_and_installed_with_a_pre_up_link(self):
        self.assertTrue(HOOK.stat().st_mode & stat.S_IXUSR)
        rows = [
            line.split("\t")
            for line in (REPO / "packaging" / "layout.tsv").read_text().splitlines()
            if line and not line.startswith("#")
        ]
        self.assertIn(
            ["0755", "data/networkmanager/90-pervius-guard", "/usr/lib/NetworkManager/dispatcher.d/90-pervius-guard"],
            rows,
        )
        self.assertIn(
            ["link", "../90-pervius-guard", "/usr/lib/NetworkManager/dispatcher.d/pre-up.d/90-pervius-guard"],
            rows,
        )

    def test_hook_has_no_python_or_user_input(self):
        text = HOOK.read_text()
        self.assertNotIn("python", text)
        for forbidden in ("curl", "wget", "$HOME", "/home", "eval", "source ", ". /", "CONNECTION_USER_"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
