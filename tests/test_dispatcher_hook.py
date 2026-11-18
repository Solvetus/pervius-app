"""The NetworkManager dispatcher hook that guards against IPv6 leaks.

The real script runs under sh with a crafted environment.  Its single
``NFT=/usr/sbin/nft`` line is replaced in a temporary copy by a fake nft that
records its arguments and input; the script has no environment override.
"""

from __future__ import annotations

import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from pervius.config import (
    MANAGED_UUID,
    USER_DATA_ALLOWED_INTERFACES,
    USER_DATA_BLOCK_IPV6,
)

REPO = Path(__file__).resolve().parents[1]
HOOK = REPO / "data" / "networkmanager" / "90-pervius-ipv6-guard"
NFT_LINE = "NFT=/usr/sbin/nft\n"
HOSTILE = '"; flush ruleset; table ip x { chain y { type filter hook output priority 0; policy drop; } }'


def nm_user_env_name(key: str) -> str:
    """NetworkManager-dispatcher(8): encoding of user-data keys."""
    out = []
    for char in key:
        if "a" <= char <= "z":
            out.append(char.upper())
        elif "A" <= char <= "Z":
            out.append("_" + char)
        elif "0" <= char <= "9":
            out.append(char)
        elif char == ".":
            out.append("__")
        else:
            out.append("_%03o" % ord(char))
    return "CONNECTION_USER_" + "".join(out)


BLOCK_VAR = nm_user_env_name(USER_DATA_BLOCK_IPV6)
IFACES_VAR = nm_user_env_name(USER_DATA_ALLOWED_INTERFACES)


class HookTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "nft.log"
        fake = self.tmp / "nft"
        fake.write_text(
            "#!/bin/sh\n"
            f'printf "ARGS %s\\n" "$*" >>"{self.log}"\n'
            f'if [ "$1" = "-f" ]; then cat >>"{self.log}"; fi\n'
            "exit 0\n"
        )
        fake.chmod(0o755)
        text = HOOK.read_text()
        self.assertEqual(text.count(NFT_LINE), 1)
        self.hook = self.tmp / "hook"
        self.hook.write_text(text.replace(NFT_LINE, f"NFT={fake}\n"))
        self.hook.chmod(0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp)

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
        hostile = {
            "VPN_IP_IFACE": HOSTILE,
            BLOCK_VAR: HOSTILE,
            IFACES_VAR: HOSTILE,
        }
        for uuid in (None, "", "11111111-1111-1111-1111-111111111111", MANAGED_UUID + "x", " " + MANAGED_UUID):
            for action in ("vpn-pre-up", "vpn-up", "vpn-down", "up", "down"):
                self.assertEqual(self.run_hook(action, uuid=uuid, **hostile), "", (uuid, action))

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
            self.assertIn("table inet pervius_v6 {}\ndelete table inet pervius_v6\ntable inet pervius_v6 {", out)
            self.assertIn('oifname { "pervius0" } accept', out)
            self.assertIn("ip6 daddr { fe80::/10, ff02::/16, fc00::/7 } accept", out)
            self.assertIn("icmpv6 type { 133, 134, 135, 136 } accept", out)
            self.assertIn("meta nfproto ipv4 accept", out)
            self.assertIn("meta nfproto ipv6 drop", out)
            self.assertNotIn("pervius_ks", out)

    def test_down_removes_the_guard(self):
        self.assertEqual(self.run_hook("vpn-down").strip(), "ARGS delete table inet pervius_v6")

    def test_other_actions_do_nothing(self):
        for action in ("up", "down", "pre-up", "vpn-pre-down", "connectivity-change", "hostname", "", "vpn-up;x"):
            self.assertEqual(self.run_hook(action), "", action)

    def test_block_flag(self):
        self.assertIn("ARGS -f -", self.run_hook("vpn-up"))  # absent means yes
        self.log.unlink()
        self.assertEqual(self.run_hook("vpn-up", **{BLOCK_VAR: "no"}).strip(), "ARGS delete table inet pervius_v6")
        for value in ("yes", "No", "0", "false", HOSTILE):
            self.log.unlink(missing_ok=True)
            self.assertIn("ARGS -f -", self.run_hook("vpn-up", **{BLOCK_VAR: value}), value)

    def test_allowed_interfaces_are_added(self):
        out = self.run_hook("vpn-up", VPN_IP_IFACE="pervius0", **{IFACES_VAR: "wt0,eth1,pervius0"})
        self.assertIn('oifname { "pervius0", "wt0", "eth1" } accept', out)

    def test_hostile_values_never_reach_nft(self):
        bad = ["wt0; flush ruleset", "*", "..", ".", "a" * 16, "wt0\nflush ruleset", '"wt0"', "-x", "wt 0", "wt0}"]
        out = self.run_hook(
            "vpn-up",
            VPN_IP_IFACE=HOSTILE,
            **{IFACES_VAR: ",".join(bad + ["wt0"])},
        )
        self.assertIn('oifname { "pervius0", "wt0" } accept', out)
        self.assertNotIn("flush ruleset", out)
        self.assertNotIn("table ip x", out)
        self.assertNotIn("*", out.replace("/*", ""))

    def test_interface_list_is_capped(self):
        names = ",".join(f"if{index}" for index in range(30))
        out = self.run_hook("vpn-up", **{IFACES_VAR: names})
        listed = re.search(r"oifname \{ (.*?) \} accept", out).group(1).split(", ")
        self.assertEqual(len(listed), 1 + 16)


class EncodingAndPackagingTests(unittest.TestCase):
    def test_env_encoding_matches_the_man_page_example(self):
        self.assertEqual(nm_user_env_name("test.foo-Bar2"), "CONNECTION_USER_TEST__FOO_055_BAR2")

    def test_hook_uses_the_encoded_names(self):
        text = HOOK.read_text()
        self.assertEqual(BLOCK_VAR, "CONNECTION_USER_COM__SOLVETUS__PERVIUS__BLOCK_055IPV6")
        self.assertEqual(IFACES_VAR, "CONNECTION_USER_COM__SOLVETUS__PERVIUS__ALLOWED_055INTERFACES")
        self.assertIn(BLOCK_VAR, text)
        self.assertIn(IFACES_VAR, text)

    def test_hook_is_executable_and_installed_with_a_pre_up_link(self):
        self.assertTrue(HOOK.stat().st_mode & stat.S_IXUSR)
        rows = [
            line.split("\t")
            for line in (REPO / "packaging" / "layout.tsv").read_text().splitlines()
            if line and not line.startswith("#")
        ]
        self.assertIn(
            ["0755", "data/networkmanager/90-pervius-ipv6-guard", "/usr/lib/NetworkManager/dispatcher.d/90-pervius-ipv6-guard"],
            rows,
        )
        self.assertIn(
            ["link", "../90-pervius-ipv6-guard", "/usr/lib/NetworkManager/dispatcher.d/pre-up.d/90-pervius-ipv6-guard"],
            rows,
        )

    def test_hook_has_no_python_or_external_input(self):
        text = HOOK.read_text()
        self.assertNotIn("python", text)
        for forbidden in ("curl", "wget", "$HOME", "/home", "read ", "eval", "source ", ". /"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
