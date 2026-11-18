"""Kill-switch and IPv6-guard rules, enforced by the real kernel.

These tests apply the generated rulesets with nft inside a fresh network
namespace that contains only dummy interfaces:

    eth9      the "physical" link (default routes, IPv4 + IPv6)
    pervius0  the pinned VPN tunnel
    wt0       an always-allowed interface (e.g. NetBird)
    tun0      some other tunnel, which must NOT be allowed

The oracle is the kernel itself: a packet dropped in the output hook makes
sendto()/connect() fail with EPERM; an allowed one is accepted (and then
vanishes into the dummy device).

They run as root, and only in a non-initial network namespace, so the host
firewall is never touched.  CI runs them with:

    sudo unshare --net /usr/bin/python3 -m unittest discover -s tests/integration -t . -v
"""

from __future__ import annotations

import os
import shutil
import tempfile
import socket
import struct
import subprocess
import time
import unittest
from pathlib import Path

from pervius.config import MANAGED_UUID
from pervius.killswitchd.rules import (
    Endpoint,
    build_dns_window,
    build_endpoint_swap,
    build_ruleset,
    merge_endpoints,
)

REPO = Path(__file__).resolve().parents[2]
HOOK = REPO / "data" / "networkmanager" / "90-pervius-guard"
NFT = shutil.which("nft", path="/usr/sbin:/usr/bin:/sbin:/bin")
IP = shutil.which("ip", path="/usr/sbin:/usr/bin:/sbin:/bin")
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


def in_private_netns() -> bool:
    try:
        return os.stat("/proc/self/ns/net").st_ino != os.stat("/proc/1/ns/net").st_ino
    except OSError:
        return False


REASON = ""
if os.geteuid() != 0:
    REASON = "needs root (run under sudo unshare --net)"
elif not in_private_netns():
    REASON = "refusing to run in the host network namespace"
elif not NFT or not IP:
    REASON = "needs nft and ip"


def run(*args, input_text=None, check=True):
    return subprocess.run(args, input=input_text, text=True, capture_output=True, check=check)


def nft(script: str, check=True):
    return run(NFT, "-f", "-", input_text=script, check=check)


def own_cgroup() -> str:
    for line in Path("/proc/self/cgroup").read_text().splitlines():
        if line.startswith("0::"):
            return line[3:].strip().strip("/")
    return ""


def tcp_syn(port: int) -> bytes:
    """A bare TCP SYN header; netfilter matches it before any checksum matters."""
    return struct.pack("!HHIIBBHHH", 40000, port, 0, 0, 5 << 4, 0x02, 64240, 0, 0)


def send(dest: str, port: int, *, proto: str = "udp", device: str | None = None) -> bool:
    """True if the output hook let the first packet out, False on EPERM.

    UDP uses sendto() on a datagram socket.  TCP uses a raw socket carrying a
    SYN, because a non-blocking connect() reports EINPROGRESS even when the SYN
    is dropped; a raw sendto() gets the output hook's verdict synchronously.
    """
    family = socket.AF_INET6 if ":" in dest else socket.AF_INET
    if proto == "udp":
        kind, number, payload = socket.SOCK_DGRAM, 0, b"pervius"
    else:
        kind, number, payload = socket.SOCK_RAW, socket.IPPROTO_TCP, tcp_syn(port)
    address = dest
    scope = 0
    if "%" in dest:
        address, ifname = dest.split("%", 1)
        scope = socket.if_nametoindex(ifname)
    target_port = port if proto == "udp" else 0
    sockaddr = (address, target_port, 0, scope) if family == socket.AF_INET6 else (address, target_port)
    with socket.socket(family, kind, number) as sock:
        if device:
            sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, device.encode())
        try:
            sock.sendto(payload, sockaddr)
        except PermissionError:
            return False
    return True


@unittest.skipIf(REASON, REASON)
class NamespaceTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        run(IP, "link", "set", "lo", "up")
        for name in ("eth9", "pervius0", "wt0", "tun0"):
            run(IP, "link", "add", name, "type", "dummy", check=False)
            run(IP, "link", "set", name, "up")
        run(IP, "addr", "add", "10.99.0.2/24", "dev", "eth9", check=False)
        run(IP, "-6", "addr", "add", "2001:db8:99::2/64", "dev", "eth9", "nodad", check=False)
        run(IP, "-6", "addr", "add", "fd99::2/64", "dev", "eth9", "nodad", check=False)
        run(IP, "addr", "add", "10.8.0.2/24", "dev", "pervius0", check=False)
        run(IP, "addr", "add", "100.64.0.2/16", "dev", "wt0", check=False)
        run(IP, "-6", "addr", "add", "2001:db8:64::2/64", "dev", "wt0", "nodad", check=False)
        run(IP, "addr", "add", "10.7.0.2/24", "dev", "tun0", check=False)
        run(IP, "route", "replace", "default", "via", "10.99.0.1", "dev", "eth9")
        run(IP, "-6", "route", "replace", "default", "via", "2001:db8:99::1", "dev", "eth9")
        time.sleep(0.5)  # let link-local addresses appear

    def tearDown(self):
        for table in ("inet pervius_ks", "inet pervius_guard", "inet pervius_v6"):
            run(NFT, "delete", "table", *table.split(), check=False)

    def assertAllowed(self, *args, **kwargs):
        self.assertTrue(send(*args, **kwargs), f"expected allowed: {args} {kwargs}")

    def assertBlocked(self, *args, **kwargs):
        self.assertFalse(send(*args, **kwargs), f"expected blocked: {args} {kwargs}")


class KillSwitchTests(NamespaceTestCase):
    ENDPOINTS = (Endpoint("192.0.2.10", 1194, "udp"), Endpoint("2001:db8::10", 443, "tcp"))

    def arm(self, **kwargs):
        nft(build_ruleset(self.ENDPOINTS, **kwargs))

    def test_baseline_without_rules_everything_leaves(self):
        self.assertAllowed("198.51.100.1", 53)
        self.assertAllowed("2001:db8:5::1", 53)

    def test_only_endpoints_on_their_exact_protocol_and_port(self):
        self.arm()
        self.assertAllowed("192.0.2.10", 1194)
        self.assertBlocked("192.0.2.10", 1195)
        self.assertBlocked("192.0.2.10", 1194, proto="tcp")
        self.assertAllowed("2001:db8::10", 443, proto="tcp")
        self.assertBlocked("2001:db8::10", 443)
        self.assertBlocked("198.51.100.1", 53)
        self.assertBlocked("198.51.100.1", 443, proto="tcp")
        self.assertBlocked("2001:db8:5::1", 53)

    def test_tunnel_is_pinned_and_other_tunnels_are_blocked(self):
        self.arm()
        self.assertAllowed("198.51.100.1", 53, device="pervius0")
        self.assertBlocked("198.51.100.1", 53, device="tun0")
        self.assertBlocked("198.51.100.1", 53, device="wt0")
        self.assertAllowed("127.0.0.1", 9)

    def test_always_allowed_interfaces(self):
        self.arm(interfaces=["wt0"])
        self.assertAllowed("100.64.0.9", 51820, device="wt0")
        self.assertAllowed("2001:db8:64::9", 53, device="wt0")
        self.assertBlocked("198.51.100.1", 53, device="tun0")
        self.assertBlocked("198.51.100.1", 53)

    def test_lan_is_opt_in(self):
        self.arm()
        self.assertBlocked("10.99.0.1", 445, proto="tcp")
        self.assertBlocked("fd99::1", 445, proto="tcp")
        self.arm(allow_lan=True)
        self.assertAllowed("10.99.0.1", 445, proto="tcp")
        self.assertAllowed("fd99::1", 445, proto="tcp")
        self.assertBlocked("198.51.100.1", 443, proto="tcp")

    def test_endpoint_swap_is_atomic_and_exclusive(self):
        self.arm()
        nft(build_endpoint_swap((Endpoint("192.0.2.20", 1194, "udp"),)))
        self.assertAllowed("192.0.2.20", 1194)
        self.assertBlocked("192.0.2.10", 1194)
        self.assertBlocked("2001:db8::10", 443, proto="tcp")

    def test_allowed_interface_set_exists_while_armed(self):
        self.arm(interfaces=["wt0"])
        listing = run(NFT, "list", "set", "inet", "pervius_ks", "allowed_ifaces").stdout
        self.assertIn('"pervius0"', listing)
        self.assertIn('"wt0"', listing)
        run(NFT, "delete", "table", "inet", "pervius_ks")
        missing = run(NFT, "list", "set", "inet", "pervius_ks", "allowed_ifaces", check=False)
        self.assertNotEqual(missing.returncode, 0)  # disarmed: the table and its sets are gone

    def test_lan_access_never_includes_dns(self):
        self.arm(allow_lan=True)
        self.assertAllowed("10.99.0.1", 445, proto="tcp")
        self.assertBlocked("10.99.0.1", 53)
        self.assertBlocked("10.99.0.1", 53, proto="tcp")
        self.assertBlocked("fd99::1", 53)
        self.assertAllowed("10.8.0.1", 53, device="pervius0")

    def test_switch_while_armed_keeps_the_old_server_until_the_new_tunnel_is_up(self):
        """Regression: replacing the endpoints before disconnecting cut the old
        tunnel's packets ("write UDPv4: Operation not permitted"); the old
        OpenVPN then held pervius0 and the new one could not open it."""
        old = (Endpoint("192.0.2.10", 1194, "udp"),)
        new = (Endpoint("192.0.2.20", 1194, "udp"),)
        nft(build_ruleset(old))
        self.assertAllowed("192.0.2.10", 1194)  # the live tunnel's server
        # 1. Before disconnecting: the new location's servers are merged in.
        nft(build_endpoint_swap(merge_endpoints(new, old)))
        self.assertAllowed("192.0.2.10", 1194)  # old tunnel can still close cleanly
        self.assertAllowed("192.0.2.20", 1194)
        # 2. New tunnel up: replace, keeping the live (new) server.
        nft(build_endpoint_swap(merge_endpoints(new, new)))
        self.assertAllowed("192.0.2.20", 1194)
        self.assertBlocked("192.0.2.10", 1194)
        self.assertAllowed("198.51.100.1", 443, proto="tcp", device="pervius0")  # tunnel traffic flows

    def test_tunnel_traffic_flows_while_armed(self):
        nft(build_ruleset((Endpoint("192.0.2.10", 1194, "udp"),)))
        for dest, port, proto in (("198.51.100.1", 443, "tcp"), ("198.51.100.1", 53, "udp"), ("10.8.0.1", 80, "tcp")):
            self.assertAllowed(dest, port, proto=proto, device="pervius0")
        self.assertBlocked("198.51.100.1", 443, proto="tcp")  # same traffic outside the tunnel

    def test_rejected_transaction_leaves_the_old_set_intact(self):
        self.arm()
        broken = build_endpoint_swap((Endpoint("192.0.2.20", 1194, "udp"),)) + "add element inet pervius_ks nope { 1 }\n"
        self.assertNotEqual(nft(broken, check=False).returncode, 0)
        self.assertAllowed("192.0.2.10", 1194)
        self.assertBlocked("192.0.2.20", 1194)

    def test_rebuild_replaces_the_table_in_one_transaction(self):
        self.arm()
        self.arm(interfaces=["wt0"])
        listing = run(NFT, "list", "table", "inet", "pervius_ks").stdout
        self.assertEqual(listing.count("chain output"), 1)
        self.assertAllowed("100.64.0.9", 51820, device="wt0")

    def test_dns_window_admits_only_the_matching_cgroup_and_expires(self):
        cgroup = own_cgroup()
        if not cgroup or not (Path("/sys/fs/cgroup") / cgroup).is_dir():
            self.skipTest("cgroup v2 path unavailable")
        self.arm(service_cgroup=cgroup)
        self.assertBlocked("10.99.0.53", 53)
        nft(build_dns_window(["10.99.0.53"], 2))
        self.assertAllowed("10.99.0.53", 53)
        self.assertAllowed("10.99.0.53", 53, proto="tcp")
        self.assertBlocked("10.99.0.53", 54)
        self.assertBlocked("10.99.0.54", 53)
        time.sleep(2.5)
        self.assertBlocked("10.99.0.53", 53)

    def test_dns_window_blocks_other_processes(self):
        # The window rule names a cgroup this test process is not in: its DNS
        # stays blocked although the resolver is in the window set.
        if not (Path("/sys/fs/cgroup") / "init.scope").is_dir() or own_cgroup() == "init.scope":
            self.skipTest("init.scope unavailable")
        self.arm(service_cgroup="init.scope")
        nft(build_dns_window(["10.99.0.53"], 5))
        self.assertBlocked("10.99.0.53", 53)
        self.assertBlocked("10.99.0.53", 53, proto="tcp")


class GuardTests(NamespaceTestCase):
    def hook(self, action, options: str | None = None, **env):
        work = Path(tempfile.mkdtemp())
        conf = work / "guard.conf"
        if options is not None:
            conf.write_text(options)
            conf.chmod(0o644)
        script = work / "hook"
        script.write_text(
            HOOK.read_text().replace("OPTIONS=/var/lib/pervius/guard.conf\n", f"OPTIONS={conf}\n")
        )
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "CONNECTION_UUID": MANAGED_UUID}
        environment.update(env)
        result = subprocess.run(
            ["sh", str(script), "pervius0", action], env=environment, capture_output=True, text=True
        )
        shutil.rmtree(work)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dns_leaves_only_through_the_tunnel(self):
        self.hook("vpn-up", VPN_IP_IFACE="pervius0")
        self.assertBlocked("10.99.0.1", 53)  # the router's resolver
        self.assertBlocked("10.99.0.1", 53, proto="tcp")
        self.assertBlocked("198.51.100.1", 853, proto="tcp")
        self.assertAllowed("10.8.0.1", 53, device="pervius0")
        self.assertAllowed("127.0.0.53", 53)
        self.assertAllowed("198.51.100.1", 443, proto="tcp")  # other IPv4 untouched

    def test_dns_guard_stays_with_ipv6_blocking_off(self):
        self.hook("vpn-up", options="block-ipv6=no\n")
        self.assertBlocked("10.99.0.1", 53)
        self.assertAllowed("2001:db8:5::1", 443, proto="tcp")

    def test_guard_blocks_global_ipv6_outside_the_tunnel(self):
        self.hook("vpn-up", VPN_IP_IFACE="pervius0")
        self.assertBlocked("2001:db8:5::1", 53)
        self.assertBlocked("2001:db8:5::1", 443, proto="tcp")
        self.assertBlocked("ff0e::1", 53, device="eth9")
        self.assertAllowed("fd99::1", 445, proto="tcp")
        self.assertAllowed("ff02::1%eth9", 5353)
        self.assertAllowed("fe80::1%eth9", 5353)
        self.assertAllowed("::1", 9)
        self.assertAllowed("198.51.100.1", 443, proto="tcp")  # IPv4 untouched (except DNS)

    def test_guard_allows_listed_interfaces(self):
        self.hook("vpn-up", options="allowed-interfaces=wt0\n", VPN_IP_IFACE="pervius0")
        self.assertAllowed("2001:db8:64::9", 53, device="wt0")
        self.assertBlocked("2001:db8:5::1", 53)

    def test_guard_follows_the_vpn_lifecycle(self):
        self.hook("vpn-pre-up", VPN_IP_IFACE="pervius0")
        self.assertBlocked("2001:db8:5::1", 443, proto="tcp")
        self.hook("vpn-down")
        self.assertAllowed("2001:db8:5::1", 443, proto="tcp")
        self.assertAllowed("10.99.0.1", 53)

    def test_ipv6_blocking_can_be_turned_off(self):
        self.hook("vpn-up", options="block-ipv6=no\n")
        self.assertAllowed("2001:db8:5::1", 443, proto="tcp")

    def test_foreign_connection_is_ignored(self):
        self.hook("vpn-up", CONNECTION_UUID="11111111-1111-1111-1111-111111111111")
        self.assertAllowed("2001:db8:5::1", 53)
        self.assertAllowed("10.99.0.1", 53)

    def test_guard_and_kill_switch_together(self):
        nft(build_ruleset((Endpoint("192.0.2.10", 1194, "udp"),)))
        self.hook("vpn-up", VPN_IP_IFACE="pervius0")
        self.assertAllowed("192.0.2.10", 1194)
        self.assertBlocked("2001:db8:5::1", 53)
        self.assertBlocked("198.51.100.1", 53)
        self.assertAllowed("198.51.100.1", 53, device="pervius0")


if __name__ == "__main__":
    unittest.main()
