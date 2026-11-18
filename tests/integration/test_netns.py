"""Kill-switch and IPv6-guard rules, enforced by the real kernel.

These tests apply the generated rulesets with nft inside a fresh network
namespace that contains only dummy interfaces:

    eth9      the "physical" link (default routes, IPv4 + IPv6)
    pervius0  the pinned VPN tunnel: a real tun device, created with the
              TUNSETIFF ioctl exactly as OpenVPN does (kind "tun")
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

import fcntl
import os
import re
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


TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
_TUN_FD: int | None = None


def make_tun():
    """Create pervius0 as a tun device held open by this process (like OpenVPN)."""
    global _TUN_FD
    if _TUN_FD is not None:
        return
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", b"pervius0", IFF_TUN | IFF_NO_PI))
    _TUN_FD = fd
    run(IP, "link", "set", "pervius0", "up")
    run(IP, "addr", "add", "10.8.0.2/24", "dev", "pervius0", check=False)


def drop_tun():
    global _TUN_FD
    if _TUN_FD is not None:
        os.close(_TUN_FD)
        _TUN_FD = None
    for _ in range(50):
        if not Path("/sys/class/net/pervius0").exists():
            return
        time.sleep(0.05)


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


def send(dest: str, port: int, *, proto: str = "udp", device: str | None = None, sport: int | None = None) -> bool:
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
        if sport is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", sport))
        if address == "255.255.255.255":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
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
        make_tun()
        for name in ("eth9", "wt0", "tun0"):
            run(IP, "link", "add", name, "type", "dummy", check=False)
            run(IP, "link", "set", name, "up")
        run(IP, "addr", "add", "10.99.0.2/24", "dev", "eth9", check=False)
        run(IP, "-6", "addr", "add", "2001:db8:99::2/64", "dev", "eth9", "nodad", check=False)
        run(IP, "-6", "addr", "add", "fd99::2/64", "dev", "eth9", "nodad", check=False)
        run(IP, "addr", "add", "100.64.0.2/16", "dev", "wt0", check=False)
        run(IP, "-6", "addr", "add", "2001:db8:64::2/64", "dev", "wt0", "nodad", check=False)
        run(IP, "addr", "add", "10.7.0.2/24", "dev", "tun0", check=False)
        run(IP, "route", "replace", "default", "via", "10.99.0.1", "dev", "eth9")
        run(IP, "-6", "route", "replace", "default", "via", "2001:db8:99::1", "dev", "eth9")
        time.sleep(0.5)  # let link-local addresses appear

    def tearDown(self):
        for table in ("inet pervius_ks", "inet pervius_guard"):
            run(NFT, "delete", "table", *table.split(), check=False)

    def assertAllowed(self, *args, **kwargs):
        self.assertTrue(send(*args, **kwargs), f"expected allowed: {args} {kwargs}")

    def assertBlocked(self, *args, **kwargs):
        self.assertFalse(send(*args, **kwargs), f"expected blocked: {args} {kwargs}")

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

    def with_impostor_tunnel(self, check):
        """Replace the real tun pervius0 by a dummy of the same name, run check()."""
        drop_tun()
        run(IP, "link", "add", "pervius0", "type", "dummy")
        try:
            run(IP, "link", "set", "pervius0", "up")
            run(IP, "addr", "add", "10.8.0.2/24", "dev", "pervius0")
            check()
        finally:
            run(IP, "link", "del", "pervius0", check=False)
            make_tun()


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

    def test_another_device_named_like_the_tunnel_is_blocked(self):
        """Regression: any device named pervius0 (VLAN, macvlan, dummy) was trusted."""
        self.arm(interfaces=["pervius0"])  # listing the name as an extra changes nothing

        def check():
            self.assertBlocked("198.51.100.1", 53, device="pervius0")
            self.assertBlocked("198.51.100.1", 443, proto="tcp", device="pervius0")

        self.with_impostor_tunnel(check)
        self.assertAllowed("198.51.100.1", 443, proto="tcp", device="pervius0")  # the real tun again

    def test_dhcp_only_to_broadcast_or_the_local_network(self):
        """Regression: the DHCP ports were an open path to any host."""
        self.arm()
        self.assertAllowed("255.255.255.255", 67, sport=68, device="eth9")
        self.assertAllowed("10.99.0.1", 67, sport=68)
        self.assertBlocked("198.51.100.1", 67, sport=68)
        self.assertBlocked("198.51.100.1", 443, sport=68)
        self.assertAllowed("ff02::1:2%eth9", 547, sport=546)
        self.assertAllowed("fe80::1%eth9", 547, sport=546)
        self.assertBlocked("2001:db8:5::1", 547, sport=546)

    def test_dns_over_quic_and_tls_are_blocked_even_to_the_lan(self):
        self.arm(allow_lan=True)
        self.assertBlocked("10.99.0.1", 853)
        self.assertBlocked("10.99.0.1", 853, proto="tcp")
        self.assertAllowed("10.99.0.1", 854)

    def test_allowed_interface_set_exists_while_armed(self):
        self.arm(interfaces=["wt0"])
        listing = run(NFT, "list", "set", "inet", "pervius_ks", "allowed_ifaces").stdout
        self.assertNotIn('"pervius0"', listing)  # the tunnel has its own name-and-kind rule
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
    def test_dns_leaves_only_through_the_tunnel(self):
        self.hook("vpn-up", VPN_IP_IFACE="pervius0")
        self.assertBlocked("10.99.0.1", 53)  # the router's resolver
        self.assertBlocked("10.99.0.1", 53, proto="tcp")
        self.assertBlocked("198.51.100.1", 853, proto="tcp")
        self.assertBlocked("198.51.100.1", 853)  # DNS over QUIC
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

    def test_guard_does_not_trust_another_device_named_like_the_tunnel(self):
        self.hook("vpn-up", VPN_IP_IFACE="pervius0")
        self.with_impostor_tunnel(lambda: self.assertBlocked("10.8.0.1", 53, device="pervius0"))

    def test_guard_and_kill_switch_together(self):
        nft(build_ruleset((Endpoint("192.0.2.10", 1194, "udp"),)))
        self.hook("vpn-up", VPN_IP_IFACE="pervius0")
        self.assertAllowed("192.0.2.10", 1194)
        self.assertBlocked("2001:db8:5::1", 53)
        self.assertBlocked("198.51.100.1", 53)
        self.assertAllowed("198.51.100.1", 53, device="pervius0")



class ForwardedDnsTests(NamespaceTestCase):
    """Containers and VMs routing through this host: their DNS stays in the tunnel.

    A client namespace behind a veth pair sends through this namespace (which
    forwards).  The oracle is a counter in a postrouting chain: a packet the
    guard drops in the forward hook never reaches it.
    """

    CLIENT = f"pvclient{os.getpid()}"
    PROBE = (
        "table inet pvprobe {}\n"
        "delete table inet pvprobe\n"
        "table inet pvprobe {\n"
        "  chain post {\n"
        "    type filter hook postrouting priority 300; policy accept;\n"
        "    ip daddr 10.99.0.1 udp dport 53 counter\n"
        "    ip daddr 10.99.0.1 udp dport 853 counter\n"
        "    ip daddr 10.99.0.1 udp dport 54 counter\n"
        '    oifname "pervius0" udp dport 53 counter\n'
        "  }\n"
        "}\n"
    )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if run(IP, "netns", "add", cls.CLIENT, check=False).returncode != 0:
            raise unittest.SkipTest("ip netns add is unavailable")
        client = ("-n", cls.CLIENT)
        run(IP, "link", "add", "vh0", "type", "veth", "peer", "name", "vc0", "netns", cls.CLIENT)
        run(IP, "addr", "add", "10.50.0.1/24", "dev", "vh0")
        run(IP, "link", "set", "vh0", "up")
        run(IP, *client, "link", "set", "lo", "up")
        run(IP, *client, "addr", "add", "10.50.0.2/24", "dev", "vc0")
        run(IP, *client, "link", "set", "vc0", "up")
        run(IP, *client, "route", "add", "default", "via", "10.50.0.1")
        Path("/proc/sys/net/ipv4/ip_forward").write_text("1\n")

    @classmethod
    def tearDownClass(cls):
        run(IP, "netns", "del", cls.CLIENT, check=False)
        run(IP, "link", "del", "vh0", check=False)
        run(IP, "route", "del", "198.51.100.53/32", check=False)

    def setUp(self):
        run(IP, "route", "replace", "198.51.100.53/32", "dev", "pervius0")
        nft(self.PROBE)

    def tearDown(self):
        super().tearDown()
        run(NFT, "delete", "table", "inet", "pvprobe", check=False)

    def forwarded(self) -> dict[str, int]:
        code = (
            "import socket\n"
            "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
            "for dest in (('10.99.0.1', 53), ('10.99.0.1', 853), ('10.99.0.1', 54), ('198.51.100.53', 53)):\n"
            "    s.sendto(b'q', dest)\n"
        )
        run(IP, "netns", "exec", self.CLIENT, "/usr/bin/python3", "-I", "-c", code)
        time.sleep(1.0)  # the client's first packets wait for ARP
        listing = run(NFT, "list", "chain", "inet", "pvprobe", "post").stdout
        counts = {}
        for key, pattern in (
            ("lan53", r"udp dport 53 counter packets (\d+)"),
            ("lan853", r"udp dport 853 counter packets (\d+)"),
            ("lan54", r"udp dport 54 counter packets (\d+)"),
            ("tunnel53", r'oifname "pervius0" udp dport 53 counter packets (\d+)'),
        ):
            match = re.search(pattern, listing)
            self.assertIsNotNone(match, listing)
            counts[key] = int(match.group(1))
        return counts

    def test_forwarding_works_without_the_guard(self):
        counts = self.forwarded()
        self.assertGreater(counts["lan53"], 0)
        self.assertGreater(counts["lan54"], 0)

    def test_forwarded_dns_is_dropped_outside_the_tunnel(self):
        """Regression: the guard's forward chain accepted all IPv4, DNS included."""
        for options in (None, "block-ipv6=no\n"):
            nft(self.PROBE)  # fresh counters
            self.hook("vpn-up", options=options, VPN_IP_IFACE="pervius0")
            counts = self.forwarded()
            self.assertEqual(counts["lan53"], 0, options)
            self.assertEqual(counts["lan853"], 0, options)
            self.assertGreater(counts["lan54"], 0, options)  # other IPv4 still forwarded
            self.assertGreater(counts["tunnel53"], 0, options)  # DNS into the tunnel is fine


if __name__ == "__main__":
    unittest.main()
