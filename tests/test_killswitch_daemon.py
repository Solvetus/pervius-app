"""Kill-switch service: authorization, atomic updates and recovery."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pervius.config import MANAGED_UUID
from pervius.killswitchd import daemon
from pervius.killswitchd import rules
from pervius.killswitchd.rules import Endpoint, Resolution, RulesError

OWNER = 1000
OTHER = 1001
REMOTES = (("vpn.example.com", 1194),)
OLD = (Endpoint("192.0.2.10", 1194, "udp"),)
NEW = (Endpoint("192.0.2.20", 1194, "udp"),)


class FakeBackend:
    def __init__(self):
        self.nft_calls: list[tuple[list[str], str | None]] = []
        self.tables: set[str] = set()
        self.tunnel = False
        self.cgroup = "system.slice/pervius-killswitchd.service"
        self.system_result = Resolution(OLD, ())
        self.direct_result = Resolution(NEW, ())
        self.direct_error: Exception | None = None
        self.system_error: Exception | None = None
        self.nameservers = ["192.168.1.1"]
        self.now = 1000.0
        self.direct_calls = []
        self.system_calls = 0
        self.vpn_active = False
        self.fail_next_nft = False
        self.profile_owner = "alice"
        self.gateways: list[str] = []
        self.guard_options = None

    def run_nft(self, args, *, input_text=None):
        if self.fail_next_nft:
            self.fail_next_nft = False
            raise daemon.ServiceError("nftables rejected the rules")
        self.nft_calls.append((list(args), input_text))
        if args[:1] == ["-f"] and input_text and "table inet pervius_ks {" in input_text:
            self.tables.add("inet pervius_ks")
        if args[:2] == ["delete", "table"]:
            self.tables.discard(" ".join(args[2:]))

    def table_exists(self, spec):
        return spec in self.tables

    def profile_remotes(self, uuid, uid, local_username):
        if uid != 0 and local_username(uid) != self.profile_owner:
            raise daemon.PermissionDenied("profile is not restricted to the current local user")
        return REMOTES, "udp"

    def resolve_system(self, remotes, protocol):
        self.system_calls += 1
        if self.system_error:
            raise self.system_error
        return self.system_result

    def resolve_direct(self, remotes, protocol, nameservers):
        self.direct_calls.append(tuple(nameservers))
        if self.direct_error:
            raise self.direct_error
        return self.direct_result

    def link_nameservers(self):
        return self.nameservers

    def tunnel_up(self):
        return self.tunnel

    def service_cgroup(self):
        return self.cgroup

    def managed_vpn_active(self):
        return self.vpn_active

    def active_vpn_gateways(self):
        return list(self.gateways)

    def write_guard_options(self, block_ipv6, interfaces):
        self.guard_options = (block_ipv6, interfaces)

    def apply_guard(self):
        self.guard_applied = getattr(self, "guard_applied", 0) + 1
        self.tables.add("inet pervius_guard")

    def clock(self):
        return self.now


class Service(daemon.KillSwitchService):
    @staticmethod
    def local_username(uid):
        return {OWNER: "alice", OTHER: "bob"}.get(uid, "nobody")


class ServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.backend = FakeBackend()
        self.service = Service(self.backend, state_file=self.tmp / "state" / "killswitch.json")

    def armed(self, **kwargs):
        self.service.arm(MANAGED_UUID, kwargs.get("allow_lan", False), kwargs.get("interfaces", []), OWNER)
        self.backend.nft_calls.clear()
        return self.service

    def last_script(self):
        return self.backend.nft_calls[-1][1]


class ArmTests(ServiceTestCase):
    def test_arm_applies_the_full_table_with_pinned_tunnel_and_window_rule(self):
        resolved = self.service.arm(MANAGED_UUID, False, ["wt0"], OWNER)
        self.assertEqual(resolved, OLD)
        script = self.last_script()
        self.assertIn('elements = { "pervius0", "wt0" }', script)
        self.assertIn('socket cgroupv2 level 2 "system.slice/pervius-killswitchd.service"', script)
        status = self.service.status()
        self.assertTrue(status["armed"].unpack())
        self.assertEqual(status["interfaces"].unpack(), ["wt0"])
        self.assertEqual(status["endpoints"].unpack(), 1)

    def test_arm_rejects_other_profiles_and_bad_interfaces(self):
        with self.assertRaises(daemon.PermissionDenied):
            self.service.arm("11111111-1111-1111-1111-111111111111", False, [], OWNER)
        with self.assertRaises(RulesError):
            self.service.arm(MANAGED_UUID, False, ["wt0; flush ruleset"], OWNER)
        self.assertEqual(self.backend.nft_calls, [])

    def test_arm_checks_profile_ownership(self):
        with self.assertRaises(daemon.PermissionDenied):
            self.service.arm(MANAGED_UUID, False, [], OTHER)

    def test_without_cgroup_there_is_no_window_rule(self):
        self.backend.cgroup = None
        self.service.arm(MANAGED_UUID, False, [], OWNER)
        self.assertNotIn("socket cgroupv2", self.last_script())

    def test_status_reply_never_carries_addresses(self):
        self.armed()
        reply = self.service.handle("GetStatus", (), None).unpack()[0]
        self.assertNotIn("resolved", reply)
        self.assertNotIn("192.0.2.10", json.dumps(reply, default=str))

    def test_state_file_is_private_and_versioned(self):
        self.armed(interfaces=["wt0"])
        data = json.loads(self.service.state_file.read_text())
        self.assertEqual(data["version"], 2)
        self.assertEqual(data["interfaces"], ["wt0"])
        self.assertEqual(self.service.state_file.stat().st_mode & 0o777, 0o600)


class ArmWhileConnectedTests(ServiceTestCase):
    """Arming must never cut a tunnel that is already running."""

    def test_live_server_is_allowed_even_if_the_names_resolve_elsewhere(self):
        self.backend.gateways = ["198.51.100.77"]
        self.service.arm(MANAGED_UUID, False, [], OWNER)
        script = self.last_script()
        self.assertIn("198.51.100.77 . udp . 1194", script)
        self.assertIn("192.0.2.10 . udp . 1194", script)
        self.assertEqual(self.service.status()["endpoints"].unpack(), 2)

    def test_live_server_alone_is_enough_when_names_fail(self):
        self.backend.gateways = ["198.51.100.77"]
        self.backend.system_error = RulesError("could not resolve any VPN server endpoint")
        resolved = self.service.arm(MANAGED_UUID, False, [], OWNER)
        self.assertEqual([e.address for e in resolved], ["198.51.100.77"])

    def test_without_a_live_tunnel_resolution_errors_still_fail(self):
        self.backend.system_error = RulesError("could not resolve any VPN server endpoint")
        with self.assertRaises(RulesError):
            self.service.arm(MANAGED_UUID, False, [], OWNER)
        self.assertEqual(self.backend.nft_calls, [])


class SwitchKeepsTheLiveTunnelTests(ServiceTestCase):
    """Regression: a switch removed the old server, so the old OpenVPN could
    not exit cleanly, held pervius0, and the new one failed with
    "TUNSETIFF pervius0: Device or resource busy"."""

    def test_replacing_keeps_the_live_server_allowed(self):
        self.armed()
        self.backend.tunnel = True
        self.backend.gateways = ["192.0.2.10"]  # the server the tunnel uses now
        self.backend.system_result = Resolution(NEW, ())
        self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        swap = self.last_script()
        self.assertIn("192.0.2.20 . udp . 1194", swap)
        self.assertIn("192.0.2.10 . udp . 1194", swap)

    def test_replacing_without_a_live_tunnel_drops_the_old_server(self):
        self.armed()
        self.backend.system_result = Resolution(NEW, ())
        self.backend.tunnel = True
        self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.assertNotIn("192.0.2.10", self.last_script())


class GuardSyncTests(ServiceTestCase):
    """Regression: a VPN already up at install/upgrade never got the guard."""

    def test_guard_is_applied_to_an_active_vpn_at_start(self):
        self.backend.vpn_active = True
        self.service._sync_guard()
        self.assertEqual(getattr(self.backend, "guard_applied", 0), 1)

    def test_existing_guard_is_left_alone(self):
        self.backend.vpn_active = True
        self.backend.tables.add("inet pervius_guard")
        self.service._sync_guard()
        self.assertEqual(getattr(self.backend, "guard_applied", 0), 0)

    def test_new_options_are_applied_to_the_active_vpn(self):
        self.backend.vpn_active = True
        self.backend.tables.add("inet pervius_guard")
        self.service.set_guard_options(False, [], OWNER)
        self.assertEqual(self.backend.guard_applied, 1)


class GuardOptionsTests(ServiceTestCase):
    def test_owner_sets_guard_options(self):
        self.service.set_guard_options(False, ["wt0"], OWNER)
        self.assertEqual(self.backend.guard_options, (False, ("wt0",)))

    def test_other_users_and_bad_names_are_refused(self):
        self.backend.profile_owner = "alice"
        with self.assertRaises(daemon.PermissionDenied):
            self.service.set_guard_options(True, [], OTHER)
        with self.assertRaises(RulesError):
            self.service.set_guard_options(True, ["wt0; flush ruleset"], OWNER)
        self.assertIsNone(self.backend.guard_options)

    def test_guard_file_format(self):
        import tempfile
        from unittest import mock

        tmp = Path(tempfile.mkdtemp()) / "pervius" / "guard.conf"
        with mock.patch.object(daemon, "GUARD_OPTIONS_PATH", str(tmp)):
            daemon.SystemBackend().write_guard_options(False, ("wt0", "eth1"))
        self.assertEqual(tmp.read_text(), "block-ipv6=no\nallowed-interfaces=wt0,eth1\n")
        self.assertEqual(tmp.stat().st_mode & 0o777, 0o644)


class ConfigureTests(ServiceTestCase):
    def test_configure_rebuilds_atomically_and_keeps_endpoints(self):
        self.armed()
        self.service.configure(True, ["wt0"], OWNER)
        script = self.last_script()
        self.assertTrue(script.startswith("table inet pervius_ks {}\ndelete table inet pervius_ks\n"))
        self.assertIn("192.0.2.10 . udp . 1194", script)
        self.assertIn("10.0.0.0/8", script)
        self.assertIn('"wt0"', script)
        self.assertEqual(self.backend.system_calls, 1)  # no new resolution

    def test_configure_requires_the_arming_user_or_root(self):
        self.armed()
        with self.assertRaises(daemon.PermissionDenied):
            self.service.configure(True, [], OTHER)
        self.service.configure(True, [], 0)

    def test_configure_requires_armed(self):
        with self.assertRaises(daemon.NotArmed):
            self.service.configure(True, [], OWNER)


class UpdateEndpointsTests(ServiceTestCase):
    def test_tunnel_up_uses_the_system_resolver_and_no_window(self):
        self.armed()
        self.backend.tunnel = True
        self.backend.system_result = Resolution(NEW, ())
        resolved = self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.assertEqual(resolved, NEW)
        self.assertEqual(self.backend.direct_calls, [])
        self.assertEqual(len(self.backend.nft_calls), 1)
        swap = self.last_script()
        self.assertIn("192.0.2.20 . udp . 1194", swap)
        self.assertNotIn("192.0.2.10", swap)
        self.assertNotIn("dns_window_v4 {", swap)

    def test_merge_keeps_the_current_endpoints(self):
        self.armed()
        self.backend.tunnel = True
        self.backend.system_result = Resolution(NEW, ())
        self.service.update_endpoints(MANAGED_UUID, False, OWNER)
        swap = self.last_script()
        self.assertIn("192.0.2.20 . udp . 1194", swap)
        self.assertIn("192.0.2.10 . udp . 1194", swap)

    def test_tunnel_down_opens_a_window_then_swaps_and_closes_it(self):
        self.armed()
        resolved = self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.assertEqual(resolved, NEW)
        self.assertEqual(self.backend.direct_calls, [("192.168.1.1",)])
        self.assertEqual(self.backend.system_calls, 1)  # only the arm
        window, swap = (call[1] for call in self.backend.nft_calls)
        self.assertEqual(window, "add element inet pervius_ks dns_window_v4 { 192.168.1.1 timeout 5s }\n")
        self.assertIn("flush set inet pervius_ks endpoints_v4", swap)
        self.assertTrue(swap.rstrip().endswith("flush set inet pervius_ks dns_window_v6"))

    def test_failed_resolution_leaves_the_set_untouched_and_closes_the_window(self):
        self.armed()
        self.backend.direct_error = RulesError("could not resolve any VPN server endpoint")
        with self.assertRaises(daemon.ResolveFailed):
            self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        scripts = [call[1] for call in self.backend.nft_calls]
        self.assertEqual(len(scripts), 2)
        self.assertIn("timeout 5s", scripts[0])
        self.assertEqual(scripts[1], "flush set inet pervius_ks dns_window_v4\nflush set inet pervius_ks dns_window_v6\n")
        self.assertEqual(self.service._endpoints, OLD)

    def test_failed_resolution_through_the_tunnel_falls_back_to_the_window(self):
        self.armed()
        self.backend.tunnel = True
        self.backend.system_error = RulesError("could not resolve any VPN server endpoint")
        resolved = self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.assertEqual(resolved, NEW)
        self.assertEqual(self.backend.direct_calls, [("192.168.1.1",)])

    def test_failed_resolution_everywhere_changes_nothing(self):
        self.armed()
        self.backend.tunnel = True
        self.backend.system_error = RulesError("could not resolve any VPN server endpoint")
        self.backend.direct_error = RulesError("could not resolve any VPN server endpoint")
        with self.assertLogs("pervius.killswitchd.daemon", level="WARNING") as logs:
            with self.assertRaises(daemon.ResolveFailed):
                self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.assertTrue(any("could not update the VPN server addresses" in line for line in logs.output))
        self.assertEqual(self.service._endpoints, OLD)

    def test_rejected_swap_keeps_the_old_endpoints(self):
        self.armed()
        self.backend.tunnel = True
        self.backend.system_result = Resolution(NEW, ())
        self.backend.fail_next_nft = True
        with self.assertRaises(daemon.ServiceError):
            self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.assertEqual(self.service._endpoints, OLD)

    def test_window_is_rate_limited(self):
        self.armed()
        self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.backend.now += 10
        with self.assertRaises(daemon.ResolveFailed):
            self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.backend.now += daemon.DNS_WINDOW_INTERVAL
        self.service.update_endpoints(MANAGED_UUID, True, OWNER)

    def test_no_window_without_the_cgroup_rule(self):
        self.backend.cgroup = None
        self.armed()
        with self.assertRaises(daemon.ResolveFailed):
            self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.assertEqual(self.backend.nft_calls, [])

    def test_no_window_without_link_resolvers(self):
        self.armed()
        self.backend.nameservers = ["127.0.0.53", "::1"]
        with self.assertRaises(daemon.ResolveFailed):
            self.service.update_endpoints(MANAGED_UUID, True, OWNER)
        self.assertEqual(self.backend.nft_calls, [])

    def test_authorization_matrix(self):
        self.armed()
        self.backend.tunnel = True
        with self.assertRaises(daemon.PermissionDenied):
            self.service.update_endpoints(MANAGED_UUID, True, OTHER)
        with self.assertRaises(daemon.PermissionDenied):
            self.service.update_endpoints("11111111-1111-1111-1111-111111111111", True, OWNER)
        self.service.update_endpoints(MANAGED_UUID, True, 0)

    def test_ownership_is_checked_like_arm(self):
        self.armed()
        self.backend.tunnel = True
        self.backend.profile_owner = "mallory"
        with self.assertRaises(daemon.PermissionDenied):
            self.service.update_endpoints(MANAGED_UUID, True, OWNER)

    def test_requires_armed(self):
        with self.assertRaises(daemon.NotArmed):
            self.service.update_endpoints(MANAGED_UUID, True, OWNER)

    def test_reply_carries_the_resolved_addresses_for_the_caller(self):
        self.armed()
        self.backend.tunnel = True
        self.backend.system_result = Resolution(NEW, ())
        self.service.caller_uid = lambda sender: OWNER
        self.service.authorize = lambda sender, uid: None
        reply = self.service.handle("UpdateEndpoints", (MANAGED_UUID, True), ":1.5").unpack()[0]
        self.assertEqual(reply["resolved"], [("192.0.2.20", 1194, "udp")])


class DisarmTests(ServiceTestCase):
    def test_only_owner_or_root_disarms(self):
        self.armed()
        with self.assertRaises(daemon.PermissionDenied):
            self.service.disarm(OTHER)
        self.service.disarm(OWNER)
        self.assertFalse(self.service.state_file.exists())
        self.assertEqual(self.backend.nft_calls[-1][0], ["delete", "table", "inet", "pervius_ks"])


class RecoveryTests(ServiceTestCase):
    def write_state(self, **overrides):
        state = {
            "version": 2,
            "armed": True,
            "uuid": MANAGED_UUID,
            "allow_lan": False,
            "interfaces": ["wt0"],
            "owner_uid": OWNER,
            "since": "2026-11-18T10:00:00+00:00",
            "endpoints": [{"address": "192.0.2.10", "port": 1194, "protocol": "udp"}],
        }
        state.update(overrides)
        self.service.state_file.parent.mkdir(parents=True, exist_ok=True)
        self.service.state_file.write_text(json.dumps(state))

    def test_surviving_table_is_rebuilt_atomically_for_the_new_cgroup(self):
        self.backend.tables.add("inet pervius_ks")
        self.write_state()
        self.service._recover_state()
        self.assertEqual(self.service._state, "armed")
        script = self.last_script()
        self.assertTrue(script.startswith("table inet pervius_ks {}\ndelete table inet pervius_ks\n"))
        self.assertIn('"wt0"', script)

    def test_version_one_state_is_upgraded(self):
        self.backend.tables.add("inet pervius_ks")
        self.write_state(version=1, interfaces=None)
        self.service._recover_state()
        self.assertEqual(self.service._state, "armed")
        self.assertNotIn("tun*", self.last_script())
        self.assertEqual(json.loads(self.service.state_file.read_text())["version"], 2)

    def test_table_without_state_fails_closed(self):
        self.backend.tables.add("inet pervius_ks")
        self.service._recover_state()
        self.assertEqual(self.service._state, "error")
        self.assertTrue(self.service._armed)
        self.assertEqual(self.backend.nft_calls, [])

    def test_state_without_table_is_reconstructed(self):
        self.write_state()
        self.service._recover_state()
        self.assertEqual(self.service._state, "armed")
        self.assertIn("inet pervius_ks", self.backend.tables)

    def test_tampered_state_is_refused(self):
        self.backend.tables.add("inet pervius_ks")
        self.write_state(interfaces=["wt0; flush ruleset"])
        self.service._recover_state()
        self.assertEqual(self.service._state, "error")
        self.write_state(uuid="11111111-1111-1111-1111-111111111111")
        self.service._recover_state()
        self.assertEqual(self.service._state, "error")

    def test_failed_rebuild_keeps_the_old_table(self):
        self.backend.tables.add("inet pervius_ks")
        self.write_state()
        self.backend.fail_next_nft = True
        self.service._recover_state()
        self.assertEqual(self.service._state, "error")
        self.assertTrue(self.service._armed)
        self.assertIn("inet pervius_ks", self.backend.tables)


class StaleGuardTests(ServiceTestCase):
    def test_stale_guard_is_removed_when_the_vpn_is_gone(self):
        self.backend.tables.update({"inet pervius_guard", "inet pervius_v6"})
        self.service._clear_stale_guard()
        self.assertEqual(
            [call[0] for call in self.backend.nft_calls],
            [["delete", "table", "inet", "pervius_guard"], ["delete", "table", "inet", "pervius_v6"]],
        )

    def test_live_guard_is_kept(self):
        self.backend.tables.add("inet pervius_guard")
        self.backend.vpn_active = True
        self.service._clear_stale_guard()
        self.assertEqual(self.backend.nft_calls, [])

    def test_status_reports_the_guard(self):
        self.assertFalse(self.service.status()["guard"].unpack())
        self.backend.tables.add("inet pervius_guard")
        self.assertTrue(self.service.status()["guard"].unpack())


class MergeTests(unittest.TestCase):
    def test_merge_is_capped_and_deduplicated(self):
        fresh = tuple(Endpoint(f"198.51.100.{i}", 1194, "udp") for i in range(1, 200))
        current = tuple(Endpoint(f"203.0.113.{i}", 1194, "udp") for i in range(1, 200))
        merged = daemon.merge_endpoints(fresh, current + fresh[:5])
        self.assertEqual(len(merged), rules.MAX_ENDPOINTS)
        self.assertEqual(merged[:199], fresh)


if __name__ == "__main__":
    unittest.main()
