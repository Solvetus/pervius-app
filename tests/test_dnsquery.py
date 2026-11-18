"""The kill-switch service's direct DNS lookups reject anything suspicious."""

from __future__ import annotations

import socket
import unittest

try:
    import dns.flags
    import dns.message
    import dns.rcode
    import dns.rdatatype
    import dns.rrset

    from pervius.killswitchd import dnsquery
except ImportError:  # pragma: no cover - python3-dnspython not installed
    dns = None

from pervius.killswitchd.rules import RulesError

SERVER = "192.0.2.53"
HOST = "lis-c01.vpn.example.com"


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class FakeSocket:
    """Records what the code sends; replies are produced per query."""

    instances: list["FakeSocket"] = []

    def __init__(self, family, socktype, responder, clock):
        self.family = family
        self.socktype = socktype
        self.responder = responder
        self.clock = clock
        self.bound = None
        self.sent = []
        self.queue = []
        self.closed = False
        self.timeouts = []
        FakeSocket.instances.append(self)

    def bind(self, address):
        self.bound = address

    def sendto(self, data, address):
        self.sent.append((data, address))
        query = dns.message.from_wire(data)
        self.queue.extend(self.responder(query, address))

    def settimeout(self, value):
        self.timeouts.append(value)

    def recvfrom(self, size):
        if not self.queue:
            self.clock.now += self.timeouts[-1]
            raise socket.timeout()
        data, source = self.queue.pop(0)
        return data[:size], source

    def close(self):
        self.closed = True


def answer(query, *records, rcode=None, flags=0, qid=None, question=None):
    reply = dns.message.make_response(query)
    if rcode is not None:
        reply.set_rcode(rcode)
    reply.flags |= flags
    if qid is not None:
        reply.id = qid
    if question is not None:
        reply.question = [question]
    for name, rdtype, values in records:
        reply.answer.append(dns.rrset.from_text(name, 300, "IN", rdtype, *values))
    return reply.to_wire()


def addresses_for(query):
    qname = str(query.question[0].name)
    rdtype = query.question[0].rdtype
    if rdtype == dns.rdatatype.A:
        return [(qname, "A", ["185.15.58.10"])]
    return [(qname, "AAAA", ["2a00:1450::10"])]


@unittest.skipIf(dns is None, "python3-dnspython is not installed")
class DirectLookupTests(unittest.TestCase):
    def setUp(self):
        FakeSocket.instances = []
        self.clock = Clock()

    def resolve(self, responder, servers=(SERVER,), remotes=((HOST, 1194),)):
        factory = lambda family, socktype: FakeSocket(family, socktype, responder, self.clock)  # noqa: E731
        return dnsquery.resolve_remotes_direct(
            remotes, "udp", servers, socket_factory=factory, clock=self.clock
        )

    def good(self, query, address):
        return [(answer(query, *addresses_for(query)), (SERVER, 53))]

    def test_valid_answers_become_endpoints(self):
        result = self.resolve(self.good)
        self.assertEqual(
            sorted((e.address, e.port, e.protocol) for e in result.endpoints),
            [("185.15.58.10", 1194, "udp"), ("2a00:1450::10", 1194, "udp")],
        )

    def test_only_a_and_aaaa_are_asked_with_random_ids_and_ephemeral_ports(self):
        self.resolve(self.good)
        queries = [dns.message.from_wire(s.sent[0][0]) for s in FakeSocket.instances]
        self.assertEqual(
            [q.question[0].rdtype for q in queries], [dns.rdatatype.A, dns.rdatatype.AAAA]
        )
        self.assertNotEqual(queries[0].id, queries[1].id)
        for sock in FakeSocket.instances:
            self.assertEqual(sock.bound, ("0.0.0.0", 0))
            self.assertEqual(sock.sent[0][1], (SERVER, 53))
            self.assertTrue(sock.closed)
        with self.assertRaises(dnsquery.DnsLookupError):
            dnsquery.query(HOST, dns.rdatatype.TXT, [SERVER], deadline=self.clock() + 5)

    def test_cname_chain_inside_the_reply_is_followed(self):
        def responder(query, _address):
            qname = str(query.question[0].name)
            if query.question[0].rdtype != dns.rdatatype.A:
                return [(answer(query), (SERVER, 53))]
            return [
                (
                    answer(
                        query,
                        (qname, "CNAME", ["edge.example.net."]),
                        ("edge.example.net.", "A", ["185.15.58.20"]),
                    ),
                    (SERVER, 53),
                )
            ]

        result = self.resolve(responder)
        self.assertEqual([e.address for e in result.endpoints], ["185.15.58.20"])

    def assertRejected(self, responder):
        with self.assertRaises(RulesError):
            self.resolve(responder)

    def test_wrong_source_address_is_ignored(self):
        self.assertRejected(
            lambda q, a: [(answer(q, *addresses_for(q)), ("203.0.113.66", 53))]
        )

    def test_wrong_source_port_is_ignored(self):
        self.assertRejected(lambda q, a: [(answer(q, *addresses_for(q)), (SERVER, 5353))])

    def test_spoofed_id_is_ignored(self):
        self.assertRejected(
            lambda q, a: [(answer(q, *addresses_for(q), qid=(q.id + 1) % 65536), (SERVER, 53))]
        )

    def test_spoof_then_genuine_reply_uses_only_the_genuine_one(self):
        def responder(query, _address):
            spoof = answer(query, (str(query.question[0].name), "A", ["203.0.113.66"]))
            return [(spoof, ("203.0.113.66", 53)), *self.good(query, _address)]

        result = self.resolve(responder)
        self.assertNotIn("203.0.113.66", [e.address for e in result.endpoints])

    def test_mismatched_question_is_ignored(self):
        def responder(query, _address):
            other = dns.message.make_query("evil.example.org", query.question[0].rdtype).question[0]
            return [(answer(query, ("evil.example.org.", "A", ["203.0.113.66"]), question=other), (SERVER, 53))]

        self.assertRejected(responder)

    def test_truncated_reply_is_rejected(self):
        self.assertRejected(
            lambda q, a: [(answer(q, *addresses_for(q), flags=dns.flags.TC), (SERVER, 53))]
        )

    def test_oversized_reply_is_rejected(self):
        def responder(query, _address):
            values = [f"198.51.{i // 250}.{i % 250 + 1}" for i in range(120)]
            wire = answer(query, (str(query.question[0].name), "A", values))
            self.assertGreater(len(wire), dnsquery.MAX_REPLY_BYTES)
            return [(wire, (SERVER, 53))]

        self.assertRejected(responder)

    def test_malformed_wire_is_ignored(self):
        def responder(query, _address):
            wire = bytearray(answer(query, *addresses_for(query)))
            return [(bytes(wire[:-3]), (SERVER, 53)), (b"\x00garbage", (SERVER, 53))]

        self.assertRejected(responder)

    def test_servfail_and_nxdomain_give_no_endpoints(self):
        self.assertRejected(lambda q, a: [(answer(q, rcode=dns.rcode.SERVFAIL), (SERVER, 53))])
        self.assertRejected(lambda q, a: [(answer(q, rcode=dns.rcode.NXDOMAIN), (SERVER, 53))])

    def test_non_address_records_are_ignored(self):
        def responder(query, _address):
            name = str(query.question[0].name)
            return [(answer(query, (name, "TXT", ['"185.15.58.10"'])), (SERVER, 53))]

        self.assertRejected(responder)

    def test_unusable_addresses_are_dropped(self):
        def responder(query, _address):
            name = str(query.question[0].name)
            if query.question[0].rdtype == dns.rdatatype.A:
                return [(answer(query, (name, "A", ["0.0.0.0", "224.0.0.1", "185.15.58.30"])), (SERVER, 53))]
            return [(answer(query), (SERVER, 53))]

        result = self.resolve(responder)
        self.assertEqual([e.address for e in result.endpoints], ["185.15.58.30"])
        self.assertTrue(result.warnings)

    def test_answers_are_capped_per_name_and_family(self):
        """Regression: every A/AAAA record became an allowlist entry."""

        def responder(query, _address):
            name = str(query.question[0].name)
            if query.question[0].rdtype == dns.rdatatype.A:
                return [(answer(query, (name, "A", [f"185.15.58.{i}" for i in range(1, 30)])), (SERVER, 53))]
            return [(answer(query, (name, "AAAA", [f"2a00:1450::{i:x}" for i in range(1, 30)])), (SERVER, 53))]

        result = self.resolve(responder)
        self.assertEqual(len([e for e in result.endpoints if ":" not in e.address]), 4)
        self.assertEqual(len([e for e in result.endpoints if ":" in e.address]), 4)
        self.assertTrue(any("at most 4 per family" in w for w in result.warnings))

    def test_non_public_answers_are_dropped(self):
        def responder(query, _address):
            name = str(query.question[0].name)
            if query.question[0].rdtype == dns.rdatatype.A:
                values = ["10.0.0.1", "192.168.1.1", "100.64.0.1", "192.0.2.10", "127.0.0.1"]
                return [(answer(query, (name, "A", values)), (SERVER, 53))]
            return [(answer(query, (name, "AAAA", ["fd00::1", "fe80::1", "::1"])), (SERVER, 53))]

        with self.assertRaises(RulesError):
            self.resolve(responder)

    def test_scoped_literal_remote_is_rejected(self):
        with self.assertRaises(RulesError):
            self.resolve(lambda q, a: [], remotes=(("fe80::1%x};flush;{", 443),))

    def test_next_server_is_tried_after_a_timeout(self):
        def responder(query, address):
            if address[0] == SERVER:
                return []
            return [(answer(query, *addresses_for(query)), (address[0], 53))]

        result = self.resolve(responder, servers=(SERVER, "192.0.2.54"))
        self.assertEqual(len(result.endpoints), 2)

    def test_overall_budget_is_enforced(self):
        self.assertRejected(lambda q, a: [])
        # Two record types against one silent server: 2 s each, within 5 s total.
        self.assertLessEqual(self.clock.now - 100.0, dnsquery.TOTAL_TIMEOUT + 0.001)
        for sock in FakeSocket.instances:
            self.assertLessEqual(sock.timeouts[0], dnsquery.PER_SERVER_TIMEOUT)

    def test_ip_literal_remotes_need_no_query(self):
        result = self.resolve(lambda q, a: [], remotes=(("185.15.58.40", 443),))
        self.assertEqual([e.address for e in result.endpoints], ["185.15.58.40"])
        self.assertEqual(FakeSocket.instances, [])

    def test_no_resolver_is_an_error(self):
        with self.assertRaises(RulesError):
            self.resolve(self.good, servers=())


if __name__ == "__main__":
    unittest.main()
