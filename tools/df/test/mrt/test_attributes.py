"""
Phase 3, tier 1: attributes set by filters, no BGP peer.

Each prefix is a blackhole static route whose attributes are set by the import filter,
one attribute (or one attribute shape) per prefix. A failure points at BIRD's MRT
encoder (proto/mrt/mrt.c -> bgp_encode_attrs) and nothing else. One daemon and one
forced dump per table serve the whole module.

Expected bytes come from the RFC encodings, not from BIRD's output. Where this build
knowingly deviates, the case says which PLAN.md finding it pins:
  - a filter-set attribute has no flags to write back, so every flag byte is 0x00
    (finding 5), apart from the extended-length bit when the value needs it;
  - the MP_REACH_NLRI next hop of an IPv6 entry takes its flags from the NEXT_HOP
    attribute, so it is 0x00 too (finding 18);
  - IPv6 entries carry the next hop in the table-dump form of MP_REACH_NLRI (finding 2),
    IPv4 entries in NEXT_HOP (finding 3).
Known bugs (findings 4 and 13) are strict xfails: they assert the correct behaviour.
"""

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import pytest

import bgpdump
import birdlab
import mrt_reader as m

ip = ipaddress.ip_address
net = ipaddress.ip_network

EXT = m.FLAG_EXTENDED


def u32(*values) -> bytes:
    return b"".join(struct.pack("!I", v) for v in values)


def as_path(*segments) -> bytes:
    return b"".join(bytes([m.AS_SEQUENCE, len(s)]) + u32(*s) for s in segments)


def mp_reach(addr) -> bytes:
    raw = ip(addr).packed
    return bytes([len(raw)]) + raw


@dataclass
class Case:
    name: str
    prefix: str
    stmts: List[str]
    # exact attributes of the one RIB entry: (flags, code, value)
    attrs: Optional[List[Tuple[int, int, bytes]]] = None
    bgpdump: dict = field(default_factory=dict)     # bgpdump -m fields to check

    @property
    def table(self) -> str:
        return "t6" if ":" in self.prefix else "t4"


PATH_300 = list(range(64600, 64900))    # prepended in this order, so the path is reversed

CASES = [
    Case("origin_igp", "10.1.0.0/16", ["bgp_origin = ORIGIN_IGP;"],
         [(0x00, m.ORIGIN, b"\x00")], {"origin": "IGP"}),
    Case("origin_egp", "10.2.0.0/16", ["bgp_origin = ORIGIN_EGP;"],
         [(0x00, m.ORIGIN, b"\x01")], {"origin": "EGP"}),
    Case("origin_incomplete", "10.3.0.0/16", ["bgp_origin = ORIGIN_INCOMPLETE;"],
         [(0x00, m.ORIGIN, b"\x02")], {"origin": "INCOMPLETE"}),

    # Order kept, 32-bit ASN written as 4 bytes, one AS_SEQUENCE.
    Case("as_path", "10.4.0.0/16",
         ["bgp_path.prepend(64512);", "bgp_path.prepend(4200000000);", "bgp_path.prepend(65001);"],
         [(0x00, m.AS_PATH, as_path([65001, 4200000000, 64512]))],
         {"as_path": "65001 4200000000 64512"}),
    # 300 ASNs: prepending fills the front segment up to 255 ASNs, then opens a new one
    # in front (nest/a-path.c:208), so 45 + 255; the attribute (1204 bytes) needs the
    # extended length.
    Case("as_path_300", "10.5.0.0/16",
         [f"bgp_path.prepend({a});" for a in PATH_300],
         [(EXT, m.AS_PATH, as_path(PATH_300[299:254:-1], PATH_300[254::-1]))],
         {"as_path": " ".join(str(a) for a in reversed(PATH_300))}),

    Case("next_hop_v4", "10.6.0.0/16", ["bgp_next_hop = 10.99.0.6;"],
         [(0x00, m.NEXT_HOP, ip("10.99.0.6").packed)], {"next_hop": "10.99.0.6"}),

    Case("med_0", "10.8.0.0/16", ["bgp_med = 0;"], [(0x00, m.MED, u32(0))], {"med": 0}),
    Case("med_1", "10.9.0.0/16", ["bgp_med = 1;"], [(0x00, m.MED, u32(1))], {"med": 1}),
    Case("med_max", "10.10.0.0/16", ["bgp_med = 4294967295;"],
         [(0x00, m.MED, u32(0xFFFFFFFF))], {"med": 4294967295}),
    Case("local_pref", "10.11.0.0/16", ["bgp_local_pref = 300;"],
         [(0x00, m.LOCAL_PREF, u32(300))], {"local_pref": 300}),

    # Insertion order is kept: MRT encoding skips the sort BGP export applies.
    Case("community", "10.12.0.0/16",
         ["bgp_community.add((65000,1));", "bgp_community.add((0,0));",
          "bgp_community.add((65535,65535));"],
         [(0x00, m.COMMUNITY, u32(0xFDE80001, 0, 0xFFFFFFFF))],
         {"communities": "65000:1 0:0 65535:65535"}),
    # 63 communities are 252 bytes: plain length. 64 are 256: extended length.
    Case("community_63", "10.13.0.0/16",
         [f"bgp_community.add((65000,{i}));" for i in range(1, 64)],
         [(0x00, m.COMMUNITY, u32(*[(65000 << 16) | i for i in range(1, 64)]))]),
    Case("community_64", "10.14.0.0/16",
         [f"bgp_community.add((65000,{i}));" for i in range(1, 65)],
         [(EXT, m.COMMUNITY, u32(*[(65000 << 16) | i for i in range(1, 65)]))]),

    Case("originator_id", "10.15.0.0/16", ["bgp_originator_id = 192.0.2.15;"],
         [(0x00, m.ORIGINATOR_ID, ip("192.0.2.15").packed)]),
    Case("cluster_list", "10.16.0.0/16",
         ["bgp_cluster_list.add(192.0.2.16);", "bgp_cluster_list.add(192.0.2.17);"],
         [(0x00, m.CLUSTER_LIST, ip("192.0.2.16").packed + ip("192.0.2.17").packed)]),

    # Route targets / origins: 2-octet AS (type 0x00), IPv4 (0x01), 4-octet AS (0x02).
    Case("ext_community", "10.17.0.0/16",
         ["bgp_ext_community.add((rt, 65000, 100));",
          "bgp_ext_community.add((ro, 192.0.2.1, 7));",
          "bgp_ext_community.add((rt, 4200000000, 5));"],
         [(0x00, m.EXT_COMMUNITY, bytes.fromhex(
             "0002fde800000064" "0103c00002010007" "0202fa56ea000005"))]),
    Case("large_community", "10.18.0.0/16",
         ["bgp_large_community.add((4200000000, 1, 2));",
          "bgp_large_community.add((1, 4294967295, 0));"],
         [(0x00, m.LARGE_COMMUNITY, u32(4200000000, 1, 2, 1, 0xFFFFFFFF, 0))]),

    # Everything at once: attributes come out in ascending type code.
    Case("all_v4", "10.19.0.0/16",
         ["bgp_origin = ORIGIN_IGP;", "bgp_path.prepend(65001);", "bgp_next_hop = 10.99.0.19;",
          "bgp_med = 5;", "bgp_local_pref = 50;", "bgp_community.add((65000,19));",
          "bgp_ext_community.add((rt, 65000, 19));", "bgp_large_community.add((65000, 19, 19));"],
         [(0x00, m.ORIGIN, b"\x00"),
          (0x00, m.AS_PATH, as_path([65001])),
          (0x00, m.NEXT_HOP, ip("10.99.0.19").packed),
          (0x00, m.MED, u32(5)),
          (0x00, m.LOCAL_PREF, u32(50)),
          (0x00, m.COMMUNITY, u32(0xFDE80013)),
          (0x00, m.EXT_COMMUNITY, bytes.fromhex("0002fde800000013")),
          (0x00, m.LARGE_COMMUNITY, u32(65000, 19, 19))],
         {"origin": "IGP", "as_path": "65001", "next_hop": "10.99.0.19", "med": 5,
          "local_pref": 50, "communities": "65000:19"}),

    # IPv6: the next hop is the table-dump form of MP_REACH_NLRI, flags 0x00.
    Case("next_hop_v6", "2001:db8:20::/48", ["bgp_next_hop = 2001:db8::20;"],
         [(0x00, m.MP_REACH_NLRI, mp_reach("2001:db8::20"))], {"next_hop": "2001:db8::20"}),
    # An IPv4 next hop on an IPv6 route: BIRD holds it IPv4-mapped, the dump writes that.
    Case("next_hop_v4_on_v6", "2001:db8:21::/48", ["bgp_next_hop = 10.99.0.21;"],
         [(0x00, m.MP_REACH_NLRI, mp_reach("::ffff:10.99.0.21"))],
         {"next_hop": "::ffff:10.99.0.21"}),
    Case("all_v6", "2001:db8:22::/48",
         ["bgp_origin = ORIGIN_EGP;", "bgp_path.prepend(65002);", "bgp_next_hop = 2001:db8::22;",
          "bgp_med = 22;", "bgp_community.add((65000,22));",
          "bgp_large_community.add((65000, 22, 22));"],
         [(0x00, m.ORIGIN, b"\x01"),
          (0x00, m.AS_PATH, as_path([65002])),
          (0x00, m.MED, u32(22)),
          (0x00, m.COMMUNITY, u32(0xFDE80016)),
          (0x00, m.LARGE_COMMUNITY, u32(65000, 22, 22)),
          (0x00, m.MP_REACH_NLRI, mp_reach("2001:db8::22"))],
         {"origin": "EGP", "as_path": "65002", "next_hop": "2001:db8::22", "med": 22,
          "communities": "65000:22"}),
]

# Prefix encodings: routes without attributes, so the entry is just the prefix.
PREFIXES_V4 = ["0.0.0.0/0", "192.0.2.1/32", "100.64.0.0/10", "198.18.128.0/17",
               "203.0.113.128/25"]
PREFIXES_V6 = ["::/0", "2001:db8:ff::1/128", "2001:db8:8000::/33", "8000::/1"]

# Finding 4: an IPv6 next hop on an IPv4 route.
V6_ON_V4 = Case("next_hop_v6_on_v4", "10.7.0.0/16", ["bgp_next_hop = 2001:db8::7;"])

# Finding 13: table t6s interleaves routes with a next hop (every fourth prefix) and
# routes with only a MED, so the dump order is sure to put some of the latter after the
# former (test_no_stale_next_hop checks that it did).
STALE_ALL = [f"2001:db8:7{i:x}00::/40" for i in range(16)]
STALE_WITH_NH = STALE_ALL[::4]
STALE_WITHOUT_NH = [p for p in STALE_ALL if p not in STALE_WITH_NH]


def render(log) -> str:
    def filter_block(name, cases):
        body = "\n".join(f"  if net = {c.prefix} then {{ {' '.join(c.stmts)} }}" for c in cases)
        return f"filter {name} {{\n{body}\n  accept;\n}}\n"

    def static(name, afi, table, prefixes, filt):
        routes = "".join(f"  route {p} blackhole;\n" for p in prefixes)
        return (f"protocol static {name} {{\n  {afi} {{ table {table}; import filter {filt}; }};\n"
                f"{routes}}}\n")

    v4 = [c for c in CASES if c.table == "t4"] + [V6_ON_V4]
    v6 = [c for c in CASES if c.table == "t6"]
    stale = ([Case("nh", p, [f"bgp_next_hop = 2001:db8::5{i};"]) for i, p in enumerate(STALE_WITH_NH)]
             + [Case("med", p, ["bgp_med = 13;"]) for p in STALE_WITHOUT_NH])
    return (birdlab.prolog("10.0.0.1", log)
            + "ipv4 table t4;\nipv6 table t6;\nipv6 table t6s;\n"
            + filter_block("f4", v4) + filter_block("f6", v6) + filter_block("f6s", stale)
            + static("s4", "ipv4", "t4", [c.prefix for c in v4] + PREFIXES_V4, "f4")
            + static("s6", "ipv6", "t6", [c.prefix for c in v6] + PREFIXES_V6, "f6")
            + static("s6s", "ipv6", "t6s", STALE_WITH_NH + STALE_WITHOUT_NH, "f6s"))


@pytest.fixture(scope="module")
def dut(lab, bird_bin):
    dut = lab.bird("dut", render(lab.log_path("dut")), bird_bin)
    dut.wait_routes("t4", len([c for c in CASES if c.table == "t4"]) + 1 + len(PREFIXES_V4))
    dut.wait_routes("t6", len([c for c in CASES if c.table == "t6"]) + len(PREFIXES_V6))
    dut.wait_routes("t6s", len(STALE_WITH_NH) + len(STALE_WITHOUT_NH))
    return dut


@pytest.fixture(scope="module")
def dumps(dut, tmp_path_factory):
    """table -> (path, parsed dump)"""
    d = tmp_path_factory.mktemp("dumps")
    out = {}
    for table in ("t4", "t6", "t6s"):
        path = dut.mrt_dump(table, d / f"{table}.mrt")
        out[table] = (path, m.read(path))
    return out


def entry(dumps, prefix) -> m.RibEntry:
    [e] = dumps["t6" if ":" in prefix else "t4"][1].rib(prefix).entries
    return e


def attrs_of(e: m.RibEntry):
    return [(a.flags, a.code, a.value) for a in e.attributes]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_attribute_bytes(dumps, case):
    e = entry(dumps, case.prefix)
    assert e.peer_index == 0
    assert attrs_of(e) == case.attrs


@pytest.mark.parametrize("case", [c for c in CASES if c.bgpdump], ids=lambda c: c.name)
def test_bgpdump_view(dumps, bgpdump_bin, case):
    result = bgpdump.run(dumps[case.table][0], bgpdump_bin)
    assert result.problems == []
    row = result.row(case.prefix)
    assert {k: getattr(row, k) for k in case.bgpdump} == case.bgpdump


def test_ipv4_entries_never_carry_mp_reach(dumps):
    """Finding 3: IPv4 entries use NEXT_HOP; MP_REACH_NLRI is for the other families."""
    for rib in dumps["t4"][1].ribs():
        for e in rib.entries:
            assert e.attr(m.MP_REACH_NLRI) is None, rib.network


@pytest.mark.parametrize("prefix", PREFIXES_V4 + PREFIXES_V6)
def test_prefix_encoding(dumps, prefix):
    table = "t6" if ":" in prefix else "t4"
    rib = dumps[table][1].rib(prefix)
    assert rib.record.subtype == (m.RIB_IPV6_UNICAST if table == "t6" else m.RIB_IPV4_UNICAST)
    [e] = rib.entries
    assert e.attributes == []


def test_whole_tables_dumped(dumps):
    for table, cases, extra in (("t4", [c for c in CASES if c.table == "t4"] + [V6_ON_V4], PREFIXES_V4),
                                ("t6", [c for c in CASES if c.table == "t6"], PREFIXES_V6)):
        f = dumps[table][1]
        [section] = f.sections
        assert section.peer_table.view_name == table
        assert [(p.peer_type, p.bgp_id, p.ip, p.asn) for p in section.peer_table.peers] == [
            birdlab.MRT_FAKE_PEER]
        assert {r.network for r in section.ribs} == {net(c.prefix) for c in cases} | {net(p) for p in extra}


@pytest.mark.xfail(strict=True, reason="finding 4: an IPv6 next hop on an IPv4 route is dropped "
                                       "(proto/bgp/attrs.c:291, 'FIXME: skip IPv6 next hops')")
def test_ipv6_next_hop_on_ipv4_route(dumps):
    assert entry(dumps, V6_ON_V4.prefix).next_hops() == [ip("2001:db8::7")]


@pytest.mark.xfail(strict=True, reason="finding 13: bws->mp_next_hop is not reset between RIB "
                                       "entries, so an entry without a next hop inherits one")
def test_no_stale_next_hop(dumps):
    ribs = list(dumps["t6s"][1].ribs())
    order = [str(r.network) for r in ribs]
    first_nh = min(order.index(p) for p in STALE_WITH_NH)
    followers = [p for p in order[first_nh + 1:] if p in STALE_WITHOUT_NH]
    # Precondition, so the test cannot pass vacuously: some route without a next hop
    # is dumped after one with a next hop.
    assert followers, f"dump order gives the bug no chance: {order}"
    for rib in ribs:
        if str(rib.network) in STALE_WITHOUT_NH:
            [e] = rib.entries
            assert e.codes() == [m.MED], f"{rib.network}: {e.next_hops()}"
