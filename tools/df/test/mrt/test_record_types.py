"""
Phase 4: VPN routes, which the fork writes as TABLE_DUMP_V2 RIB_GENERIC records
(AFI 1/2, SAFI 128; proto/mrt/mrt.c:446-529). PLAN.md findings 11, 12 and 14.

Part A: static vpn4/vpn6 routes with filter-set attributes, dumped with `mrt dump`, so
the record layout can be checked byte for byte. Part B: VPN routes received over BGP by
the production config (prodconf.py, a session with vpn4/vpn6 families), dumped by the
periodic `protocol mrt` timer.

What the fork writes, and what bgpdump makes of it:
  - NLRI: length byte = prefix length + 88 (one 3-byte label, 8-byte RD), so bgpdump
    prints a VPNv4 /24 as /112;
  - label: always 0x000001 (label 0, bottom of stack), whatever label was received;
  - RD: BIRD's in-memory u64, i.e. little-endian on this x86 host, with the IP part of
    type-1 RDs byte-swapped once more (mrt_make_rd_u64) so bgpdump prints it right.
    None of the three RD types is in RFC 4364 byte order;
  - next hop: the table-dump MP_REACH_NLRI, 16 bytes, IPv4 next hops IPv4-mapped.
"""

import ipaddress
import struct
import time
from dataclasses import dataclass
from typing import List

import pytest

import bgpdump
import birdlab
import mrt_reader as m
import prodconf

ip = ipaddress.ip_address
net = ipaddress.ip_network

LABEL_0_BOS = 0x000001


@dataclass
class Rd:
    text: str            # as BIRD's config and bgpdump write it
    fork: bytes          # as the fork writes it
    rfc: bytes           # RFC 4364 byte order, for reference


RD0 = Rd("100:100", bytes.fromhex("6400000064000000"), bytes.fromhex("0000006400000064"))
RD0B = Rd("65000:1", bytes.fromhex("01000000e8fd0000"), bytes.fromhex("0000fde800000001"))
RD1 = Rd("10.0.0.2:7", bytes.fromhex("07000a0000020100"), bytes.fromhex("00010a0000020007"))
RD2 = Rd("4200000000:9", bytes.fromhex("090000ea56fa0200"), bytes.fromhex("0002fa56ea000009"))


def u32(*values) -> bytes:
    return b"".join(struct.pack("!I", v) for v in values)


def mp_reach(addr) -> bytes:
    raw = ip(addr).packed
    return bytes([len(raw)]) + raw


# -- part A: static VPN routes ----------------------------------------------------------

@dataclass
class VpnRoute:
    rd: Rd
    prefix: str

    @property
    def config(self) -> str:
        return f"{self.rd.text} {self.prefix}"


# The same IP prefix under two RDs is two routes, two records.
VPN4 = [VpnRoute(RD0, "10.10.0.0/24"), VpnRoute(RD0B, "10.10.0.0/24"),
        VpnRoute(RD1, "10.20.0.0/24"), VpnRoute(RD2, "10.30.0.0/24"),
        VpnRoute(RD0, "10.40.1.0/25"), VpnRoute(RD0, "10.50.0.1/32")]
VPN6 = [VpnRoute(RD0, "2001:db8:10::/48"), VpnRoute(RD1, "2001:db8:20::/48"),
        VpnRoute(RD2, "2001:db8:30::/64"), VpnRoute(RD0, "2001:db8:40::1/128")]

NH4, NH6 = "10.99.0.10", "2001:db8::10"
ATTRS_A = {
    "vpn4": [(0x00, m.ORIGIN, b"\x00"),
             (0x00, m.AS_PATH, bytes([m.AS_SEQUENCE, 1]) + u32(65010)),
             (0x00, m.COMMUNITY, u32(0xFDE8000A)),
             (0x00, m.MP_REACH_NLRI, mp_reach(f"::ffff:{NH4}"))],
    "vpn6": [(0x00, m.ORIGIN, b"\x00"),
             (0x00, m.AS_PATH, bytes([m.AS_SEQUENCE, 1]) + u32(65010)),
             (0x00, m.COMMUNITY, u32(0xFDE8000A)),
             (0x00, m.MP_REACH_NLRI, mp_reach(NH6))],
}
IP4_ROUTES = ["10.60.0.0/16"]
IP6_ROUTES = ["2001:db8:60::/48"]


def render_a(log, dumpdir) -> str:
    def fset(nh):
        return ("bgp_origin = ORIGIN_IGP; bgp_path.prepend(65010); "
                f"bgp_community.add((65000,10)); bgp_next_hop = {nh}; accept;")
    return (birdlab.prolog("10.0.0.1", log) + "debug protocols { events };\n"
            + "ipv4 table t4;\nipv6 table t6;\nvpn4 table v4vpn;\nvpn6 table v6vpn;\n"
            + f"filter f4 {{ {fset(NH4)} }}\nfilter f6 {{ {fset(NH6)} }}\n"
            + "protocol static sv4 {\n  vpn4 { table v4vpn; import filter f4; };\n"
            + "".join(f"  route {r.config} blackhole;\n" for r in VPN4) + "}\n"
            + "protocol static sv6 {\n  vpn6 { table v6vpn; import filter f6; };\n"
            + "".join(f"  route {r.config} blackhole;\n" for r in VPN6) + "}\n"
            + "protocol static s4 {\n  ipv4 { table t4; import filter f4; };\n"
            + "".join(f"  route {p} blackhole;\n" for p in IP4_ROUTES) + "}\n"
            + "protocol static s6 {\n  ipv6 { table t6; import filter f6; };\n"
            + "".join(f"  route {p} blackhole;\n" for p in IP6_ROUTES) + "}\n"
            # Finding 14: ADD-PATH dumps. Only the protocol form has `always add path`.
            + f'protocol mrt ap_vpn4 {{ table v4vpn; filename "{dumpdir}/ap_vpn4.mrt"; '
              f"period 1; always add path on; }}\n"
            + f'protocol mrt ap_ipv4 {{ table t4; filename "{dumpdir}/ap_ipv4.mrt"; '
              f"period 1; always add path on; }}\n")


@pytest.fixture(scope="module")
def static_vpn(lab, bird_bin, tmp_path_factory):
    """(dut, dumps): dumps maps a name to the dump's path."""
    dumpdir = tmp_path_factory.mktemp("static_vpn")
    dut = lab.bird("dut", render_a(lab.log_path("dut"), dumpdir), bird_bin)
    for table, n in (("v4vpn", len(VPN4)), ("v6vpn", len(VPN6)),
                     ("t4", len(IP4_ROUTES)), ("t6", len(IP6_ROUTES))):
        dut.wait_routes(table, n)
    # The ADD-PATH protocols dump every second: wait for one that started after the
    # routes were in, then stop them so the files stay put.
    since = dut.mrt_dump_events()
    dut.wait_periodic_dumps(since)
    for proto in since:
        dut.disable(proto)
    dumps = {"ap_vpn4": dumpdir / "ap_vpn4.mrt", "ap_ipv4": dumpdir / "ap_ipv4.mrt"}
    for table in ("v4vpn", "v6vpn"):
        dumps[table] = dut.mrt_dump(table, dumpdir / f"{table}.mrt")
    dumps["wildcard"] = dut.mrt_dump('"*"', dumpdir / "wildcard.mrt")
    return dut, dumps


def vpn_rib(f: m.MrtFile, route: VpnRoute) -> m.Rib:
    ribs = [r for r in f.ribs()
            if r.network == net(route.prefix) and r.prefix.rd == route.rd.fork]
    assert len(ribs) == 1, f"{len(ribs)} records for {route.config}"
    return ribs[0]


def family(route: VpnRoute) -> str:
    return "vpn6" if ":" in route.prefix else "vpn4"


A_ROUTES = VPN4 + VPN6
A_IDS = [f"{family(r)}-{r.config}" for r in A_ROUTES]


@pytest.mark.parametrize("route", A_ROUTES, ids=A_IDS)
def test_record_layout(static_vpn, route):
    table = "v6vpn" if family(route) == "vpn6" else "v4vpn"
    rib = vpn_rib(m.read(static_vpn[1][table]), route)
    assert rib.record.subtype == m.RIB_GENERIC
    assert (rib.afi, rib.safi) == ((m.AFI_IPV6 if family(route) == "vpn6" else m.AFI_IPV4),
                                   m.SAFI_MPLS_VPN)
    assert rib.prefix.labels == [LABEL_0_BOS]
    assert rib.prefix.length_bits == net(route.prefix).prefixlen + 88
    assert rib.prefix.rd == route.rd.fork
    assert rib.prefix.rd != route.rd.rfc
    [e] = rib.entries
    assert e.peer_index == 0
    assert [(a.flags, a.code, a.value) for a in e.attributes] == ATTRS_A[family(route)]


@pytest.mark.parametrize("table,routes", [("v4vpn", VPN4), ("v6vpn", VPN6)])
def test_whole_vpn_table_dumped(static_vpn, table, routes):
    f = m.read(static_vpn[1][table])
    [section] = f.sections
    assert section.peer_table.view_name == table
    assert sorted((r.prefix.rd, r.network) for r in section.ribs) == sorted(
        (x.rd.fork, net(x.prefix)) for x in routes)


@pytest.mark.parametrize("route", A_ROUTES, ids=A_IDS)
def test_bgpdump_view(static_vpn, bgpdump_bin, route):
    table = "v6vpn" if family(route) == "vpn6" else "v4vpn"
    result = bgpdump.run(static_vpn[1][table], bgpdump_bin)
    assert result.problems == []
    n = net(route.prefix)
    rows = [r for r in result.rows
            if r.rd == route.rd.text and r.prefix == f"{n.network_address}/{n.prefixlen + 88}"]
    assert len(rows) == 1, [r.line for r in result.rows]
    row = rows[0]
    assert (row.afi, row.safi) == ((2 if family(route) == "vpn6" else 1), 128)
    assert (row.peer_ip, row.peer_as) == ("::", 0)
    assert (row.as_path, row.origin, row.communities) == ("65010", "IGP", "65000:10")
    assert row.next_hop == (NH6 if family(route) == "vpn6" else f"::ffff:{NH4}")


def test_addpath_ipv4_dump(static_vpn):
    """The control for finding 14: an IPv4 table with `always add path` is fine."""
    f = m.read(static_vpn[1]["ap_ipv4"])
    ribs = list(f.ribs())
    assert {r.network for r in ribs} == {net(p) for p in IP4_ROUTES}
    for rib in ribs:
        assert rib.record.subtype == m.RIB_IPV4_UNICAST_ADDPATH
        [e] = rib.entries
        assert e.path_id == 0                       # static routes have no path ID
        assert e.get(m.NEXT_HOP) == ip(NH4)


@pytest.mark.xfail(strict=True, reason="finding 14: VPN + ADD-PATH keeps subtype RIB_GENERIC "
                                       "but writes a path ID (mrt.c:564, 640)")
def test_addpath_vpn_dump(static_vpn):
    # bgpdump prints these records without a warning, with every attribute lost (empty
    # path, INCOMPLETE, next hop 255.255.255.255): only the strict reader notices.
    f = m.read(static_vpn[1]["ap_vpn4"])
    ribs = list(f.ribs())
    assert {(r.prefix.rd, r.network) for r in ribs} == {(x.rd.fork, net(x.prefix)) for x in VPN4}
    for rib in ribs:
        [e] = rib.entries
        assert [(a.flags, a.code, a.value) for a in e.attributes] == ATTRS_A["vpn4"]


@pytest.mark.xfail(strict=True, reason="finding 12: a table pattern only matches ipv4/ipv6 "
                                       "tables (mrt.c:230-232), VPN tables are skipped")
def test_wildcard_dump_includes_vpn_tables(static_vpn):
    views = [s.peer_table.view_name for s in m.read(static_vpn[1]["wildcard"]).sections]
    # Precondition: the pattern dump happened and covered the IP tables.
    assert {"t4", "t6"} <= set(views), views
    assert {"v4vpn", "v6vpn"} <= set(views), views


# -- part B: VPN over BGP, production config -------------------------------------------

PEER_AS = 200
MRT_PERIOD = 2
VPN4_B = [VpnRoute(RD0, "10.70.0.0/24"), VpnRoute(RD1, "10.71.0.0/24"),
          VpnRoute(RD2, "10.72.0.0/24")]
VPN6_B = [VpnRoute(RD0, "2001:db8:70::/48"), VpnRoute(RD2, "2001:db8:72::/48")]
FAMILIES_B = ["ipv4", "ipv6", "vpn4", "vpn6"]


def render_announcer(log, local, remote) -> str:
    return birdlab.prolog("10.0.0.21", log) + f"""
vpn4 table v4;
vpn6 table v6;

protocol static sv4 {{
  vpn4 {{ table v4; }};
{"".join(f"  route {r.config} blackhole;{chr(10)}" for r in VPN4_B)}}}

protocol static sv6 {{
  vpn6 {{ table v6; }};
{"".join(f"  route {r.config} blackhole;{chr(10)}" for r in VPN6_B)}}}

protocol bgp dut {{
  local {local} as {PEER_AS};
  neighbor {remote} as {prodconf.LOCAL_AS};
  connect delay time 1;
  connect retry time 2;
  vpn4 mpls {{ table v4; import none; export filter {{ bgp_community.add((200,70)); accept; }}; }};
  vpn6 mpls {{ table v6; import none; export filter {{ bgp_community.add((200,70)); accept; }}; }};
}}
"""


@dataclass
class Received:
    dut: birdlab.Bird
    link: object
    files: dict                       # family -> MrtFile
    paths: dict                       # family -> Path
    t0: int


@pytest.fixture(scope="module")
def received(lab, bird_bin, peer_bird_bin, tmp_path_factory) -> Received:
    dumpdir = tmp_path_factory.mktemp("bgp_vpn")
    link = lab.link("dut_b", "peer_v")
    session = prodconf.Session(link.ip4["peer_v"], link.ip4["dut_b"], PEER_AS, FAMILIES_B)
    t0 = int(time.time())
    dut = lab.bird("dut_b", prodconf.render_dut(lab.log_path("dut_b"), dumpdir, [session],
                                                MRT_PERIOD), bird_bin)
    lab.bird("peer_v", render_announcer(lab.log_path("peer_v"), link.ip4["peer_v"],
                                        link.ip4["dut_b"]), peer_bird_bin)
    remote = link.ip4["peer_v"]
    dut.wait_established(prodconf.session_name(remote))
    dut.wait_routes(prodconf.analytics_table(remote, "vpn4"), len(VPN4_B))
    dut.wait_routes(prodconf.analytics_table(remote, "vpn6"), len(VPN6_B))
    since = dut.mrt_dump_events()
    dut.wait_periodic_dumps(since)
    for proto in since:
        dut.disable(proto)
    paths = {f: prodconf.dump_file(dumpdir, PEER_AS, remote, f) for f in FAMILIES_B}
    return Received(dut, link, {f: m.read(p) for f, p in paths.items()}, paths, t0)


def complete_section(f: m.MrtFile, routes: List[VpnRoute]) -> m.Section:
    want = {(r.rd.fork, net(r.prefix)) for r in routes}
    for s in f.sections:
        if {(r.prefix.rd, r.network) for r in s.ribs} == want:
            return s
    raise AssertionError(f"no dump holds exactly {sorted(want)}")


B_CASES = [("vpn4", r) for r in VPN4_B] + [("vpn6", r) for r in VPN6_B]
B_IDS = [f"{fam}-{r.config}" for fam, r in B_CASES]


def received_next_hops(rcv: Received, fam: str, route: VpnRoute) -> List[str]:
    """The BGP.next_hop addresses the DUT stores for `route`."""
    table = prodconf.analytics_table(rcv.link.ip4["peer_v"], fam)
    return rcv.dut.route_attributes(table)[route.config]["BGP.next_hop"].split()


@pytest.mark.parametrize("fam,route", B_CASES, ids=B_IDS)
def test_received_vpn_routes(received, fam, route):
    section = complete_section(received.files[fam], VPN4_B if fam == "vpn4" else VPN6_B)
    assert section.peer_table.view_name == prodconf.analytics_table(received.link.ip4["peer_v"], fam)
    rib = vpn_rib(m.MrtFile([section], []), route)
    assert rib.record.subtype == m.RIB_GENERIC
    assert rib.prefix.labels == [LABEL_0_BOS]
    assert rib.prefix.length_bits == net(route.prefix).prefixlen + 88
    [e] = rib.entries
    peer = section.peer_table.peers[e.peer_index]
    assert (peer.ip, peer.asn, peer.bgp_id) == (received.link.ip4["peer_v"], PEER_AS, ip("10.0.0.21"))
    assert received.t0 <= e.originated
    assert e.get(m.AS_PATH) == [(m.AS_SEQUENCE, [PEER_AS])]
    assert e.get(m.COMMUNITY) == [(200, 70)]
    assert e.get(m.LOCAL_PREF) == 100
    if fam == "vpn4":
        assert e.next_hops() == [ip(f"::ffff:{received.link.ip4['peer_v']}")]
    else:
        # Received as global + link-local (direct session); the dump keeps the global.
        assert len(received_next_hops(received, fam, route)) == 2
        assert e.next_hops() == [received.link.ip6["peer_v"]]


@pytest.mark.parametrize("fam,route", B_CASES, ids=B_IDS)
def test_received_label_is_not_dumped(received, fam, route):
    """The peer sends label 3 (implicit null); the dump writes label 0 regardless."""
    table = prodconf.analytics_table(received.link.ip4["peer_v"], fam)
    assert received.dut.route_attributes(table)[route.config]["BGP.mpls_label_stack"] == "3"
    section = complete_section(received.files[fam], VPN4_B if fam == "vpn4" else VPN6_B)
    assert vpn_rib(m.MrtFile([section], []), route).prefix.labels == [LABEL_0_BOS]


@pytest.mark.parametrize("fam,route", B_CASES, ids=B_IDS)
def test_received_vpn_bgpdump_view(received, bgpdump_bin, fam, route):
    result = bgpdump.run(received.paths[fam], bgpdump_bin)
    assert result.problems == []
    n = net(route.prefix)
    rows = [r for r in result.rows
            if r.rd == route.rd.text and r.prefix == f"{n.network_address}/{n.prefixlen + 88}"]
    assert rows, [r.line for r in result.rows]
    row = rows[0]
    peer_ip = received.link.ip4["peer_v"]
    assert (row.peer_ip, row.peer_as, row.as_path) == (str(peer_ip), PEER_AS, str(PEER_AS))
    assert row.next_hop == (f"::ffff:{peer_ip}" if fam == "vpn4" else str(received.link.ip6["peer_v"]))
    assert row.communities == "200:70"


def test_unicast_dumps_of_a_vpn_only_peer_are_empty(received):
    """The session's ipv4/ipv6 tables get dumped too; the peer sent nothing there."""
    for fam in ("ipv4", "ipv6"):
        f = received.files[fam]
        assert f.sections and all(not s.ribs for s in f.sections)
