"""
Phase 5, tier 2: attributes received over BGP.

The DUT runs the production config (prodconf.py) with four analytics sessions and a
BGP4MP capture of everything it receives. Four BIRD announcers set attributes in their
export filters:

  peer_e   eBGP AS 200 over IPv4 (the production shape): ORIGIN, a 32-bit ASN in the
           path, MED, 70 communities (extended length), ext and large communities
  peer_i   iBGP AS 2500: LOCAL_PREF, ORIGINATOR_ID, CLUSTER_LIST
  peer_2b  eBGP without 4-byte ASNs: AS_PATH with AS_TRANS plus AS4_PATH on the wire
  peer_x6  eBGP over IPv6, multihop (so no link-local), extended next hop: IPv4 routes
           with an IPv6 next hop (finding 4 as production would meet it) and IPv6 routes
           with a 16-byte next hop

The core check compares each route's RIB entry with the UPDATE that carried it, from the
capture. Only these differences are allowed (expected_entry):
  - NEXT_HOP keeps its value, loses its flags (0x40 -> 0x00; finding 5);
  - MP_REACH_NLRI shrinks to the table-dump form with the global next hop, flags 0x00,
    appended after the other attributes (findings 2, 18, 22);
  - an eBGP route gains LOCAL_PREF 100, flags 0x00 (finding 5);
  - AS4_PATH disappears into AS_PATH, which is then 4-byte (RFC 6793 merge).
Everything else, flags included, must come through unchanged.
"""

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Dict, List

import pytest

import bgpdump
import birdlab
import mrt_reader as m
import prodconf

ip = ipaddress.ip_address
net = ipaddress.ip_network


def u32(*values) -> bytes:
    return b"".join(struct.pack("!I", v) for v in values)


@dataclass
class Route:
    name: str
    prefix: str
    stmts: List[str]                     # export filter statements on the announcer
    view: Dict[str, object] = field(default_factory=dict)   # expected bgpdump fields
    path4: List[int] = None              # expected AS_PATH in the dump, if merged from AS4_PATH

    @property
    def afi(self) -> str:
        return "ipv6" if ":" in self.prefix else "ipv4"


@dataclass
class Peer:
    role: str
    router_id: str
    asn: int
    transport: str                       # "ipv4" or "ipv6"
    routes: List[Route]
    options: str = ""                    # extra `protocol bgp` lines on the announcer
    ext_next_hop: bool = False

    @property
    def ibgp(self) -> bool:
        return self.asn == prodconf.LOCAL_AS


COMMS_70 = [f"bgp_community.add((200,{i}));" for i in range(1, 71)]

PEERS = [
    Peer("peer_e", "10.0.0.31", 200, "ipv4", [
        Route("e_path", "198.51.100.0/24",
              ["bgp_origin = ORIGIN_EGP;", "bgp_path.prepend(4200000000);",
               "bgp_path.prepend(64500);", "bgp_med = 10;", "bgp_community.add((200,1));",
               "bgp_community.add((65535,65281));"],
              {"as_path": "200 64500 4200000000", "origin": "EGP", "med": 10,
               "local_pref": 100, "communities": "200:1 no-export"}),
        Route("e_communities", "203.0.113.0/24",
              COMMS_70 + ["bgp_ext_community.add((rt, 200, 5));",
                          "bgp_ext_community.add((ro, 10.0.0.31, 6));",
                          "bgp_large_community.add((200, 1, 2));"],
              {"as_path": "200", "origin": "IGP", "local_pref": 100,
               "communities": " ".join(f"200:{i}" for i in range(1, 71))}),
        Route("e_v6", "2001:db8:e1::/48",
              ["bgp_med = 7;", "bgp_large_community.add((200, 7, 7));"],
              {"as_path": "200", "med": 7, "local_pref": 100}),
    ]),
    Peer("peer_i", "10.0.0.32", 2500, "ipv4", [
        Route("i_local_pref", "198.51.101.0/24",
              ["bgp_local_pref = 300;", "bgp_originator_id = 192.0.2.9;",
               "bgp_cluster_list.add(192.0.2.10);", "bgp_community.add((2500,1));"],
              {"as_path": "", "local_pref": 300, "communities": "2500:1"}),
        Route("i_v6", "2001:db8:e2::/48", ["bgp_local_pref = 50;"],
              {"as_path": "", "local_pref": 50}),
    ]),
    Peer("peer_2b", "10.0.0.33", 65003, "ipv4", [
        Route("as4_merge", "198.51.102.0/24",
              ["bgp_path.prepend(64510);", "bgp_path.prepend(4200000000);"],
              {"as_path": "65003 4200000000 64510", "local_pref": 100},
              path4=[65003, 4200000000, 64510]),
    ], options="enable as4 off;"),
    Peer("peer_x6", "10.0.0.34", 64999, "ipv6", [
        Route("ext_next_hop", "198.51.103.0/24", ["bgp_med = 3;"],
              {"as_path": "64999", "med": 3, "local_pref": 100}),
        Route("v6_16_byte", "2001:db8:e4::/48", ["bgp_med = 4;"],
              {"as_path": "64999", "med": 4, "local_pref": 100}),
    ], options="multihop;", ext_next_hop=True),
]

CASES = [(p, r) for p in PEERS for r in p.routes]


CASE_IDS = [r.name for _, r in CASES]


def render_announcer(log, peer: Peer, local, remote) -> str:
    clauses = "\n".join(f"  if net = {r.prefix} then {{ {' '.join(r.stmts)} }}" for r in peer.routes)
    statics = {afi: "".join(f"  route {r.prefix} blackhole;\n" for r in peer.routes if r.afi == afi)
               for afi in ("ipv4", "ipv6")}
    ext = " extended next hop on;" if peer.ext_next_hop else ""
    return birdlab.prolog(peer.router_id, log) + f"""
protocol static s4 {{
  ipv4;
{statics['ipv4']}}}

protocol static s6 {{
  ipv6;
{statics['ipv6']}}}

filter export_dut {{
{clauses}
  accept;
}}

protocol bgp dut {{
  local {local} as {peer.asn};
  neighbor {remote} as {prodconf.LOCAL_AS};
  connect delay time 1;
  connect retry time 2;
  {peer.options}
  ipv4 {{ import none; export filter export_dut;{ext} }};
  ipv6 {{ import none; export filter export_dut; }};
}}
"""


@dataclass
class Tier2:
    dut: birdlab.Bird
    links: Dict[str, object]
    dumps: Dict[tuple, m.MrtFile]        # (role, afi) -> table dump
    dump_paths: Dict[tuple, object]
    capture: List[m.Bgp4mp]              # BGP4MP records, all peers

    def remote(self, peer: Peer):
        return self.links[peer.role].ip4[peer.role] if peer.transport == "ipv4" \
            else self.links[peer.role].ip6[peer.role]

    def local(self, peer: Peer):
        return self.links[peer.role].ip4["dut"] if peer.transport == "ipv4" \
            else self.links[peer.role].ip6["dut"]

    def entry(self, peer: Peer, route: Route) -> m.RibEntry:
        [e] = self.dumps[(peer.role, route.afi)].rib(route.prefix).entries
        return e

    def update(self, peer: Peer, route: Route) -> m.BgpUpdate:
        """The UPDATE from `peer` that announced `route`; fails unless exactly one did."""
        found = [u for u in (r.update() for r in self.capture
                             if r.peer_ip == self.remote(peer) and r.message_type == m.BGP_UPDATE)
                 if net(route.prefix) in u.prefixes()]
        assert len(found) == 1, f"{len(found)} UPDATEs from {peer.role} announce {route.prefix}"
        return found[0]


@pytest.fixture(scope="module")
def tier2(lab, bird_bin, peer_bird_bin, tmp_path_factory) -> Tier2:
    dumpdir = tmp_path_factory.mktemp("tier2")
    capture_path = dumpdir / "bgp4mp.mrt"
    links = {p.role: lab.link("dut", p.role) for p in PEERS}

    def addr(p, side):
        link = links[p.role]
        return link.ip4[side] if p.transport == "ipv4" else link.ip6[side]

    sessions = [prodconf.Session(addr(p, p.role), addr(p, "dut"), p.asn) for p in PEERS]
    dut = lab.bird("dut", prodconf.render_dut(lab.log_path("dut"), dumpdir, sessions, 3900,
                                              bgp4mp_file=capture_path), bird_bin)
    for p in PEERS:
        lab.bird(p.role, render_announcer(lab.log_path(p.role), p, addr(p, p.role),
                                          addr(p, "dut")), peer_bird_bin)
    for p in PEERS:
        remote = addr(p, p.role)
        dut.wait_established(prodconf.session_name(remote))
        for afi in ("ipv4", "ipv6"):
            dut.wait_routes(prodconf.analytics_table(remote, afi),
                            sum(1 for r in p.routes if r.afi == afi))

    dumps, paths = {}, {}
    for p in PEERS:
        for afi in ("ipv4", "ipv6"):
            path = dut.mrt_dump(prodconf.analytics_table(addr(p, p.role), afi),
                                dumpdir / f"{p.role}_{afi}.mrt")
            paths[(p.role, afi)] = path
            dumps[(p.role, afi)] = m.read(path)
    capture = m.parse_file(m.complete_records(capture_path.read_bytes())).bgp4mp()
    return Tier2(dut, links, dumps, paths, capture)


def encode_as_path(asns) -> bytes:
    return bytes([m.AS_SEQUENCE, len(asns)]) + u32(*asns)


def expected_entry(update: m.BgpUpdate, peer: Peer, route: Route):
    """The RIB entry's attributes as (flags, code, value), derived from the UPDATE."""
    out = []
    mp = None
    for a in update.attributes:
        if a.code == m.NEXT_HOP:
            out.append((0x00, m.NEXT_HOP, a.value))
        elif a.code == m.MP_REACH_NLRI:
            mp = a.decode(table_dump=False)
        elif a.code == m.AS4_PATH:
            continue
        elif a.code == m.AS_PATH and not update.as4:
            out.append((a.flags, m.AS_PATH, encode_as_path(route.path4)))
        else:
            out.append((a.flags, a.code, a.value))
    if not peer.ibgp:
        assert update.attr(m.LOCAL_PREF) is None
        out.append((0x00, m.LOCAL_PREF, u32(100)))
    out.sort(key=lambda t: t[1])
    if mp is not None:
        glob = mp.next_hops[0].packed
        out.append((0x00, m.MP_REACH_NLRI, bytes([len(glob)]) + glob))
    return out


def xfail_ext_next_hop(case):
    peer, route = case
    if route.name == "ext_next_hop":
        return pytest.param(peer, route, id=route.name, marks=pytest.mark.xfail(
            strict=True, reason="finding 4: an IPv6 next hop on an IPv4 route is dropped"))
    return pytest.param(peer, route, id=route.name)


@pytest.mark.parametrize("peer,route", [xfail_ext_next_hop(c) for c in CASES])
def test_dump_matches_update(tier2, peer, route):
    e = tier2.entry(peer, route)
    assert [(a.flags, a.code, a.value) for a in e.attributes] == \
        expected_entry(tier2.update(peer, route), peer, route)


@pytest.mark.parametrize("peer,route", CASES, ids=CASE_IDS)
def test_peer_index(tier2, peer, route):
    section = tier2.dumps[(peer.role, route.afi)].sections[0]
    p = section.peer_table.peers[tier2.entry(peer, route).peer_index]
    assert (p.ip, p.asn, p.bgp_id) == (tier2.remote(peer), peer.asn, ip(peer.router_id))


def test_received_flags(tier2):
    """Finding 5, spelled out: received flags survive, NEXT_HOP and default LOCAL_PREF do not."""
    peer_e, peer_i = PEERS[0], PEERS[1]
    flags = {a.code: a.flags for a in tier2.entry(peer_e, peer_e.routes[0]).attributes}
    assert flags == {m.ORIGIN: 0x40, m.AS_PATH: 0x40, m.NEXT_HOP: 0x00, m.MED: 0x80,
                     m.LOCAL_PREF: 0x00, m.COMMUNITY: 0xC0}
    flags = {a.code: a.flags for a in tier2.entry(peer_e, peer_e.routes[1]).attributes}
    assert flags[m.COMMUNITY] == 0xC0 | m.FLAG_EXTENDED
    assert (flags[m.EXT_COMMUNITY], flags[m.LARGE_COMMUNITY]) == (0xC0, 0xC0)
    flags = {a.code: a.flags for a in tier2.entry(peer_i, peer_i.routes[0]).attributes}
    assert (flags[m.LOCAL_PREF], flags[m.ORIGINATOR_ID], flags[m.CLUSTER_LIST]) == (0x40, 0x80, 0x80)


def test_as4_path_merged(tier2):
    peer = next(p for p in PEERS if p.role == "peer_2b")
    route = peer.routes[0]
    u = tier2.update(peer, route)
    # Precondition: the peer really sent a 2-byte path with AS_TRANS plus AS4_PATH.
    assert not u.as4
    assert 23456 in u.get(m.AS_PATH)[0][1]
    assert u.attr(m.AS4_PATH) is not None
    e = tier2.entry(peer, route)
    assert m.AS4_PATH not in e.codes()
    assert e.get(m.AS_PATH) == [(m.AS_SEQUENCE, route.path4)]


def test_extended_next_hop_received(tier2):
    """Precondition for the finding 4 xfails: the IPv6 next hop did reach the DUT."""
    peer = next(p for p in PEERS if p.role == "peer_x6")
    route = next(r for r in peer.routes if r.name == "ext_next_hop")
    mp = tier2.update(peer, route).get(m.MP_REACH_NLRI)
    assert (mp.afi, mp.safi, mp.next_hops) == (1, 1, [tier2.remote(peer)])
    table = prodconf.analytics_table(tier2.remote(peer), "ipv4")
    assert tier2.dut.route_attributes(table)[route.prefix]["BGP.next_hop"] == str(tier2.remote(peer))


def test_sixteen_byte_next_hop(tier2):
    """A multihop peer sends no link-local: the 16-byte MP_REACH next hop path."""
    peer = next(p for p in PEERS if p.role == "peer_x6")
    route = next(r for r in peer.routes if r.name == "v6_16_byte")
    assert tier2.update(peer, route).get(m.MP_REACH_NLRI).next_hops == [tier2.remote(peer)]
    assert tier2.entry(peer, route).next_hops() == [tier2.remote(peer)]


def expected_next_hop_text(tier2, peer, route) -> str:
    if route.afi == "ipv4" and peer.transport == "ipv4":
        return str(tier2.links[peer.role].ip4[peer.role])
    return str(tier2.links[peer.role].ip6[peer.role])


def bgpdump_case(case):
    peer, route = case
    if route.name == "ext_next_hop":
        return pytest.param(peer, route, id=route.name, marks=pytest.mark.xfail(
            strict=True, reason="finding 4: bgpdump shows 255.255.255.255 (finding 24)"))
    return pytest.param(peer, route, id=route.name)


@pytest.mark.parametrize("peer,route", [bgpdump_case(c) for c in CASES])
def test_bgpdump_view(tier2, bgpdump_bin, peer, route):
    result = bgpdump.run(tier2.dump_paths[(peer.role, route.afi)], bgpdump_bin)
    assert result.problems == []
    row = result.row(route.prefix)
    assert (row.peer_ip, row.peer_as) == (str(tier2.remote(peer)), peer.asn)
    assert {k: getattr(row, k) for k in route.view} == route.view
    assert row.next_hop == expected_next_hop_text(tier2, peer, route)


@pytest.mark.parametrize("peer", PEERS, ids=lambda p: p.role)
def test_bgp4mp_capture(tier2, peer):
    """BIRD's BGP4MP writer (mrt.c mrt_dump_bgp_*): headers, subtypes, state changes."""
    records = [r for r in tier2.capture if r.peer_ip == tier2.remote(peer)]
    messages = [r for r in records if r.message is not None]
    states = [r for r in records if r.message is None]
    subtypes = {}
    for r in messages:
        subtypes.setdefault(r.message_type, set()).add(r.record.subtype)
    assert set(subtypes) >= {m.BGP_OPEN, m.BGP_UPDATE, m.BGP_KEEPALIVE}
    # A message follows the session's ASN size only from OpenConfirm on (packets.c:97-106):
    # the OPEN, and a KEEPALIVE that beats it, are always 2-byte MESSAGE records.
    assert subtypes[m.BGP_OPEN] == {m.BGP4MP_MESSAGE}
    assert subtypes[m.BGP_UPDATE] == {
        m.BGP4MP_MESSAGE if "as4 off" in peer.options else m.BGP4MP_MESSAGE_AS4}
    # State changes are always AS4 (mrt.c:961).
    assert {r.record.subtype for r in states} == {m.BGP4MP_STATE_CHANGE_AS4}
    assert m.BGP_STATE_ESTABLISHED in [r.new_state for r in states]
    # Before a connection exists there is no socket to take the peer address from
    # (packets.c:104): those state changes carry 0.0.0.0 / :: and only the AS says whose.
    unbound = [r for r in tier2.capture if r.peer_ip.is_unspecified and r.peer_as == peer.asn]
    assert unbound and all(r.message is None for r in unbound)
    for r in records + unbound:
        assert (r.peer_as, r.local_as) == (peer.asn, prodconf.LOCAL_AS)
        assert r.afi == (m.AFI_IPV4 if peer.transport == "ipv4" else m.AFI_IPV6)
        if r in records:
            assert r.local_ip == tier2.local(peer)
        else:
            assert r.local_ip.is_unspecified
