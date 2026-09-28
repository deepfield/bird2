"""
Phase 2: the production path, end to end.

The DUT config is what pipedream renders for analytics collection sessions, with lab
addresses: the `bgp_peer` template (pipedream lib/deepy/bird/config.py:113) and the
session, pipe and `protocol mrt` blocks of
lib/deepy/bird/manager/bird_conf_renderer.py (_render_analytics_block,
_render_analytics_mrt). Two peers, both AS 200 as on the dev box, cover the two shapes
the renderer produces:

  peer_a, merged session: the ipv4/ipv6 channels import into merged_session_<peer>_*,
    which a pipe also fills with mitigation statics from dev_<af>_56000; a second pipe
    copies only RTS_BGP routes into bgp_session_<peer>_*, the table that is dumped.
  peer_b, analytics session: the channels import straight into bgp_session_<peer>_*.

Dumps come from the periodic `protocol mrt` timer, as in production, not from the CLI.
The only lines the renderer does not produce are the log file and
`debug protocols { events }`, which lets the test see when a periodic dump is complete.
"""

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

import pytest

import bgpdump
import birdlab
import mrt_reader as m

ip = ipaddress.ip_address
net = ipaddress.ip_network

LOCAL_AS = 2500
PEER_AS = 200
DEVICE_ID = 56000
MRT_PERIOD = 2          # production: 3900 s


@dataclass
class Route:
    prefix: str
    prepend: List[int] = field(default_factory=list)     # path behind the peer's own AS
    communities: List[Tuple[int, int]] = field(default_factory=list)
    med: int = None

    @property
    def afi(self) -> str:
        return "ipv6" if ":" in self.prefix else "ipv4"


@dataclass
class Peer:
    role: str
    router_id: str
    merged: bool
    routes: List[Route]


PEERS = [
    Peer("peer_a", "10.0.0.11", merged=True, routes=[
        Route("198.51.100.0/24", [64500], [(200, 100), (200, 101)], med=10),
        Route("203.0.113.0/24"),
        Route("2001:db8:a::/48", [64500], [(200, 106)], med=60),
    ]),
    Peer("peer_b", "10.0.0.12", merged=False, routes=[
        Route("198.18.0.0/15", [64501, 64502], [(200, 200)], med=20),
        Route("2001:db8:b::/48", med=5),
    ]),
]

# Mitigation statics in the merged session's device tables: never in a dump.
MITIGATIONS = {"ipv4": "192.0.2.0/24", "ipv6": "2001:db8:dead::/48"}

BGP_PEER_TEMPLATE = """
template bgp bgp_peer {
    debug all;
    mrtdump all;
    local as myas;
    ipv4 { import all; extended next hop on; export none; };
    ipv6 { import all; extended next hop on; export none; };
    vpn4 mpls { import all; export none; extended next hop on; table mastervpn4; };
    vpn6 mpls { import all; export none; extended next hop on; table mastervpn6; };
    ipv4 mpls { import all; export none; extended next hop on; table masteripv4mpls; };
    ipv6 mpls { import all; export none; extended next hop on; table masteripv6mpls; };
    multihop;
    graceful restart on;
    long lived graceful restart on;
    enable as4 on;
    enable extended messages off;
    capabilities on;
    interpret communities off;
    deterministic med on;
}
"""


def session_name(remote_ip) -> str:
    return "session_" + str(remote_ip).replace(".", "_")


def analytics_table(remote_ip, afi) -> str:
    return f"bgp_{session_name(remote_ip)}_{afi}"


def merged_table(remote_ip, afi) -> str:
    return f"merged_{session_name(remote_ip)}_{afi}"


def dump_file(dumpdir, remote_ip, afi):
    return dumpdir / f"local_bgpdump.{PEER_AS}.{remote_ip}.{afi}.mrt"


def render_dut(log, dumpdir, sessions) -> str:
    """sessions: [(Peer, remote_ip, source_ip)]"""
    out = [f'log "{log}" all;\ndebug protocols {{ events }};\n',
           "router id 0.0.0.1;\ndefine myas = 0;\n\n"
           "vpn4 table mastervpn4;\nvpn6 table mastervpn6;\n"
           "ipv4 table masteripv4mpls;\nipv6 table masteripv6mpls;\n",
           BGP_PEER_TEMPLATE]
    for family in ("ipv4", "ipv6", "flow4", "flow6"):
        out.append(f"{family} table dev_{family}_{DEVICE_ID};\n")
    for afi, prefix in MITIGATIONS.items():
        out.append(f"protocol static mit_{DEVICE_ID}_{afi} {{\n"
                   f"    {afi} {{ table dev_{afi}_{DEVICE_ID}; }};\n"
                   f"    route {prefix} blackhole;\n}}\n")

    for peer, remote, source in sessions:
        name = session_name(remote)
        out.append("\n")
        for afi in ("ipv4", "ipv6"):
            out.append(f"{afi} table {analytics_table(remote, afi)};\n")
        if peer.merged:
            for afi in ("ipv4", "ipv6"):
                out.append(f"{afi} table {merged_table(remote, afi)};\n")
        out.append(f"\nprotocol bgp {name} from bgp_peer {{\n"
                   f"    neighbor {remote} as {PEER_AS};\n")
        for afi in ("ipv4", "ipv6"):
            if peer.merged:
                out.append(f"    {afi} {{ table {merged_table(remote, afi)}; "
                           f"export where source = RTS_STATIC; next hop keep on; }};\n")
            else:
                out.append(f"    {afi} {{ table {analytics_table(remote, afi)}; }};\n")
        if peer.merged:
            for family in ("flow4", "flow6"):
                out.append(f"    {family}  {{ table dev_{family}_{DEVICE_ID}; "
                           f"import none; export all; extended next hop; }};\n")
        out.append(f"    source address {source};\n"
                   f"    local as {LOCAL_AS};\n"
                   f"    allow local as {LOCAL_AS};\n}}\n")
        if peer.merged:
            for afi in ("ipv4", "ipv6"):
                out.append(f"\nprotocol pipe mit_bridge_{DEVICE_ID}_{afi} {{\n"
                           f"    table dev_{afi}_{DEVICE_ID};\n"
                           f"    peer table {merged_table(remote, afi)};\n"
                           f"    import none;\n    export all;\n}}\n"
                           f"protocol pipe analytics_mrt_{name}_{afi} {{\n"
                           f"    table {merged_table(remote, afi)};\n"
                           f"    peer table {analytics_table(remote, afi)};\n"
                           f"    import none;\n    export where source = RTS_BGP;\n}}\n")

    for peer, remote, source in sessions:
        for afi in ("ipv4", "ipv6"):
            out.append(f"\nprotocol mrt {{\n"
                       f"    table {analytics_table(remote, afi)};\n"
                       f'    filename "{dump_file(dumpdir, remote, afi)}";\n'
                       f"    period {MRT_PERIOD};\n}}\n")
    return "".join(out)


def render_peer(log, peer: Peer, local, remote) -> str:
    """A BIRD announcer: static routes, attributes set on export to the DUT."""
    clauses = []
    for r in peer.routes:
        stmts = [f"bgp_path.prepend({asn});" for asn in reversed(r.prepend)]
        stmts += [f"bgp_community.add(({a},{b}));" for a, b in r.communities]
        if r.med is not None:
            stmts.append(f"bgp_med = {r.med};")
        if stmts:
            clauses.append(f"  if net = {r.prefix} then {{ {' '.join(stmts)} }}")
    statics = {afi: "".join(f"  route {r.prefix} blackhole;\n"
                            for r in peer.routes if r.afi == afi) for afi in ("ipv4", "ipv6")}
    return birdlab.prolog(peer.router_id, log) + f"""
protocol static s4 {{
  ipv4;
{statics['ipv4']}}}

protocol static s6 {{
  ipv6;
{statics['ipv6']}}}

filter export_dut {{
{chr(10).join(clauses)}
  accept;
}}

protocol bgp dut {{
  local {local} as {PEER_AS};
  neighbor {remote} as {LOCAL_AS};
  connect delay time 1;
  connect retry time 2;
  ipv4 {{ import all; export filter export_dut; }};
  ipv6 {{ import all; export filter export_dut; }};
}}
"""


@dataclass
class Prod:
    dut: birdlab.Bird
    dumpdir: object
    links: Dict[str, object]
    t0: int              # before the DUT started, whole seconds like MRT timestamps
    t1: float            # after the dumps were frozen
    files: Dict[Tuple[str, str], m.MrtFile]              # (role, afi) -> parsed dump file

    def remote(self, peer: Peer):
        return self.links[peer.role].ip4[peer.role]

    def path(self, peer: Peer, afi: str):
        return dump_file(self.dumpdir, self.remote(peer), afi)

    def section(self, peer: Peer, afi: str) -> m.Section:
        """The first dump in the file that holds every route the peer announced."""
        complete = complete_sections(self.files[(peer.role, afi)], expected_prefixes(peer, afi))
        assert complete, f"no dump of {self.path(peer, afi)} holds all of {peer.role}'s routes"
        return complete[0]


def expected_prefixes(peer, afi):
    return {net(r.prefix) for r in peer.routes if r.afi == afi}


def complete_sections(f: m.MrtFile, expected) -> List[m.Section]:
    """Sections holding every expected prefix; dumps from before the routes arrived do not."""
    return [s for s in f.sections if {r.network for r in s.ribs} == expected]


def section_key(s: m.Section):
    """What a dump says, minus timestamps: for comparing repeated dumps."""
    return ([(p.peer_type, p.bgp_id, p.ip, p.asn) for p in s.peer_table.peers],
            [(r.record.subtype, r.prefix,
              [(e.peer_index, e.path_id, [(a.flags, a.code, a.value) for a in e.attributes])
               for e in r.entries]) for r in s.ribs])


@pytest.fixture(scope="module")
def prod(lab, bird_bin, peer_bird_bin, tmp_path_factory) -> Prod:
    dumpdir = tmp_path_factory.mktemp("pipedream_tmp")
    links = {p.role: lab.link("dut", p.role) for p in PEERS}
    sessions = [(p, links[p.role].ip4[p.role], links[p.role].ip4["dut"]) for p in PEERS]

    # MRT times are truncated to whole seconds, and a route can arrive within the second
    # the DUT started in: BIRD shortens its connect delay by up to 25% (RFC 4271 jitter).
    t0 = int(time.time())
    dut = lab.bird("dut", render_dut(lab.log_path("dut"), dumpdir, sessions), bird_bin)
    for p in PEERS:
        link = links[p.role]
        lab.bird(p.role, render_peer(lab.log_path(p.role), p,
                                     link.ip4[p.role], link.ip4["dut"]), peer_bird_bin)
    for p in PEERS:
        remote = links[p.role].ip4[p.role]
        dut.wait_established(session_name(remote))
        for afi in ("ipv4", "ipv6"):
            dut.wait_routes(analytics_table(remote, afi), len(expected_prefixes(p, afi)))

    # Every route is in place, so the next periodic dumps show all of them. Wait for two,
    # so each file holds at least two complete dumps appended one after the other.
    since = dut.mrt_dump_events()
    assert len(since) == 2 * len(PEERS), since
    dut.wait_periodic_dumps(dut.wait_periodic_dumps(since))
    for proto in since:
        dut.disable(proto)                  # freeze the files before reading them
    t1 = time.time()

    files = {(p.role, afi): m.read(dump_file(dumpdir, links[p.role].ip4[p.role], afi))
             for p in PEERS for afi in ("ipv4", "ipv6")}
    return Prod(dut, dumpdir, links, t0, t1, files)


CASES = [(p, afi) for p in PEERS for afi in ("ipv4", "ipv6")]
CASE_IDS = [f"{p.role}-{afi}" for p, afi in CASES]


@pytest.mark.parametrize("peer,afi", CASES, ids=CASE_IDS)
def test_repeated_dumps_are_identical(prod, peer, afi):
    """Each period appends a whole dump; once all routes are in, every dump says the same."""
    complete = complete_sections(prod.files[(peer.role, afi)], expected_prefixes(peer, afi))
    assert len(complete) >= 2
    assert all(section_key(s) == section_key(complete[0]) for s in complete[1:])


@pytest.mark.parametrize("peer,afi", CASES, ids=CASE_IDS)
def test_peer_table(prod, peer, afi):
    pt = prod.section(peer, afi).peer_table
    assert pt.view_name == analytics_table(prod.remote(peer), afi)
    assert pt.collector_id == ip("0.0.0.1")
    # Every BGP session is listed, whichever session filled the table.
    peers = [(p.peer_type, p.bgp_id, p.ip, p.asn) for p in pt.peers]
    assert peers[0] == birdlab.MRT_FAKE_PEER
    assert sorted(peers[1:]) == sorted(
        (2, ip(q.router_id), prod.remote(q), PEER_AS) for q in PEERS)


@pytest.mark.parametrize("peer,afi", CASES, ids=CASE_IDS)
def test_routes(prod, peer, afi):
    section = prod.section(peer, afi)
    peers = section.peer_table.peers
    link = prod.links[peer.role]
    for route in (r for r in peer.routes if r.afi == afi):
        rib = next(r for r in section.ribs if r.network == net(route.prefix))
        assert rib.record.subtype == (m.RIB_IPV4_UNICAST if afi == "ipv4" else m.RIB_IPV6_UNICAST)
        assert prod.t0 <= rib.record.timestamp <= prod.t1
        [e] = rib.entries
        # The pipe (merged session) must not hide which session the route came from.
        assert (peers[e.peer_index].ip, peers[e.peer_index].bgp_id) == (
            link.ip4[peer.role], ip(peer.router_id))
        assert prod.t0 <= e.originated <= prod.t1
        assert e.get(m.ORIGIN) == 0
        assert e.get(m.AS_PATH) == [(m.AS_SEQUENCE, [PEER_AS] + route.prepend)]
        assert e.get(m.LOCAL_PREF) == 100
        assert e.get(m.MED) == route.med
        assert e.get(m.COMMUNITY) == (route.communities or None)
        if afi == "ipv4":
            assert e.attr(m.MP_REACH_NLRI) is None
            assert e.next_hops() == [link.ip4[peer.role]]
        else:
            # Received as global + link-local (direct session); the dump keeps the global.
            assert e.attr(m.NEXT_HOP) is None
            assert e.next_hops() == [link.ip6[peer.role]]


@pytest.mark.parametrize("peer,afi", CASES, ids=CASE_IDS)
def test_bgpdump_view(prod, bgpdump_bin, peer, afi):
    result = bgpdump.run(prod.path(peer, afi), bgpdump_bin)
    assert result.problems == []
    by_prefix = result.by_prefix()
    assert set(by_prefix) == {r.prefix for r in peer.routes if r.afi == afi}
    link = prod.links[peer.role]
    next_hop = link.ip4[peer.role] if afi == "ipv4" else link.ip6[peer.role]
    for route in (r for r in peer.routes if r.afi == afi):
        rows = by_prefix[route.prefix]
        # One row per appended dump; apart from the dump time they must agree.
        assert len({row.line.split("|", 2)[2] for row in rows}) == 1
        row = rows[0]
        assert (row.peer_ip, row.peer_as) == (str(link.ip4[peer.role]), PEER_AS)
        assert row.as_path == " ".join(str(a) for a in [PEER_AS] + route.prepend)
        assert (row.origin, row.next_hop) == ("IGP", str(next_hop))
        assert (row.local_pref, row.med) == (100, route.med or 0)
        assert row.communities == " ".join(f"{a}:{b}" for a, b in route.communities)


@pytest.mark.parametrize("afi", ["ipv4", "ipv6"])
def test_mitigation_routes_stay_out_of_the_dump(prod, afi):
    """The merged table holds the mitigation static; the dumped table must not."""
    peer = next(p for p in PEERS if p.merged)
    remote = prod.remote(peer)
    n_bgp = len(expected_prefixes(peer, afi))
    assert prod.dut.route_count(merged_table(remote, afi)) == n_bgp + 1
    assert prod.dut.route_count(analytics_table(remote, afi)) == n_bgp
    mitigation = net(MITIGATIONS[afi])
    for p in PEERS:
        for section in prod.files[(p.role, afi)].sections:
            assert mitigation not in {r.network for r in section.ribs}
