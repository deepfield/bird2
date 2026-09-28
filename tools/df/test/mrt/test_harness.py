"""
Smoke tests for the harness itself: a daemon in a namespace dumps a table, and two
daemons in separate namespaces bring up a direct BGP session over a veth link.
"""

import ipaddress
import os

import pytest

import bgpdump
import birdlab
import mrt_reader as m

ip = ipaddress.ip_address

# Peer 0 stands in for non-BGP routes. BIRD writes it with IPA_NONE, which in BIRD 2 is
# the IPv6 zero address, so it is an AS4 + IPv6 peer with address ::.
FAKE_PEER = (3, ip("0.0.0.0"), ip("::"), 0)


def dut_static_config(log):
    return birdlab.prolog("10.0.0.1", log) + """
ipv4 table t4;
ipv6 table t6;

filter set_bgp4 {
  bgp_origin = ORIGIN_IGP;
  bgp_path.empty;
  bgp_path.prepend(65001);
  bgp_next_hop = 10.99.0.1;
  accept;
}

filter set_bgp6 {
  bgp_origin = ORIGIN_IGP;
  bgp_path.empty;
  bgp_path.prepend(65001);
  bgp_next_hop = 2001:db8::1;
  accept;
}

protocol static s4 {
  ipv4 { table t4; import filter set_bgp4; };
  route 10.1.0.0/16 blackhole;
  route 10.2.0.0/16 blackhole;
}

protocol static s6 {
  ipv6 { table t6; import filter set_bgp6; };
  route 2001:db8:1::/48 blackhole;
}
"""


@pytest.fixture(scope="module")
def static_dut(lab, bird_bin):
    dut = lab.bird("dut", dut_static_config(lab.log_path("dut")), bird_bin)
    dut.wait_routes("t4", 2)
    dut.wait_routes("t6", 1)
    return dut


def test_dump_ipv4_table(static_dut, tmp_path):
    f = m.read(static_dut.mrt_dump("t4", tmp_path / "t4.mrt"))
    [section] = f.sections
    pt = section.peer_table
    assert pt.view_name == "t4"
    assert pt.collector_id == ip("10.0.0.1")
    assert [(p.peer_type, p.bgp_id, p.ip, p.asn) for p in pt.peers] == [FAKE_PEER]
    assert sorted(str(r.prefix) for r in section.ribs) == ["10.1.0.0/16", "10.2.0.0/16"]
    for rib in section.ribs:
        assert rib.record.subtype == m.RIB_IPV4_UNICAST
        [e] = rib.entries
        assert e.peer_index == 0
        assert e.get(m.ORIGIN) == 0
        assert e.get(m.AS_PATH) == [(m.AS_SEQUENCE, [65001])]
        assert e.next_hops() == [ip("10.99.0.1")]


def test_bgpdump_reads_ipv4_dump(static_dut, bgpdump_bin, tmp_path):
    result = bgpdump.run(static_dut.mrt_dump("t4", tmp_path / "t4.mrt"), bgpdump_bin)
    assert result.problems == []
    assert sorted(r.prefix for r in result.rows) == ["10.1.0.0/16", "10.2.0.0/16"]
    for r in result.rows:
        assert (r.peer_ip, r.peer_as) == ("::", 0)
        assert (r.as_path, r.origin, r.next_hop) == ("65001", "IGP", "10.99.0.1")


def test_dump_ipv6_table(static_dut, tmp_path):
    f = m.read(static_dut.mrt_dump("t6", tmp_path / "t6.mrt"))
    rib = f.rib("2001:db8:1::/48")
    assert rib.record.subtype == m.RIB_IPV6_UNICAST
    [e] = rib.entries
    assert e.get(m.NEXT_HOP) is None
    assert e.next_hops() == [ip("2001:db8::1")]


def test_dump_file_belongs_to_test_user(static_dut, tmp_path):
    path = static_dut.mrt_dump("t4", tmp_path / "owner.mrt")
    assert path.stat().st_uid == os.getuid()


def test_mrt_dump_of_unknown_table_fails(static_dut, tmp_path):
    with pytest.raises(birdlab.BirdError):
        static_dut.mrt_dump("no_such_table", tmp_path / "x.mrt")


def peer_config(log, router_id, local, remote, local_as, remote_as, statics=""):
    return birdlab.prolog(router_id, log) + f"""
ipv4 table t4;

protocol static s4 {{
  ipv4 {{ table t4; }};
{statics}
}}

protocol bgp bgp1 {{
  local {local} as {local_as};
  neighbor {remote} as {remote_as};
  connect delay time 1;
  connect retry time 2;
  ipv4 {{ table t4; import all; export all; }};
}}
"""


def test_bgp_session_over_veth(lab, bird_bin, peer_bird_bin, bgpdump_bin, tmp_path):
    link = lab.link("dut2", "peer_e")
    dut = lab.bird("dut2", peer_config(
        lab.log_path("dut2"), "10.0.0.1",
        link.ip4["dut2"], link.ip4["peer_e"], 65000, 65001), bird_bin)
    peer = lab.bird("peer_e", peer_config(
        lab.log_path("peer_e"), "10.0.0.2",
        link.ip4["peer_e"], link.ip4["dut2"], 65001, 65000,
        statics="  route 10.50.0.0/16 blackhole;"), peer_bird_bin)

    dut.wait_established("bgp1")
    dut.wait_routes("t4", 1)

    f = m.read(dut.mrt_dump("t4", tmp_path / "bgp.mrt"))
    [section] = f.sections
    peers = section.peer_table.peers
    assert [(p.peer_type, p.bgp_id, p.ip, p.asn) for p in peers] == [
        FAKE_PEER,
        (2, ip("10.0.0.2"), link.ip4["peer_e"], 65001),
    ]
    [e] = f.rib("10.50.0.0/16").entries
    assert e.peer_index == 1
    assert e.get(m.AS_PATH) == [(m.AS_SEQUENCE, [65001])]
    assert e.next_hops() == [link.ip4["peer_e"]]
    assert peer.protocol_state("bgp1").startswith("Established")

    result = bgpdump.run(tmp_path / "bgp.mrt", bgpdump_bin)
    assert result.problems == []
    r = result.row("10.50.0.0/16")
    assert (r.peer_ip, r.peer_as, r.as_path, r.next_hop) == ("10.99.1.2", 65001, "65001", "10.99.1.2")
