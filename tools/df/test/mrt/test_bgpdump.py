"""
Tests for the bgpdump wrapper: line parsing (no bgpdump needed), that problems the real
binary only logs are caught, and what the product's bgpdump makes of records it cannot
or will not show, which is what analytics then sees.
"""

import struct

import pytest

import bgpdump as b
import mrt_reader as m
from test_mrt_reader import PEER_TABLE_HEX, PEERS, RIB_V4_HEX, attr, entry, prefix, rib

LINE_V4 = ("TABLE_DUMP_V2(1,1)|1790615057|B|10.99.1.2|65001|10.50.0.0/16|65001|IGP|"
           "10.99.1.2|100|0|65001:5|NAG||")
LINE_VPN4 = ("TABLE_DUMP_V2(1,128)|1790615057|B|::|0|100:100|8.8.8.0/112|65009|IGP|"
             "::ffff:10.99.0.9|0|0||NAG||")


def test_parse_unicast_line():
    r = b.parse_line(LINE_V4)
    assert (r.afi, r.safi, r.timestamp) == (1, 1, 1790615057)
    assert (r.peer_ip, r.peer_as, r.rd, r.prefix) == ("10.99.1.2", 65001, None, "10.50.0.0/16")
    assert (r.as_path, r.origin, r.next_hop) == ("65001", "IGP", "10.99.1.2")
    assert (r.local_pref, r.med, r.communities) == (100, 0, "65001:5")
    assert (r.atomic_aggregate, r.aggregator) == ("NAG", "")


def test_parse_vpn_line():
    r = b.parse_line(LINE_VPN4)
    assert (r.afi, r.safi, r.rd, r.prefix) == (1, 128, "100:100", "8.8.8.0/112")
    assert r.next_hop == "::ffff:10.99.0.9"


@pytest.mark.parametrize("line,msg", [
    (LINE_V4.replace("|65001:5|", "|"), "13 fields"),
    (LINE_V4 + "x", "does not end with"),
    ("TABLE_DUMP2" + LINE_V4[len("TABLE_DUMP_V2(1,1)"):], "not a TABLE_DUMP_V2 line"),
    (LINE_V4.replace("|B|", "|A|"), "entry kind 'A'"),
])
def test_malformed_lines(line, msg):
    with pytest.raises(b.BgpdumpError, match=msg):
        b.parse_line(line)


def test_clean_file(bgpdump_bin, tmp_path):
    path = tmp_path / "ok.mrt"
    path.write_bytes(bytes.fromhex(PEER_TABLE_HEX + RIB_V4_HEX))
    result = b.run(path, bgpdump_bin)
    assert result.problems == []
    r = result.row("192.168.0.0/24")
    assert (r.peer_ip, r.peer_as, r.as_path) == ("fd99:1::2", 65001, "65001 6943")
    assert (r.origin, r.next_hop, r.communities) == ("INCOMPLETE", "10.99.1.2", "no-export")


def test_truncated_file_is_a_problem(bgpdump_bin, tmp_path):
    path = tmp_path / "truncated.mrt"
    path.write_bytes(bytes.fromhex(PEER_TABLE_HEX + RIB_V4_HEX)[:-3])
    result = b.run(path, bgpdump_bin)
    assert result.rows == []
    assert any("[error]" in p for p in result.problems), result.stderr


def run_bytes(tmp_path, bgpdump_bin, data: bytes) -> b.Result:
    path = tmp_path / "built.mrt"
    path.write_bytes(data)
    return b.run(path, bgpdump_bin)


@pytest.mark.parametrize("subtype,network", [(m.RIB_IPV4_UNICAST, "10.0.0.0/8"),
                                             (m.RIB_IPV6_UNICAST, "2001:db8::/32")])
def test_missing_attributes_print_placeholders(bgpdump_bin, tmp_path, subtype, network):
    """
    An entry without attributes: bgpdump fills in placeholders instead of leaving the
    fields empty. `255.255.255.255` is its "no next hop", for IPv6 entries too: the
    symptom of DP-4605 / DP-6093, and what finding 4 produces.
    """
    result = run_bytes(tmp_path, bgpdump_bin, PEERS + rib(subtype, 0, prefix(network), entry(b"", 1)))
    assert result.problems == []
    r = result.row(network)
    assert (r.as_path, r.origin, r.next_hop) == ("", "INCOMPLETE", "255.255.255.255")
    assert (r.local_pref, r.med, r.communities) == (0, 0, "")


def test_addpath_records_are_silently_dropped(bgpdump_bin, tmp_path):
    """
    bgpdump 1.4.99.14 skips RIB_*_ADDPATH records entirely: no rows and no warning. The
    strict reader shows the record is well formed. Analytics would lose such routes.
    """
    data = PEERS + rib(m.RIB_IPV4_UNICAST_ADDPATH, 0, prefix("10.0.0.0/8"),
                       entry(attr(0x40, m.ORIGIN, b"\x00"), 1, path_id=7))
    [record] = m.parse_file(data).ribs()
    assert (record.add_path, record.entries[0].path_id) == (True, 7)
    result = run_bytes(tmp_path, bgpdump_bin, data)
    assert (result.rows, result.problems) == ([], [])


def test_many_ipv4_records(bgpdump_bin, tmp_path):
    """The control for finding 26: 3000 IPv4 records come out whole."""
    records = b"".join(
        rib(m.RIB_IPV4_UNICAST, i, prefix(f"10.{i >> 8}.{i & 255}.0/24"),
            entry(attr(0x40, m.ORIGIN, b"\x00"), 1)) for i in range(3000))
    result = run_bytes(tmp_path, bgpdump_bin, PEERS + records)
    assert result.problems == []
    assert len(result.rows) == 3000


def many_vpn_records(peer_ip: str, n: int = 3000) -> bytes:
    """n well-formed VPNv4 records, laid out as the fork writes them (RD 65000:<i>), all
    from peer 0 of a one-peer table, like BIRD's dump of a table of static VPN routes."""
    from test_mrt_reader import peer_entry, peer_table
    mp = attr(0x00, m.MP_REACH_NLRI, bytes([16]) + bytes(10) + b"\xff\xff" + bytes([10, 99, 0, 1]))
    med = attr(0x00, m.MED, struct.pack("!I", 7))
    return peer_table(peer_entry(3, "0.0.0.0", peer_ip, 0), view=b"t") + b"".join(
        rib(m.RIB_GENERIC, i, struct.pack("!HB", 1, 128) + bytes([112]) + bytes.fromhex("000001")
            + struct.pack("<Q", (65000 << 32) | i) + bytes([198, 51, 100]), entry(med + mp, 0))
        for i in range(n))


def test_many_vpn_records_real_peer(bgpdump_bin, tmp_path):
    """The other control for finding 26: the same records from a real IPv6 peer are fine."""
    result = run_bytes(tmp_path, bgpdump_bin, many_vpn_records("fd99:1::2"))
    assert result.problems == []
    assert sorted(int(r.rd.split(":")[1]) for r in result.rows) == list(range(3000))


@pytest.mark.xfail(strict=True, reason="finding 26: with peer :: (BIRD's peer 0) bgpdump "
                                       "1.4.99.14 loses or garbles VPN routes after ~2996 records")
def test_many_vpn_records_fake_peer(bgpdump_bin, tmp_path):
    data = many_vpn_records("::")
    assert len(list(m.parse_file(data).ribs())) == 3000          # well-formed
    result = run_bytes(tmp_path, bgpdump_bin, data)
    assert result.problems == []
    assert sorted(int(r.rd.split(":")[1]) for r in result.rows) == list(range(3000))
