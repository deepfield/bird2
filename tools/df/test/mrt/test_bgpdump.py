"""
Tests for the bgpdump wrapper: line parsing (no bgpdump needed), and that problems the
real binary only logs are caught.
"""

import pytest

import bgpdump as b
from test_mrt_reader import PEER_TABLE_HEX, RIB_V4_HEX

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
