"""
Unit tests for mrt_reader against hand-built bytes; no BIRD needed.

The literal-hex records are laid out by hand from RFC 6396, so they check the reader
independently of the small builders below.
"""

import ipaddress
import struct

import pytest

import mrt_reader as m

ip = ipaddress.ip_address
net = ipaddress.ip_network


# -- builders ---------------------------------------------------------------------

def record(rtype, subtype, body, ts=1700000000):
    return struct.pack("!IHHI", ts, rtype, subtype, len(body)) + body


def attr(flags, code, value):
    if flags & m.FLAG_EXTENDED:
        return struct.pack("!BBH", flags, code, len(value)) + value
    return struct.pack("!BBB", flags, code, len(value)) + value


def peer_entry(ptype, bgp_id, peer_ip, asn):
    fmt_as = "!I" if ptype & 2 else "!H"
    return bytes([ptype]) + ip(bgp_id).packed + ip(peer_ip).packed + struct.pack(fmt_as, asn)


def peer_table(*entries, collector="10.0.0.1", view=b"t"):
    body = ip(collector).packed + struct.pack("!H", len(view)) + view
    body += struct.pack("!H", len(entries)) + b"".join(entries)
    return record(m.TABLE_DUMP_V2, m.PEER_INDEX_TABLE, body)


def entry(attrs, peer=0, originated=1700000000, path_id=None):
    out = struct.pack("!HI", peer, originated)
    if path_id is not None:
        out += struct.pack("!I", path_id)
    return out + struct.pack("!H", len(attrs)) + attrs


def rib(subtype, seq, nlri, *entries):
    body = struct.pack("!I", seq) + nlri + struct.pack("!H", len(entries)) + b"".join(entries)
    return record(m.TABLE_DUMP_V2, subtype, body)


def prefix(network):
    n = net(network)
    return bytes([n.prefixlen]) + n.network_address.packed[:(n.prefixlen + 7) // 8]


PEERS = peer_table(peer_entry(2, "0.0.0.0", "0.0.0.0", 0),
                   peer_entry(2, "10.0.0.2", "10.99.1.2", 65001))


def one_rib(data):
    f = m.parse_file(data)
    ribs = list(f.ribs())
    assert len(ribs) == 1
    return ribs[0]


# -- MRT header ---------------------------------------------------------------------

def test_iter_records_splits_on_header_length():
    data = record(m.BGP4MP, 4, b"\x01\x02") + record(99, 7, b"")
    recs = list(m.iter_records(data))
    assert [(r.type, r.subtype, r.body, r.offset) for r in recs] == [
        (m.BGP4MP, 4, b"\x01\x02", 0), (99, 7, b"", 14)]
    assert recs[0].timestamp == 1700000000


def test_truncated_header_is_an_error():
    with pytest.raises(m.MrtFormatError, match="truncated MRT header"):
        list(m.iter_records(record(99, 1, b"") + b"\x00\x00"))


def test_record_length_past_end_is_an_error():
    with pytest.raises(m.MrtFormatError, match="past the end"):
        list(m.iter_records(record(99, 1, b"abcd")[:-1]))


# -- PEER_INDEX_TABLE ---------------------------------------------------------------

PEER_TABLE_HEX = (
    "65000000" "000d" "0001" "0000003b"      # ts, TABLE_DUMP_V2, PEER_INDEX_TABLE, length 59
    "0a000001" "0002" "7434" "0003"          # collector 10.0.0.1, view "t4", 3 peers
    "02" "00000000" "00000000" "00000000"    # AS4, IPv4: fake peer 0
    "03" "0a000002" "fd990001000000000000000000000002" "0000fde9"   # AS4, IPv6, AS 65001
    "00" "0a000003" "0a630202" "fde8"        # 2-byte AS, IPv4, AS 65000
)


def test_peer_index_table_literal():
    f = m.parse_file(bytes.fromhex(PEER_TABLE_HEX))
    pt = f.sections[0].peer_table
    assert pt.collector_id == ip("10.0.0.1")
    assert pt.view_name == "t4"
    assert [(p.index, p.peer_type, p.bgp_id, p.ip, p.asn) for p in pt.peers] == [
        (0, 2, ip("0.0.0.0"), ip("0.0.0.0"), 0),
        (1, 3, ip("10.0.0.2"), ip("fd99:1::2"), 65001),
        (2, 0, ip("10.0.0.3"), ip("10.99.2.2"), 65000),
    ]


def test_peer_table_trailing_bytes_is_an_error():
    data = bytearray(bytes.fromhex(PEER_TABLE_HEX))
    data[21] = 2                              # claim 2 peers, 3 present
    with pytest.raises(m.MrtFormatError, match="trailing bytes"):
        m.parse_file(bytes(data))


def test_peer_table_unknown_type_bits_is_an_error():
    with pytest.raises(m.MrtFormatError, match="unknown peer type bits"):
        m.parse_file(peer_table(b"\x04" + bytes(10)))


# -- RIB records --------------------------------------------------------------------

RIB_V4_HEX = (
    "65000000" "000d" "0002" "00000031"      # ts, TABLE_DUMP_V2, RIB_IPV4_UNICAST, length 49
    "00000000" "18c0a800" "0001"             # seq 0, 192.168.0.0/24, 1 entry
    "0001" "65000000" "001f"                 # peer 1, originated, 31 bytes of attributes
    "400101" "02"                            # ORIGIN INCOMPLETE
    "40020a" "0202" "0000fde9" "00001b1f"    # AS_PATH SEQUENCE 65001 6943
    "400304" "0a630102"                      # NEXT_HOP 10.99.1.2
    "c00804" "ffffff01"                      # COMMUNITY no-export
)


def test_rib_ipv4_literal():
    rib_ = one_rib(PEERS + bytes.fromhex(RIB_V4_HEX))
    assert (rib_.sequence, rib_.afi, rib_.safi, rib_.add_path) == (0, 1, 1, False)
    assert rib_.prefix == net("192.168.0.0/24")
    [e] = rib_.entries
    assert (e.peer_index, e.originated, e.path_id) == (1, 0x65000000, None)
    assert e.codes() == [m.ORIGIN, m.AS_PATH, m.NEXT_HOP, m.COMMUNITY]
    assert [a.flags for a in e.attributes] == [0x40, 0x40, 0x40, 0xC0]
    assert e.get(m.ORIGIN) == 2
    assert e.get(m.AS_PATH) == [(m.AS_SEQUENCE, [65001, 6943])]
    assert e.get(m.NEXT_HOP) == ip("10.99.1.2")
    assert e.get(m.COMMUNITY) == [(0xFFFF, 0xFF01)]
    assert e.next_hops() == [ip("10.99.1.2")]
    assert e.get(m.MED) is None


def test_attribute_offsets_are_file_offsets():
    data = PEERS + bytes.fromhex(RIB_V4_HEX)
    e = one_rib(data).entries[0]
    for a in e.attributes:
        assert data[a.offset] == a.flags and data[a.offset + 1] == a.code


@pytest.mark.parametrize("hops", [["2001:db8::1"], ["2001:db8::1", "fe80::1"]])
def test_rib_ipv6_table_dump_mp_reach(hops):
    nh = b"".join(ip(h).packed for h in hops)
    mp = attr(0x80, m.MP_REACH_NLRI, bytes([len(nh)]) + nh)
    rib_ = one_rib(PEERS + rib(m.RIB_IPV6_UNICAST, 0, prefix("2001:db8:1::/48"), entry(mp, 1)))
    assert rib_.prefix == net("2001:db8:1::/48")
    assert rib_.entries[0].next_hops() == [ip(h) for h in hops]
    assert rib_.entries[0].get(m.MP_REACH_NLRI).afi is None


def test_mp_reach_table_dump_rejects_extra_bytes():
    value = bytes([16]) + ip("2001:db8::1").packed + b"\x00"
    with pytest.raises(m.MrtFormatError, match="trailing bytes"):
        m.parse_mp_reach(value, table_dump=True)


def test_mp_reach_wire_layout():
    value = (struct.pack("!HBB", 2, 1, 16) + ip("2001:db8::1").packed + b"\x00"
             + prefix("2001:db8:1::/48"))
    mp = m.parse_mp_reach(value, table_dump=False)
    assert (mp.afi, mp.safi, mp.next_hops) == (2, 1, [ip("2001:db8::1")])
    assert mp.nlri == prefix("2001:db8:1::/48")


def test_extended_length_attribute():
    comms = b"".join(struct.pack("!HH", 65000, i) for i in range(70))
    a = attr(0xC0 | m.FLAG_EXTENDED, m.COMMUNITY, comms)
    e = one_rib(PEERS + rib(m.RIB_IPV4_UNICAST, 0, prefix("10.0.0.0/8"), entry(a))).entries[0]
    assert e.attr(m.COMMUNITY).flags == 0xD0
    assert e.get(m.COMMUNITY) == [(65000, i) for i in range(70)]


def test_all_known_attributes_decode():
    attrs = b"".join([
        attr(0x40, m.MED, struct.pack("!I", 0xFFFFFFFF)),
        attr(0x40, m.LOCAL_PREF, struct.pack("!I", 100)),
        attr(0x40, m.ATOMIC_AGGREGATE, b""),
        attr(0xC0, m.AGGREGATOR, struct.pack("!I", 4200000000) + ip("10.0.0.9").packed),
        attr(0x80, m.ORIGINATOR_ID, ip("10.0.0.7").packed),
        attr(0x80, m.CLUSTER_LIST, ip("10.0.0.8").packed + ip("10.0.0.9").packed),
        attr(0xC0, m.EXT_COMMUNITY, bytes.fromhex("0002fde800000064")),
        attr(0xC0, m.IPV6_EXT_COMMUNITY, bytes.fromhex("000c") + ip("2001:db8::1").packed + b"\x00\x00"),
        attr(0xC0, m.LARGE_COMMUNITY, struct.pack("!III", 4200000000, 1, 2)),
        attr(0xC0, 99, b"\xde\xad"),
    ])
    e = one_rib(PEERS + rib(m.RIB_IPV4_UNICAST, 0, prefix("0.0.0.0/0"), entry(attrs))).entries[0]
    assert e.get(m.MED) == 0xFFFFFFFF
    assert e.get(m.LOCAL_PREF) == 100
    assert e.get(m.ATOMIC_AGGREGATE) is True
    assert e.get(m.AGGREGATOR) == (4200000000, ip("10.0.0.9"))
    assert e.get(m.ORIGINATOR_ID) == ip("10.0.0.7")
    assert e.get(m.CLUSTER_LIST) == [ip("10.0.0.8"), ip("10.0.0.9")]
    assert e.get(m.EXT_COMMUNITY) == [bytes.fromhex("0002fde800000064")]
    assert e.get(m.IPV6_EXT_COMMUNITY) == [bytes.fromhex("000c20010db8000000000000000000000001" "0000")]
    assert e.get(m.LARGE_COMMUNITY) == [(4200000000, 1, 2)]
    assert e.get(99) == b"\xde\xad"


@pytest.mark.parametrize("code,value,msg", [
    (m.ORIGIN, b"\x03", "ORIGIN value 3"),
    (m.NEXT_HOP, b"\x0a\x00\x00", "NEXT_HOP: length 3"),
    (m.COMMUNITY, b"\x00\x00\x00", "not a multiple of 4"),
    (m.AS_PATH, b"\x02\x02\x00\x00\x00\x01", "need 4 bytes"),
    (m.AS_PATH, b"\x05\x00", "segment type 5"),
])
def test_bad_attribute_values(code, value, msg):
    with pytest.raises(m.MrtFormatError, match=msg):
        m.decode_attribute(code, value)


def test_duplicate_attribute_is_an_error():
    attrs = attr(0x40, m.ORIGIN, b"\x00") * 2
    with pytest.raises(m.MrtFormatError, match="appears twice"):
        m.parse_file(PEERS + rib(m.RIB_IPV4_UNICAST, 0, prefix("10.0.0.0/8"), entry(attrs)))


def test_unused_flag_bits_are_an_error():
    with pytest.raises(m.MrtFormatError, match="unused flag bits"):
        m.parse_attributes(attr(0x41, m.ORIGIN, b"\x00"))


def test_attribute_running_past_its_block_is_an_error():
    with pytest.raises(m.MrtFormatError, match="attribute 1 value"):
        m.parse_attributes(b"\x40\x01\x05\x00")


def test_entry_count_too_high_is_an_error():
    data = bytearray(PEERS + bytes.fromhex(RIB_V4_HEX))
    data[len(PEERS) + 12 + 8 + 1] = 2        # entry count 1 -> 2
    with pytest.raises(m.MrtFormatError, match="peer index: need 2 bytes"):
        m.parse_file(bytes(data))


def test_rib_trailing_bytes_is_an_error():
    body = bytes.fromhex(RIB_V4_HEX)[12:] + b"\x00"
    with pytest.raises(m.MrtFormatError, match="RIB record: 1 trailing bytes"):
        m.parse_file(PEERS + record(m.TABLE_DUMP_V2, m.RIB_IPV4_UNICAST, body))


@pytest.mark.parametrize("network", ["0.0.0.0/0", "10.1.2.3/32", "10.128.0.0/9"])
def test_prefix_lengths(network):
    rib_ = one_rib(PEERS + rib(m.RIB_IPV4_UNICAST, 0, prefix(network), entry(b"")))
    assert rib_.prefix == net(network)


def test_prefix_host_bits_are_an_error():
    with pytest.raises(m.MrtFormatError, match="host bits set"):
        m.parse_file(PEERS + rib(m.RIB_IPV4_UNICAST, 0, b"\x17\x0a\x00\x01", entry(b"")))


def test_prefix_too_long_is_an_error():
    with pytest.raises(m.MrtFormatError, match="prefix length 33"):
        m.parse_file(PEERS + rib(m.RIB_IPV4_UNICAST, 0, b"\x21" + bytes(5), entry(b"")))


def test_addpath_subtype_has_path_ids():
    rib_ = one_rib(PEERS + rib(m.RIB_IPV6_UNICAST_ADDPATH, 0, prefix("2001:db8::/32"),
                               entry(b"", 1, path_id=7), entry(b"", 1, path_id=8)))
    assert rib_.add_path
    assert [e.path_id for e in rib_.entries] == [7, 8]


# -- RIB_GENERIC ----------------------------------------------------------------------

RIB_VPN4_HEX = (
    "65000000" "000d" "0006" "00000020"      # ts, TABLE_DUMP_V2, RIB_GENERIC, length 32
    "00000000" "0001" "80"                   # seq 0, AFI 1, SAFI 128
    "70" "000001"                            # NLRI length 112 bits, label 0 + bottom of stack
    "6400000064000000"                       # RD, raw as the fork writes it
    "080808"                                 # 8.8.8.0/24
    "0001" "0001" "65000000" "0000"          # 1 entry: peer 1, originated, no attributes
)


def test_rib_generic_vpn4_literal():
    rib_ = one_rib(PEERS + bytes.fromhex(RIB_VPN4_HEX))
    assert (rib_.afi, rib_.safi, rib_.add_path) == (1, 128, False)
    assert isinstance(rib_.prefix, m.VpnPrefix)
    assert rib_.prefix.labels == [0x000001]
    assert rib_.prefix.rd == bytes.fromhex("6400000064000000")
    assert rib_.prefix.prefix == net("8.8.8.0/24")
    assert rib_.prefix.length_bits == 112
    assert rib_.network == net("8.8.8.0/24")


def test_rib_generic_vpn6_two_labels():
    n = net("2001:db8:5::/48")
    nlri = (struct.pack("!HB", 2, 128) + bytes([48 + 48 + 64])
            + bytes.fromhex("000640" "000651") + bytes(8) + n.network_address.packed[:6])
    rib_ = one_rib(PEERS + rib(m.RIB_GENERIC, 0, nlri, entry(b"", 1)))
    assert rib_.prefix.labels == [0x000640, 0x000651]
    assert rib_.network == n


def test_rib_generic_vpn_without_bottom_of_stack_is_an_error():
    nlri = struct.pack("!HB", 1, 128) + bytes([24 + 64]) + bytes(3) + bytes(8)
    with pytest.raises(m.MrtFormatError, match="too short for the label stack"):
        m.parse_file(PEERS + rib(m.RIB_GENERIC, 0, nlri, entry(b"")))


def test_rib_generic_unicast_safi():
    nlri = struct.pack("!HB", 1, 1) + prefix("10.0.0.0/8")
    assert one_rib(PEERS + rib(m.RIB_GENERIC, 0, nlri, entry(b""))).prefix == net("10.0.0.0/8")


def test_rib_generic_unsupported_safi_is_an_error():
    nlri = struct.pack("!HB", 1, 133) + b"\x00"
    with pytest.raises(m.MrtFormatError, match="SAFI 133"):
        m.parse_file(PEERS + rib(m.RIB_GENERIC, 0, nlri, entry(b"")))


# -- whole files ----------------------------------------------------------------------

def test_rib_before_peer_table_is_an_error():
    with pytest.raises(m.MrtFormatError, match="before any PEER_INDEX_TABLE"):
        m.parse_file(bytes.fromhex(RIB_V4_HEX))


def test_peer_index_out_of_range_is_an_error():
    data = PEERS + rib(m.RIB_IPV4_UNICAST, 0, prefix("10.0.0.0/8"), entry(b"", peer=2))
    with pytest.raises(m.MrtFormatError, match="peer index 2, peer table has 2 peers"):
        m.parse_file(data)


def test_sequence_gap_is_an_error():
    data = (PEERS + rib(m.RIB_IPV4_UNICAST, 0, prefix("10.0.0.0/8"), entry(b""))
            + rib(m.RIB_IPV4_UNICAST, 2, prefix("11.0.0.0/8"), entry(b"")))
    with pytest.raises(m.MrtFormatError, match="sequence number 2 after 0"):
        m.parse_file(data)


def test_appended_dumps_are_separate_sections():
    one_dump = (PEERS + rib(m.RIB_IPV4_UNICAST, 0, prefix("10.0.0.0/8"), entry(b""))
                + rib(m.RIB_IPV4_UNICAST, 1, prefix("11.0.0.0/8"), entry(b"")))
    f = m.parse_file(one_dump + one_dump)
    assert len(f.sections) == 2
    assert [[r.sequence for r in s.ribs] for s in f.sections] == [[0, 1], [0, 1]]
    assert len(f.by_network()[net("10.0.0.0/8")]) == 2
    with pytest.raises(LookupError, match="2 RIB records"):
        f.rib("10.0.0.0/8")


def test_other_record_types_are_kept_raw():
    bgp4mp = record(m.BGP4MP, 4, b"\x00" * 20)
    f = m.parse_file(bgp4mp + PEERS + bytes.fromhex(RIB_V4_HEX))
    assert [(r.type, r.subtype) for r in f.other] == [(m.BGP4MP, 4)]
    assert f.rib("192.168.0.0/24").entries[0].peer_index == 1
