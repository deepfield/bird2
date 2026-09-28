"""
Phase 6: how dumps are produced, beyond what is in them. PLAN.md findings 15 and 16.

  - Large tables (finding 15). A dump step writes about 2048 records' worth of routes
    (s->max, mrt.c:738) and then yields; the next step resumes the table iterator. The
    fork patched the resume to set mp_reach again (mrt.c:741-744); without that, IPv6 and
    VPN entries after the first step lose their next hop. Every route carries its own MED
    and next hop, so an entry that ends up with another route's attributes shows.
  - Files (finding 16). The filename is used literally and opened for append: repeated
    dumps add sections, a pattern dump writes one section per table with the sequence
    number running on, and an over-long filename overflows mrt_open_file's buffer.
  - Odds and ends: an empty table, `mrt dump ... where`, an unopenable file.
"""

import struct
import time

import pytest

import bgpdump
import birdlab
import mrt_reader as m

# NV4 stays below ~2996: beyond that the product's bgpdump corrupts VPN output (finding
# 26, test_bgpdump.py). 2500 routes still take several dump steps.
N4, N6, NV4 = 5000, 5000, 2500
SMALL = {"t4": [("10.1.0.0/16", 1), ("10.2.0.0/16", 2), ("10.3.0.0/16", 3)],
         "pa4": [("10.11.0.0/16", 11), ("10.12.0.0/16", 12), ("10.13.0.0/16", 13)],
         "pb4": [("10.21.0.0/16", 21), ("10.22.0.0/16", 22)]}


def big4(i):
    return f"10.{i >> 8}.{i & 255}.0/24", f"172.16.{i >> 8}.{i & 255}"


def big6(i):
    return f"2001:db8:{i:x}::/48", f"2001:db8:ffff::{i:x}"


def bigv4(i):
    return f"65000:{i} 198.51.100.0/24", f"172.17.{i >> 8}.{i & 255}"


def u32(v) -> bytes:
    return struct.pack("!I", v)


def render(log, dumpdir) -> str:
    def static(name, afi, table, routes):
        body = "".join(f"  route {net} blackhole {{ {stmts} }};\n" for net, stmts in routes)
        return f"protocol static {name} {{\n  {afi} {{ table {table}; }};\n{body}}}\n"

    out = [birdlab.prolog("10.0.0.1", log), "debug protocols { events };\n",
           "ipv4 table big4;\nipv6 table big6;\nvpn4 table bigv4;\n",
           "ipv4 table t4;\nipv4 table pa4;\nipv4 table pb4;\nipv4 table empty4;\n"]
    out.append(static("sbig4", "ipv4", "big4", [
        (big4(i)[0], f"bgp_med = {i}; bgp_next_hop = {big4(i)[1]};") for i in range(1, N4 + 1)]))
    out.append(static("sbig6", "ipv6", "big6", [
        (big6(i)[0], f"bgp_med = {i}; bgp_next_hop = {big6(i)[1]};") for i in range(1, N6 + 1)]))
    out.append(static("sbigv4", "vpn4", "bigv4", [
        (bigv4(i)[0], f"bgp_med = {i}; bgp_next_hop = {bigv4(i)[1]};") for i in range(1, NV4 + 1)]))
    for table, routes in SMALL.items():
        out.append(static(f"s_{table}", "ipv4", table,
                          [(net, f"bgp_med = {med};") for net, med in routes]))
    # The same large table through the periodic path (protocol mrt), as production dumps.
    out.append(f'protocol mrt pbig6 {{ table big6; filename "{dumpdir}/periodic_big6.mrt"; '
               f"period 1; }}\n")
    return "".join(out)


@pytest.fixture(scope="module")
def mech(lab, bird_bin, tmp_path_factory):
    """(dut, dumpdir)"""
    dumpdir = tmp_path_factory.mktemp("mechanics")
    dut = lab.bird("dut", render(lab.log_path("dut"), dumpdir), bird_bin)
    for table, n in (("big4", N4), ("big6", N6), ("bigv4", NV4),
                     ("t4", 3), ("pa4", 3), ("pb4", 2)):
        dut.wait_routes(table, n, timeout=60)
    since = dut.mrt_dump_events()
    dut.wait_periodic_dumps(since, timeout=60)
    dut.disable("pbig6")
    return dut, dumpdir


@pytest.fixture(scope="module")
def big_dumps(mech):
    dut, dumpdir = mech
    return {t: dut.mrt_dump(t, dumpdir / f"{t}.mrt") for t in ("big4", "big6", "bigv4")}


def section_key(s: m.Section):
    """What a dump says, minus timestamps."""
    return ([(p.peer_type, p.bgp_id, p.ip, p.asn) for p in s.peer_table.peers],
            [(r.record.subtype, r.sequence, r.prefix,
              [(e.peer_index, [(a.flags, a.code, a.value) for a in e.attributes])
               for e in r.entries]) for r in s.ribs])


def vpn_index(rd: bytes) -> int:
    """The route number of a 65000:<i> RD, as the fork writes it (little-endian u64)."""
    value = struct.unpack("<Q", rd)[0]
    assert value >> 32 == 65000, rd.hex()
    return value & 0xFFFFFFFF


def expected_entry(table, i):
    med = (0x00, m.MED, u32(i))
    if table == "big4":
        return [(0x00, m.NEXT_HOP, m.ipaddress.IPv4Address(big4(i)[1]).packed), med]
    nh = m.ipaddress.ip_address(big6(i)[1] if table == "big6" else f"::ffff:{bigv4(i)[1]}")
    return [med, (0x00, m.MP_REACH_NLRI, bytes([16]) + nh.packed)]


def route_index(table, rib: m.Rib) -> int:
    if table == "bigv4":
        return vpn_index(rib.prefix.rd)
    net = rib.network
    if table == "big4":
        a = net.network_address.packed
        return a[1] << 8 | a[2]
    return int.from_bytes(net.network_address.packed[4:6], "big")


@pytest.mark.parametrize("table,n", [("big4", N4), ("big6", N6), ("bigv4", NV4)])
def test_large_table_dump(big_dumps, table, n):
    """Every route once, sequence 0..n-1, each entry with its own route's attributes."""
    [section] = m.read(big_dumps[table]).sections
    assert [r.sequence for r in section.ribs] == list(range(n))
    seen = set()
    for rib in section.ribs:
        i = route_index(table, rib)
        seen.add(i)
        [e] = rib.entries
        assert [(a.flags, a.code, a.value) for a in e.attributes] == expected_entry(table, i), \
            f"{rib.prefix}: record {rib.sequence}"
    assert seen == set(range(1, n + 1))


@pytest.mark.parametrize("table,n", [("big4", N4), ("big6", N6), ("bigv4", NV4)])
def test_large_table_bgpdump(big_dumps, bgpdump_bin, table, n):
    result = bgpdump.run(big_dumps[table], bgpdump_bin)
    assert result.problems == []
    assert len(result.rows) == n
    for row in result.rows:
        if table == "bigv4":
            i = int(row.rd.split(":")[1])
            assert row.next_hop == f"::ffff:{bigv4(i)[1]}"
        else:
            addr = m.ipaddress.ip_network(row.prefix).network_address.packed
            i = (addr[1] << 8 | addr[2]) if table == "big4" else int.from_bytes(addr[4:6], "big")
            assert row.next_hop == (big4(i)[1] if table == "big4" else big6(i)[1])
        assert row.med == i


def test_periodic_dump_of_large_table_matches_cli(mech, big_dumps):
    """The protocol mrt path (timer + events) writes what `mrt dump` writes."""
    dut, dumpdir = mech
    periodic = m.read(dumpdir / "periodic_big6.mrt").sections
    complete = [s for s in periodic if len(s.ribs) == N6]
    assert complete, [len(s.ribs) for s in periodic]
    [cli] = m.read(big_dumps["big6"]).sections
    assert all(section_key(s) == section_key(cli) for s in complete)


def test_repeated_dumps_append(mech):
    dut, dumpdir = mech
    path = dumpdir / "twice.mrt"
    dut.mrt_dump("t4", path)
    dut.mrt_dump("t4", path)
    sections = m.read(path).sections
    assert len(sections) == 2
    # Each dump starts its own sequence and says the same thing.
    assert [[r.sequence for r in s.ribs] for s in sections] == [[0, 1, 2], [0, 1, 2]]
    assert section_key(sections[0]) == section_key(sections[1])


def test_pattern_dump_one_section_per_table(mech):
    """A pattern dump writes each table's section in turn; the sequence number runs on
    across tables (one counter per dump, mrt.c:686), it restarts only with a new dump."""
    dut, dumpdir = mech
    path = dut.mrt_dump('"p*"', dumpdir / "pattern.mrt")
    sections = m.read(path).sections
    assert [s.peer_table.view_name for s in sections] == ["pa4", "pb4"]
    assert [[r.sequence for r in s.ribs] for s in sections] == [[0, 1, 2], [3, 4]]
    assert [sorted(str(r.network) for r in s.ribs) for s in sections] == [
        sorted(n for n, _ in SMALL["pa4"]), sorted(n for n, _ in SMALL["pb4"])]


def test_filename_is_literal(mech):
    """Upstream expands %N (table name) and strftime patterns; the fork opens the name as is."""
    dut, dumpdir = mech
    name = dumpdir / "dump-%N-%Y.mrt"
    dut.mrt_dump("t4", name)
    assert name.exists()
    assert not (dumpdir / f"dump-t4-{time.gmtime().tm_year}.mrt").exists()
    assert len(m.read(name).sections) == 1


def test_empty_table(mech, bgpdump_bin):
    dut, dumpdir = mech
    path = dut.mrt_dump("empty4", dumpdir / "empty.mrt")
    [section] = m.read(path).sections
    assert (section.peer_table.view_name, section.ribs) == ("empty4", [])
    result = bgpdump.run(path, bgpdump_bin)
    assert (result.rows, result.problems) == ([], [])


def test_where_filter(mech):
    dut, dumpdir = mech
    path = dumpdir / "filtered.mrt"
    dut.cmd(f'mrt dump table t4 to "{path}" where bgp_med >= 2')
    [section] = m.read(path).sections
    assert sorted(str(r.network) for r in section.ribs) == ["10.2.0.0/16", "10.3.0.0/16"]
    assert [r.sequence for r in section.ribs] == [0, 1]


def test_unopenable_file_is_reported(mech):
    """BIRD reports it on the CLI (as an 8009 line inside a successful reply) and carries on."""
    dut, dumpdir = mech
    with pytest.raises(birdlab.BirdError, match="Unable to open MRT file"):
        dut.mrt_dump("t4", dumpdir / "no-such-dir" / "x.mrt")
    assert dut.running()
    assert dut.route_count("t4") == 3


@pytest.fixture(scope="module")
def long_filename_dut(lab, bird_bin, tmp_path_factory):
    """A daemon whose protocol mrt filename is longer than PATH_MAX (4096)."""
    dumpdir = tmp_path_factory.mktemp("long")
    name = dumpdir / ("x" * 4200 + ".mrt")
    dut = lab.bird("dut_long", birdlab.prolog("10.0.0.2", lab.log_path("dut_long"))
                   + "ipv4 table t4;\n"
                   + "protocol static { ipv4 { table t4; }; route 10.1.0.0/16 blackhole; }\n"
                   + f'protocol mrt longname {{ table t4; filename "{name}"; period 1; }}\n',
                   bird_bin)
    assert dut.running()                    # the config itself is accepted
    time.sleep(2.5)                         # past the first periodic dump
    return dut


@pytest.mark.xfail(strict=True, reason="finding 16: mrt_open_file strcpy()s the filename into "
                                       "a PATH_MAX buffer (mrt.c:263); glibc aborts the daemon "
                                       "('buffer overflow detected')")
def test_long_filename_does_not_crash(long_filename_dut):
    assert long_filename_dut.running()
