import ipaddress
import os
from ipaddress import IPv4Address, IPv4Network
import unittest
import subprocess
from typing import List
from mrt_build_from_text import (
    MRTPeerIndexTable,
    MRTPeerIndexTableEntry,
    MRTTextEntry,
    MRTRibTableEntry,
    MRTRibTable,
    read_text_mrt_dump,
    construct_peer_table,
    construct_rib_tables,
    mrt_bytes_peer_index_table,
    mrt_bytes_single_rib_table,
    mrt_encode_prefix,
    community_xform,
    convert_text_to_binary_mrt,
    write_binary_mrt,
)


class TestMRTTextEntry(unittest.TestCase):
    def test_parse_line(self):
        actual = MRTTextEntry(
            line="TABLE_DUMP2|1520490003|B|198.108.63.60||192.86.138.0/24|11537 20965 1930|IGP|207.72.224.3|100|0|(237,1) (237,3) (237,1400) (237,11537) (11537,2501) (20965,155) (20965,65532) (20965,65533) (20965,65534)|||"
        )
        assert isinstance(actual, MRTTextEntry)
        assert actual.timestamp == 1520490003
        assert actual.peer == IPv4Address("198.108.63.60")
        assert actual.peer_as is None
        assert actual.prefix == IPv4Network("192.86.138.0/24")
        assert actual.aspath == [11537, 20965, 1930]
        assert actual.origin == "IGP"
        assert actual.nexthop == IPv4Address("207.72.224.3")
        assert actual.prf == 100
        assert actual.med == 0
        assert actual.communities == [
            0x00ED0001,  # "(237,1)",
            0x00ED0003,  # "(237,3)",
            0x00ED0578,  # "(237,1400)",
            0x00ED2D11,  # "(237,11537)",
            0x2D1109C5,  # "(11537,2501)",
            0x51E5009B,  # "(20965,155)",
            0x51E5FFFC,  # "(20965,65532)",
            0x51E5FFFD,  # "(20965,65533)",
            0x51E5FFFE,  # "(20965,65534)",
        ]
        assert actual.aggregator is None
        assert actual.aggregator_as is None

        # actual = MRTTextEntry().from_string("TABLE_DUMP2|1520490003|B|198.108.63.60||122.86.48.0/20|7018 1299 58453 9808 9394|IGP|198.108.93.55|100|0|(237,2) (237,7018)|||")
        # assert isinstance(actual, MRTTextEntry)


class TestMRTPeerIndexTableEntry(unittest.TestCase):
    def test_construction(self):
        actual = MRTPeerIndexTableEntry(IPv4Address("192.108.25.1"), 6502)
        assert isinstance(actual, MRTPeerIndexTableEntry)
        assert actual.peer_ip == IPv4Address("192.108.25.1")
        assert actual.peer_as == 6502
        assert actual.peer_bgp_id == int(IPv4Address("192.108.25.1"))
        assert actual.peer_type == 2


class TestMRTPeerIndexTable(unittest.TestCase):
    def test_construction(self):
        actual = MRTPeerIndexTable(int(IPv4Address("10.0.0.1")), "View 1")
        assert isinstance(actual, MRTPeerIndexTable)
        assert len(actual) == 0
        assert actual.collector_id == 0xA000001
        assert actual.view_name == "View 1"

    def test_str(self):
        actual = MRTPeerIndexTable(int(IPv4Address("10.0.0.1")), "View 1")
        assert str(actual) == "10.0.0.1 - View 1 - 0 peers"

    def test_len(self):
        actual = MRTPeerIndexTable(int(IPv4Address("10.0.0.1")), "View 1")
        for i in range(0, 10):
            entry = MRTPeerIndexTableEntry(IPv4Address(f"10.0.{i}.1"), 6502)
            actual.append(entry)
        assert len(actual) == 10

    def test_append(self):
        actual = MRTPeerIndexTable(int(IPv4Address("10.0.0.1")), "View 1")
        entry = MRTPeerIndexTableEntry(IPv4Address("10.0.1.1"), 6502)
        actual.append(entry)
        assert len(actual) == 1
        assert str(actual) == "10.0.0.1 - View 1 - 1 peers"
        assert actual[0] == entry

    def test_contains(self):
        actual = MRTPeerIndexTable(int(IPv4Address("10.0.0.1")), "View 1")
        entry = MRTPeerIndexTableEntry(IPv4Address("10.0.1.1"), 6502)
        actual.append(entry)
        assert len(actual) == 1
        assert str(actual) == "10.0.0.1 - View 1 - 1 peers"
        assert entry in actual

    def test_lookup_peer(self):
        actual = MRTPeerIndexTable(int(IPv4Address("10.0.0.1")), "View 1")
        entry = MRTPeerIndexTableEntry(IPv4Address("10.0.1.1"), 6502)
        actual.append(entry)
        assert len(actual) == 1
        assert str(actual) == "10.0.0.1 - View 1 - 1 peers"
        assert actual.lookup_peer(IPv4Address("10.0.1.1")) == 0
        assert actual.lookup_peer(IPv4Address("192.168.1.1")) is None


class TestMRTRibTableEntry(unittest.TestCase):
    CT: MRTRibTableEntry = MRTRibTableEntry
    TEXT_ENTRY: MRTTextEntry = MRTTextEntry(
        "TABLE_DUMP2|1520490003|B|198.108.63.60||192.86.138.0/24|11537 20965 1930|IGP|207.72.224.3|100|0|(237,1) (237,3) (237,1400) (237,11537) (11537,2501) (20965,155) (20965,65532) (20965,65533) (20965,65534)|||"
    )

    def test_construction_defaulted(self):
        actual = self.CT(1)
        assert isinstance(actual, MRTRibTableEntry)
        assert actual.peer_index == 1

    def test_construction(self):
        actual = self.CT(1, self.TEXT_ENTRY)
        assert isinstance(actual, MRTRibTableEntry)
        assert actual.peer_index == 1
        assert actual.aspath == list([11537, 20965, 1930])
        assert actual.origin == "IGP"
        assert actual.nexthop == IPv4Address("207.72.224.3")
        assert actual.prf == 100
        assert actual.med == 0
        assert actual.communities == list(
            [
                0x00ED0001,  # "(237,1)",
                0x00ED0003,  # "(237,3)",
                0x00ED0578,  # "(237,1400)",
                0x00ED2D11,  # "(237,11537)",
                0x2D1109C5,  # "(11537,2501)",
                0x51E5009B,  # "(20965,155)",
                0x51E5FFFC,  # "(20965,65532)",
                0x51E5FFFD,  # "(20965,65533)",
                0x51E5FFFE,  # "(20965,65534)",
            ]
        )
        assert actual.aggregator is None
        assert actual.aggregator_as is None


class TestMRTRibTable(unittest.TestCase):
    CT: MRTRibTable = MRTRibTable
    TIMESTAMP: int = 1520490003
    PEER_INDEX: int = 1
    PREFIX: ipaddress.IPv4Address = ipaddress.IPv4Address("46.24.26.209")

    def test_construction_defaulted(self):
        actual = self.CT(1, self.TIMESTAMP, self.PEER_INDEX, self.PREFIX)
        assert isinstance(actual, MRTRibTable)
        assert len(actual) == 0
        assert actual.sequence == 1
        assert actual.timestamp == self.TIMESTAMP
        assert actual.peer_index == self.PEER_INDEX
        assert actual.prefix == self.PREFIX


class TestFileMethods(unittest.TestCase):
    FILENAME: str = "local_bgpdump.40858.46.24.26.209.txt.gz"
    PEER_INDEX: int = 1

    def test_community_xform(self):
        assert community_xform("(237,1)") == 0x00ED0001
        assert community_xform("(237, 3)") == 0x00ED0003
        assert community_xform("(237, 1400)") == 0x00ED0578
        assert community_xform("(20965,65534)") == 0x51E5FFFE

    def test_construct_peer_table(self):
        entries = read_text_mrt_dump(os.path.join("test_data", self.FILENAME))
        actual = construct_peer_table(self.FILENAME, entries)
        assert isinstance(actual, MRTPeerIndexTable)
        assert len(actual) == 1
        assert actual.collector_id == 773331665
        assert actual.peer_count == 1
        actual_peer = actual[0]
        assert actual_peer.peer_as == 40858
        assert actual_peer.peer_bgp_id == 773331665
        assert actual_peer.peer_ip == 773331665
        assert actual_peer.peer_type == 2

    def test_parse_file(self):
        test_file = os.path.join("test_data", self.FILENAME)
        result: List[MRTTextEntry] = read_text_mrt_dump(test_file)
        assert len(result) == 190

    def test_construct_rib_tables(self):
        test_file = os.path.join("test_data", self.FILENAME)
        actual = construct_rib_tables(test_file)
        assert isinstance(actual, tuple)
        assert len(actual) == 2
        actual_peer_table = actual[0]
        assert isinstance(actual_peer_table, MRTPeerIndexTable)
        actual_rib_tables = actual[1]
        assert isinstance(actual_rib_tables, list)
        assert len(actual_rib_tables) == 190

    def test_mrt_convert_text_to_binary(self):
        test_file = os.path.join("test_data", self.FILENAME)
        output_file = "local_bgpdump.40858.46.24.26.209.ipv4.mrt"
        convert_text_to_binary_mrt(output_file, test_file)

    def test_file_write(self):
        output_path: str = "local_bgpdump.test.ipv4.mrt"
        timestamp = 0x01020304
        peer_index_table: MRTPeerIndexTable = MRTPeerIndexTable(
            collector_id=0x0A000001, view_name="test_ivp4"
        )
        peer_index_table.append(
            MRTPeerIndexTableEntry(
                peer_bgp_id=0x0A000001,
                peer_ip=IPv4Address("46.47.48.49"),
                peer_as=0xABCD,
            )
        )
        peer_index_table.append(
            MRTPeerIndexTableEntry(
                peer_bgp_id=0x0A000001,
                peer_ip=IPv4Address("47.47.48.49"),
                peer_as=0xBCDE,
            )
        )

        rib_tables: List[MRTRibTable] = []
        rib_table: MRTRibTable = MRTRibTable(
            sequence=0,
            timestamp=0x01020304,
            peer_index=1,
            prefix=IPv4Network("172.19.0.0/16"),
        )
        rib_table.append(
            MRTRibTableEntry(
                peer_index=1,
                text_entry=MRTTextEntry(
                    "|".join(
                        [
                            "TABLE_DUMP2",
                            "1616629181",
                            "B",
                            "172.17.0.7",
                            "",
                            "172.19.0.0/16",
                            "123 456",
                            "IGP",
                            "172.18.0.1",
                            "100",
                            "0",
                            "(237,1) (237,3) (237,1400)",
                            "",
                            "",
                            "",
                        ]
                    )
                ),
            )
        )
        rib_tables.append(rib_table)

        write_binary_mrt(
            output_path, timestamp, peer_index_table, rib_tables, progress=False
        )

        assert os.path.isfile(output_path)
        bgpdump_path = "../../bgpdump"
        proc_res: subprocess.CompletedProcess = subprocess.run(
            [bgpdump_path, output_path],
            cwd="/home/peterwinkler/src/deepfield/private/bird2/tools/df",
            capture_output=True,
        )
        assert proc_res.returncode == 0
        output = proc_res.stdout.decode("utf-8").split("\n")
        assert output == [
            "TIME: 07/15/70 16:57:40",
            "TYPE: TABLE_DUMP_V2/IPV4_UNICAST",
            "PREFIX: 172.19.0.0/16",
            "SEQUENCE: 0",
            "FROM: 46.47.48.49 AS43981",
            "ORIGINATED: 03/24/21 23:39:41",
            "ORIGIN: IGP",
            "ASPATH: 123 456",
            "NEXT_HOP: 172.18.0.1",
            "LOCAL_PREF: 100",
            "COMMUNITY: 237:1 237:3 237:1400",
            "",
            "",
        ]


class TestMRTBytes(unittest.TestCase):
    TIMESTAMP: int = 0x5F354BCE

    def test_mrt_encode_prefix(self):
        assert mrt_encode_prefix(IPv4Network("10.0.0.0/8")) == b"\x08\x0a"
        assert mrt_encode_prefix(IPv4Network("10.128.0.0/9")) == b"\x09\x0a\x80"
        assert mrt_encode_prefix(IPv4Network("10.0.0.0/16")) == b"\x10\x0a\x00"
        assert mrt_encode_prefix(IPv4Network("10.1.128.0/17")) == b"\x11\x0a\x01\x80"
        assert mrt_encode_prefix(IPv4Network("10.1.2.0/24")) == b"\x18\x0a\x01\x02"
        assert (
            mrt_encode_prefix(IPv4Network("10.1.2.128/25")) == b"\x19\x0a\x01\x02\x80"
        )

    def test_mrt_bytes_peer_index_table(self):
        table: MRTPeerIndexTable = MRTPeerIndexTable(
            collector_id=0x0A000001, view_name="mastervpn4"
        )
        table.append(
            MRTPeerIndexTableEntry(
                peer_bgp_id=0x0A000002,
                peer_ip=IPv4Address("172.23.0.7"),
                peer_as=0xFDEA,
            )
        )
        actual = mrt_bytes_peer_index_table(self.TIMESTAMP, table)
        assert isinstance(actual, bytes)
        assert len(actual) == 68
        assert actual[:4] == b"\x5f\x35\x4b\xce", "timestamp"
        assert actual[4:6] == b"\x00\x0d", "table type"
        assert actual[6:8] == b"\x00\x01", "table subtype"
        assert actual[8:12] == b"\x00\x00\x00\x40", "entry length"
        assert actual[12:16] == b"\x0a\x00\x00\x01", "collector id"
        assert actual[16:18] == b"\x00\x0a", "view name length"
        assert actual[18:28] == b"\x6d\x61\x73\x74\x65\x72\x76\x70\x6e\x34", "view name"
        assert actual[28:30] == b"\x00\x02", "peer count"
        assert actual[30:31] == b"\x03", "peer type 4 octet as + AFI==IPV6"
        assert actual[31:35] == bytes(4), "0.0.0.0 collector id"
        assert actual[35:51] == bytes(16), "::0 ipv6 address"
        assert actual[51:55] == bytes(4), "0 as"
        assert actual[55:56] == b"\x02", "peer type 4 octet as + AFI=IPv4"
        assert actual[56:60] == b"\x0a\x00\x00\x02", "collector id 10.0.0.2"
        assert actual[60:64] == b"\xac\x17\x00\x07", "ip address 172.23.0.7"
        assert actual[64:68] == b"\x00\x00\xfd\xea", "as 0xfdea"

    def test_mrt_bytes_single_rib_table(self):
        table: MRTRibTable = MRTRibTable(
            sequence=0,
            timestamp=0x605BCDF6,
            peer_index=1,
            prefix=IPv4Network("172.19.0.0/16"),
        )
        entry = MRTRibTableEntry(
            peer_index=1,
            text_entry=MRTTextEntry(
                "TABLE_DUMP2|1616629181|B|172.17.0.7||172.19.0.0/16|123 456|IGP|172.18.0.1|100|0|(237,1) (237,3) (237,1400)|||"
            ),
        )
        table.append(entry)
        actual = mrt_bytes_single_rib_table(table)
        assert isinstance(actual, bytes)
        assert actual[:4] == b"\x60\x5b\xcd\xf6", "timestamp"
        assert actual[4:6] == b"\x00\x0d", "type - table dump v2"
        assert actual[6:8] == b"\x00\x02", "subtype - 2"
        assert actual[8:12] == b"\x00\x00\x00\x3f", "entry length"
        assert actual[12:16] == b"\x00\x00\x00\x00", "sequence number"
        assert actual[16:17] == b"\x10", "prefix length"
        assert actual[17:19] == b"\xac\x13", "prefix"
        assert actual[19:21] == b"\x00\x01", "entry count"
        assert actual[21:23] == b"\x00\x01", "peer index"
        assert actual[23:27] == b"\x60\x5b\xcd\xbd", "originating time"
        assert actual[27:29] == b"\x00\x2e", "attribute length"
        assert actual[29:33] == b"\x40\x01\x01\x00", "origin"
        assert actual[33:35] == b"\x40\x02", "aspath flag and type"
        assert actual[35:36] == b"\x0a", "aspath octet length"
        assert actual[36:37] == b"\x02", "aspath type sequence"
        assert actual[37:38] == b"\x02", "aspath $ of asns"
        assert actual[38:46] == b"\x00\x00\x00\x7b\x00\x00\x01\xc8", "aspath"
        assert actual[46:53] == b"\x00\x03\x04\xac\x12\x00\x01", "nexthop"
        assert actual[53:60] == b"\x40\x05\x04\x00\x00\x00\x64", "local pref"
        # (237, 1)(237, 3)(237, 1400)
        assert actual[60:63] == b"\x40\x08\x0c", "community header"
        assert actual[63:67] == b"\x00\xed\x00\x01", "community #0"
        assert actual[67:71] == b"\x00\xed\x00\x03", "community #1"
        assert actual[71:75] == b"\x00\xed\x05\x78", "community #2"
        assert len(actual) == 75


if __name__ == "__main__":
    unittest.main()
    exit(0)
