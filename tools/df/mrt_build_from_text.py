"""
take some gz mrt text dumps and make binary mrts from it

NOTE: the data will not be complete since peer index information is not available
in text based mrt dumps
"""

import gzip
import argparse
import ipaddress
import os
import struct
import tqdm
from tqdm import tqdm
from tqdm.utils import CallbackIOWrapper

from collections.abc import MutableSequence
from typing import List, Any, Optional, Dict, Iterable, Tuple


def community_xform(community_str: str) -> int:
    if community_str.startswith("("):
        community_str = community_str[1:]
    if community_str.endswith(")"):
        community_str = community_str[:-1]
    parts = community_str.split(",")
    return int(int(parts[0]) << 16) + int(parts[1])


class MRTTextEntry:
    type_str: str
    timestamp: int
    peer: ipaddress.IPv4Address
    peer_as: Optional[int]
    prefix: ipaddress.IPv4Network
    aspath: List[int]
    origin: str
    nexthop: ipaddress.IPv4Address
    prf: Optional[int]
    med: Optional[int]
    communities: List[str]
    aggregator: Optional[str]
    aggregator_as: Optional[int]

    def __init__(self, line: Optional[str] = None):
        if line:
            self.from_string(line)

    def from_string(self, line: str):
        """ convert string to peer table entry"""
        # TABLE_DUMP2|1520490003|B|198.108.63.60||192.86.138.0/24|11537 20965 1930|IGP|207.72.224.3|100|0|(237,1) (237,3) (237,1400) (237,11537) (11537,2501) (20965,155) (20965,65532) (20965,65533) (20965,65534)|||
        parts = line.split("|")
        if parts[0] != "TABLE_DUMP2":
            print(f"wrong line format {line}")
            return
        self.type_str = parts[0]
        self.timestamp = int(parts[1])
        self.peer = ipaddress.IPv4Address(parts[3])
        self.peer_as = int(parts[4]) if len(parts[4]) > 0 else None
        self.prefix = ipaddress.IPv4Network(parts[5].replace(" ", ""))
        aspath_raw = parts[6].split(" ")
        self.aspath = [int(x) for x in aspath_raw if len(x) > 0 and x not in ["{", "}"]]
        self.origin = parts[7]
        self.nexthop = ipaddress.IPv4Address(parts[8])
        self.prf = int(parts[9]) if len(parts[9]) > 0 else None
        self.med = int(parts[10]) if len(parts[10]) > 0 else None
        communities_raw = parts[11]
        self.communities = [
            community_xform(x) for x in communities_raw.split(" ") if len(x) > 0
        ]
        self.aggregator = parts[12] if len(parts[12]) else None
        self.aggregator_as = int(parts[13]) if len(parts[13]) > 0 else None


def read_text_mrt_dump(
    path: str, progress: Optional[bool] = False
) -> List[MRTTextEntry]:
    result: List[MRTTextEntry] = []
    line: int = 0
    pbar = None

    if path.endswith(".gz"):
        if progress:
            size = os.path.getsize(path)
            print(f"Reading {path}  ")
            pbar = tqdm(total=size, unit="b", unit_scale=True, unit_divisor=1024)
            # ... continue to use `t` for something else
        with open(path, "rb") as compressed_file:
            with tqdm(total=size, unit="B", unit_scale=True, unit_divisor=1024) as t:
                fobj = CallbackIOWrapper(t.update, compressed_file, "read")
                with gzip.GzipFile(fileobj=fobj) as gz:
                    for x in gz:
                        result.append(MRTTextEntry(x.decode("utf-8")))
                t.reset()
    else:
        with open(path, "r") as f:
            with tqdm(unit="B", unit_scale=True, unit_divisor=1024) as t:
                fobj = CallbackIOWrapper(t.update, f, "read")
                for x in fobj:
                    result.append(MRTTextEntry(x))

    if pbar:
        print("Done.")
    return result


class MRTPeerIndexTableEntry:
    peer_type: int
    peer_bgp_id: int
    peer_ip: ipaddress.IPv4Address
    peer_as: int

    def __init__(
        self,
        peer_ip: ipaddress.IPv4Address,
        peer_as: int,
        peer_bgp_id: Optional[int] = None,
        peer_type: Optional[int] = None,
    ):
        self.peer_ip = peer_ip
        self.peer_as = peer_as
        self.peer_bgp_id = peer_bgp_id if peer_bgp_id else int(self.peer_ip)
        self.peer_type = peer_type if peer_type else 2


class MRTPeerIndexTable(MutableSequence):
    collector_id: int
    view_name: str
    peer_count: int
    peer_entries: Optional[List[MRTPeerIndexTableEntry]]

    def __init__(self, collector_id: int, view_name: str):
        self.collector_id = collector_id
        self.view_name = view_name
        self.peer_count = 0
        self.peer_entries = []
        self.peer_lookup_cache = None

    def __len__(self):
        return len(self.peer_entries)

    def __str__(self):
        ip = ipaddress.IPv4Address(self.collector_id)
        return f"{ip} - {self.view_name} - {self.peer_count} peers"

    def __contains__(self, item):
        return item in self.peer_entries

    def __getitem__(self, index):
        return self.peer_entries[index]

    def __setitem__(self, index, value):
        self.peer_entries[index] = value
        self.peer_lookup_cache = None

    def __delitem__(self, index):
        del self.peer_entries[index]
        self.peer_count = len(self.peer_entries)
        self.peer_lookup_cache = None

    def insert(self, index, value) -> None:
        self.peer_entries.insert(index, value)
        self.peer_count = len(self.peer_entries)
        self.peer_lookup_cache = None

    def append(self, value) -> None:
        self.peer_entries.append(value)
        self.peer_count = len(self.peer_entries)
        self.peer_lookup_cache = None

    def clear(self) -> None:
        self.peer_entries.clear()
        self.peer_count = 0
        self.peer_lookup_cache = None

    def reverse(self) -> None:
        raise NotImplementedError

    def extend(self, values: Iterable[MRTPeerIndexTableEntry]) -> None:
        self.peer_entries.extend(values)
        self.peer_count = len(self.peer_entries)
        self.peer_lookup_cache = None

    def remove(self, value) -> None:
        self.peer_entries.remove(value)
        self.peer_count = len(self.peer_entries)
        self.peer_lookup_cache = None

    def pop(self, index=-1) -> MRTPeerIndexTableEntry:
        result = self.peer_entries[index]
        del self.peer_entries[index]
        self.peer_count = len(self.peer_entries)
        self.peer_lookup_cache = None
        return result

    def lookup_peer(self, peer: ipaddress.IPv4Address) -> int:
        if self.peer_lookup_cache is None:
            self.refresh_peer_lookup_cache()
        return self.peer_lookup_cache.get(int(peer))

    def refresh_peer_lookup_cache(self):
        self.peer_lookup_cache = {
            int(e.peer_ip): i for i, e in enumerate(self.peer_entries)
        }

    @classmethod
    def make_peer_dictionary(cls, entries: List[MRTTextEntry]) -> Dict[int, int]:
        return {int(e.peer): e.peer_as for e in entries}


def construct_peer_table(
    filename: str, entries: List[MRTTextEntry], progress: Optional[bool] = False
) -> MRTPeerIndexTable:
    """
    construct a peer table
    clues from the filename of the text based mrt dump are needed
    i.e local_bgpdump.40858.46.24.26.209.txt.gz
    means AS.......................: 40858
          collector ip (and id)....: 46.24.26.209  773331665
    """
    collector_id: int = 0
    peer_ip: Optional[ipaddress.IPv4Address] = None
    peer_as: int = 0

    if not filename.startswith("local_bgpdump"):
        raise ValueError(f"filename {filename} does not start with local_bgpdump")

    filename = filename.replace("local_bgpdump.", "")
    pos = filename.find(".")
    peer_as = int(filename[:pos])
    filename = filename[pos + 1 :]
    if filename.endswith(".gz"):
        filename = filename[:-3]
    if filename.endswith(".txt"):
        filename = filename[:-4]
    peer_ip = ipaddress.IPv4Address(filename)
    collector_id = int(peer_ip)
    session_id: str = str(peer_ip).replace(".", "_")
    view_name: str = f"bgp_session_{session_id}_ipv4"
    result: MRTPeerIndexTable = MRTPeerIndexTable(collector_id, view_name)

    peers: Dict[int, int] = MRTPeerIndexTable.make_peer_dictionary(entries)
    for p in peers.items():
        result.append(MRTPeerIndexTableEntry(p[0], p[1] or peer_as))

    result.refresh_peer_lookup_cache()
    return result


class MRTRibTableEntry(object):
    peer_index: int
    originating_time: int

    aspath: List[int]
    origin: str
    nexthop: ipaddress.IPv4Address
    prf: Optional[int]
    med: Optional[int]
    communities: List[str]
    aggregator: Optional[ipaddress.IPv4Address]
    aggregator_as: Optional[int]

    def __init__(self, peer_index: int, text_entry: Optional[MRTTextEntry] = None):
        self.peer_index = peer_index
        if text_entry:
            self.from_text_entry(text_entry)

    def from_text_entry(self, text_entry: MRTTextEntry) -> None:
        self.originating_time = text_entry.timestamp

        self.aspath = list(text_entry.aspath)
        self.origin = text_entry.origin
        self.nexthop = ipaddress.IPv4Address(text_entry.nexthop)
        self.prf = text_entry.prf
        self.med = text_entry.med
        self.communities = list(text_entry.communities)
        self.aggregator = None
        self.aggregator_as = None
        if text_entry.aggregator:
            self.aggregator = ipaddress.IPv4Address(text_entry.aggregator)
            self.aggregator_as = text_entry.aggregator_as


class MRTRibTable(MutableSequence):
    """ IPv4 Unicast only right now"""

    sequence: int
    timestamp: int
    peer_index: int
    prefix: ipaddress.IPv4Network

    entries: List[MRTRibTableEntry]

    def __init__(
        self,
        sequence: int,
        timestamp: int,
        peer_index: int,
        prefix: ipaddress.IPv4Address,
    ):
        self.sequence = sequence
        self.timestamp = timestamp
        self.peer_index = peer_index
        self.prefix = prefix
        self.entries = []

    def __len__(self):
        return len(self.entries)

    def __str__(self):
        length = len(self)
        return f"{length} entries"

    def __contains__(self, item: MRTRibTableEntry):
        return item in self.entries

    def __getitem__(self, index: int):
        return self.entries[index]

    def __setitem__(self, index: int, value: MRTRibTableEntry):
        self.entries[index] = value

    def __delitem__(self, index: int):
        del self.entries[index]

    def insert(self, index: int, value: MRTRibTableEntry) -> None:
        self.entries.insert(index, value)

    def append(self, value: MRTRibTableEntry) -> None:
        self.entries.append(value)

    def clear(self) -> None:
        self.entries.clear()

    def reverse(self) -> None:
        raise NotImplementedError

    def extend(self, values: Iterable[MRTRibTableEntry]) -> None:
        self.peer_entries.extend(values)

    def remove(self, value: MRTRibTableEntry) -> None:
        self.peer_entries.remove(value)

    def pop(self, index: int = -1) -> MRTRibTableEntry:
        result = self.peer_entries[index]
        del self.peer_entries[index]
        self.peer_count = len(self.peer_entries)
        return result


"""
MRT Header
    Timestamp: 1611255769(2021-01-21 19:02:49)
    Type: 13(TABLE_DUMP_V2)
    Subtype: 1(PEER_INDEX_TABLE)
    Length: 3712
PEER_INDEX_TABLE
    Collector: 64.156.49.48
    View Name Length: 26
    View Name: bgp_session_4_68_34_1_ipv4
    Peer Count: 282
    Peer Type: 0x03
    Peer BGP ID: 0.0.0.0
    Peer IP Address: ::
    Peer AS: 0
    Peer Type: 0x02
    Peer BGP ID: 4.68.15.0
    Peer IP Address: 4.68.15.0
    Peer AS: 3356
    Peer Type: 0x02
    Peer BGP ID: 4.68.15.10
    Peer IP Address: 4.68.15.10
    Peer AS: 3356
    ...
    
---------------------------------------------------------------
MRT Header
    Timestamp: 1611255769(2021-01-21 19:02:49)
    Type: 13(TABLE_DUMP_V2)
    Subtype: 2(RIB_IPV4_UNICAST)
    Length: 62
RIB_IPV4_UNICAST
    Sequence Number: 0
    Prefix Length: 0
    Prefix: 0.0.0.0
    Entry Count: 1
    Peer Index: 159
    Originated Time: 1610467498(2021-01-12 16:04:58)
    Attribute Length: 47
    Path Attribute Flags/Type/Length: 0x40/1/1
        ORIGIN: 0(IGP)
    Path Attribute Flags/Type/Length: 0x50/2/0
        AS_PATH
    Path Attribute Flags/Type/Length: 0x00/3/4
        NEXT_HOP: 205.171.0.58
    Path Attribute Flags/Type/Length: 0x40/5/4
        LOCAL_PREF: 50
    Path Attribute Flags/Type/Length: 0xc0/8/4
        COMMUNITY: 209:450
    Path Attribute Flags/Type/Length: 0x80/9/4
        ORIGINATOR_ID: 205.171.0.58
    Path Attribute Flags/Type/Length: 0x80/10/8
        CLUSTER_LIST: 4.68.34.1 67.14.131.87
---------------------------------------------------------------
MRT Header
    Timestamp: 1611255769(2021-01-21 19:02:49)
    Type: 13(TABLE_DUMP_V2)
    Subtype: 2(RIB_IPV4_UNICAST)
    Length: 122
RIB_IPV4_UNICAST
    Sequence Number: 1
    Prefix Length: 23
    Prefix: 223.94.242.0
    Entry Count: 1
    Peer Index: 159
    Originated Time: 1610529327(2021-01-13 09:15:27)
    Attribute Length: 104
    ...0    
"""


def construct_rib_tables(
    path: str, progress: bool = False
) -> Tuple[MRTPeerIndexTable, List[MRTRibTable]]:

    filename: str = os.path.basename(path)
    entries: List[MRTTextEntry] = read_text_mrt_dump(path, progress)
    peer_index_table: MRTPeerIndexTable = construct_peer_table(
        filename, entries, progress
    )
    rib_tables: List[MRTRibTable] = []
    sequence: int = 0

    for text_entry in entries:
        peer_index = peer_index_table.lookup_peer(text_entry.peer)
        rib_table_entry = MRTRibTableEntry(peer_index, text_entry)
        rib_table = MRTRibTable(
            sequence, text_entry.timestamp, peer_index, text_entry.prefix
        )
        rib_table.append(rib_table_entry)
        sequence += 1
        rib_tables.append(rib_table)

    return (peer_index_table, rib_tables)


"""
00000000  60 5b cd f6                                        timestamp
            00 0d                                            type: table dump v2
            00 01                                            subtype: peer table
            00 00 00 35                                      entry length
            0a 00 00 01                                      collector id 10.0.0.1
00000010  00 07                                              view name lengthj
            6d 61 73 74 65 72  34                            view name "master4" 
            00 02 
            03                                               peer type 0x2 4 octet as + 0x1 ipv6
            00 00 00 00                                      collector_id 0
00000020    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 ::0 ipv6 
00000030  00 00 00 00                                        as 0
            02                                               peer type 0x2 4 octet as + ipv4 
            0a 00 01  01                                     peer id 
            ac 12 00 07                                      peer ip 
            00 00 fd    
00000040  e8                                                 peer as 
            60 5b cd f6                  7                    timestamp 
            00 0d                                            type: table dump v3
            00  02                                           subtype: ipv4 unicast
            00 00 00 30                                      length 
            00 00 00 
00000050  00                                                 sequence # 
            10                                               prefix length - 16 
            ac 13                                            prefix 
            00 01                                            entry count 
            00 01                                            peer index  
            60 5b cd bd                                      originating time 
            00 1f                                            attribute length 
            40 01                                            origin   
00000060  01 00                                              length + igp
            40 02                                            aspath 
            0a                                               length in octets 
            02                                               type 
            02                                               length in as
            00  00 00 7b                                     as#0 
            00 00 01 c8                                      as#1
            00  
00000070  03                                                 nexthop 
            04                                               length 
            ac 12 00 01                                      172.18.0.1
            40 05                                            local pref  
            04                                               length 
            00 00 00 64                                      100
"""


def mrt_common_header(timestamp: int, type: int, subtype: int) -> bytes:
    ts_bytes = struct.pack(">I", timestamp)
    header_bytes = struct.pack(">hh", type, subtype)
    return ts_bytes + header_bytes


def mrt_bytes_peer_index_table(
    timestamp: int, table: MRTPeerIndexTable, progress: Optional[bool] = False
) -> bytes:
    common_bytes = mrt_common_header(timestamp, 13, 1)
    id_bytes = struct.pack(">I", table.collector_id)

    rest: bytes = bytes()
    collector_bytes = struct.pack(">I", table.collector_id)
    rest += collector_bytes
    viewname_bytes = table.view_name.encode("utf-8")
    viewname_length_bytes = struct.pack(">h", len(viewname_bytes))
    rest += viewname_length_bytes + viewname_bytes
    peer_count_bytes = struct.pack(">h", len(table.peer_entries) + 1)
    rest += peer_count_bytes
    # always write 0.9.0.0 as a ivp6 entry
    default_route_bytes = bytes.fromhex("03") + bytes(4 + 16 + 4)
    rest += default_route_bytes
    for peer_entry in table.peer_entries:
        peer_type_byte = struct.pack(">b", peer_entry.peer_type)
        peer_bgp_id_bytes = struct.pack(">I", peer_entry.peer_bgp_id)
        peer_bgp_ip_bytes = struct.pack(">I", int(peer_entry.peer_ip))
        peer_as_bytes = struct.pack(">I", peer_entry.peer_as)
        rest += peer_type_byte + peer_bgp_id_bytes + peer_bgp_ip_bytes + peer_as_bytes

    mrt_entry_length = len(rest)  # common bytes have been read by then
    mrt_entry_length_bytes = struct.pack(">I", mrt_entry_length)
    result: bytes = common_bytes + mrt_entry_length_bytes + rest
    if progress:
        bl = len(result)
        pc = len(table.peer_entries)
        print(f"{bl:10d} bytes for {pc:10d} in peer_index_table")
    return result


def mrt_encode_prefix(prefix: ipaddress.IPv4Network) -> bytes:
    octets = int(int(prefix.prefixlen + 7) / 8)
    prefix_bytes = int(prefix.network_address).to_bytes(length=4, byteorder="big")
    return (
        int(prefix.prefixlen).to_bytes(length=1, byteorder="big")
        + prefix_bytes[:octets]
    )


def mrt_bytes_single_rib_table(table: MRTRibTable) -> bytes:
    common_bytes: bytes = mrt_common_header(table.timestamp, 13, 2)

    rest = bytes()
    sequence_bytes = struct.pack(">I", table.sequence)
    rest += sequence_bytes
    prefix_bytes = mrt_encode_prefix(table.prefix)
    rest += prefix_bytes
    entry_count_bytes = struct.pack(">h", len(table.entries))
    rest += entry_count_bytes
    for table_entry in table.entries:
        peer_index_bytes = struct.pack(">h", table_entry.peer_index)
        rest += peer_index_bytes
        originating_time_bytes = struct.pack(">I", table_entry.originating_time)
        rest += originating_time_bytes

        attribute_bytes = bytes()
        origin_value = 0 if table_entry.origin == "IGP" else 1
        origin_bytes = struct.pack(">bbbb", 0x40, 1, 1, origin_value)
        attribute_bytes += origin_bytes

        aspath_bytes = bytes()
        for asn in table_entry.aspath:
            aspath_bytes += struct.pack(">I", asn)
        aspath_header = struct.pack(
            ">BBBBB", 0x40, 2, len(aspath_bytes) + 2, 2, len(table_entry.aspath)
        )
        attribute_bytes += aspath_header + aspath_bytes

        nexthop_bytes = struct.pack(">bbbI", 0x0, 3, 4, int(table_entry.nexthop))
        attribute_bytes += nexthop_bytes

        if table_entry.med:
            med_bytes = struct.pack(">bbbI", 0x40, 4, 4, table_entry.med)
            attribute_bytes += med_bytes

        if table_entry.prf:
            local_pref_bytes = struct.pack(">BbbI", 0x40, 5, 4, table_entry.prf)
            attribute_bytes += local_pref_bytes

        if table_entry.aggregator:
            aggregator_bytes = struct.pack(
                ">BbbII", 0x40, 7, 4, table_entry.aggregator_as, table_entry.aggregator
            )

        if table_entry.communities:
            community_bytes = bytes()
            for c in table_entry.communities:
                community_bytes += struct.pack(">L", c)
            community_header = struct.pack(">BBB", 0x40, 8, len(community_bytes))
            attribute_bytes += community_header + community_bytes

        attribute_length_bytes = struct.pack(">H", len(attribute_bytes))
        rest += attribute_length_bytes + attribute_bytes

    mrt_entry_length = len(rest)
    mrt_entry_length_bytes = struct.pack(">I", mrt_entry_length)
    result: bytes = common_bytes + mrt_entry_length_bytes + rest

    return result


def mrt_bytes_rib_tables(
    tables: List[MRTRibTable], progress: Optional[bool] = False
) -> bytes:
    result = bytes()

    pbar = tables
    if progress:
        tc = len(tables)
        print(f"Processing {tc} RIB Tables")
        pbar = tqdm(tables)

    for table in pbar:
        result += mrt_bytes_single_rib_table(table)

    if progress:
        pbar.reset()
        print("Done.")
    return result


def mrt_bytes_write_rib_tables(file, tables: List[MRTRibTable]) -> int:
    total: int = 0
    for table in tables:
        rib_table_bytes = mrt_bytes_single_rib_table(table)
        total += len(rib_table_bytes)
        file.write(rib_table_bytes)

    return total


def mrt_bytes(
    timestamp: int,
    peer_index_table: MRTPeerIndexTable,
    rib_tables: List[MRTRibTable],
    progress: Optional[bool] = False,
) -> bytes:
    return mrt_bytes_peer_index_table(
        timestamp, peer_index_table, progress
    ) + mrt_bytes_rib_tables(rib_tables, progress)


def mrt_bytes_write(
    f,
    timestamp: int,
    peer_index_table: MRTPeerIndexTable,
    rib_tables: List[MRTRibTable],
) -> int:
    index_table_bytes = mrt_bytes_peer_index_table(timestamp, peer_index_table)
    count: int = len(index_table_bytes)
    f.write(index_table_bytes)
    mrt_bytes_write_rib_tables(f, rib_tables)


def write_binary_mrt(
    output_path: str,
    timestamp: float,
    peer_index_table: MRTPeerIndexTable,
    rib_tables: List[MRTRibTable],
    progress: Optional[bool] = False,
) -> None:
    with tqdm(unit="b", unit_scale=True, unit_divisor=1025) as t:
        with open(output_path, "wb") as outfile:
            fobj = CallbackIOWrapper(t.update, outfile, "write")
            mrt_bytes_write(fobj, timestamp, peer_index_table, rib_tables)

    t.reset()


def convert_text_to_binary_mrt(
    output_path: str, input_path: str, progress: Optional[bool] = False
) -> None:
    peer_index_table: MRTPeerIndexTable
    rib_tables: List[MRTRibTable]

    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"{input_path} does not exist or cannot be read")
    input_file_stat = os.stat(input_path)
    timestamp = int(input_file_stat.st_mtime)
    (peer_index_table, rib_tables) = construct_rib_tables(input_path, progress)
    write_binary_mrt(output_path, timestamp, peer_index_table, rib_tables, progress)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="verbose and debug output",
    )
    parser.add_argument(
        "input_files", type=str, nargs="+", help="mrt dump in text from (.txt, .gz)"
    )
    return parser.parse_args()


def usage():
    print("Usage:")


def main():
    args = parse_args()
    for input_path in args.input_files:
        output_path = input_path.replace(".gz", "").replace(".txt", "") + ".mrt"
        if args.verbose:
            print(f"{input_path} -> {output_path}")
        convert_text_to_binary_mrt(output_path, input_path, progress=args.verbose)


if __name__ == "__main__":
    main()
