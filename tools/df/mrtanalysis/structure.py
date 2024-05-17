import collections
import struct

from typing import Dict, Any, Tuple, List, Union, Optional, Callable
import ipaddress
from df.mrtanalysis.util import hexline, Block

from df.mrtanalysis.util import Block

MRTHeaderTypes = {
    0: "NULL (DEPRECATED)	[RFC6396]",
    1: "START (DEPRECATED)	[RFC6396]",
    2: "DIE (DEPRECATED)	[RFC6396]",
    3: "I_AM_DEAD (DEPRECATED)	[RFC6396]",
    4: "PEER_DOWN (DEPRECATED)	[RFC6396]",
    5: "BGP (DEPRECATED)	[RFC6396]",
    6: "RIP (DEPRECATED)	[RFC6396]",
    7: "IDRP (DEPRECATED)	[RFC6396]",
    8: "RIPNG (DEPRECATED)	[RFC6396]",
    9: "BGP4PLUS (DEPRECATED)	[RFC6396]",
    10: "BGP4PLUS_01 (DEPRECATED)	[RFC6396]",
    11: "OSPFv2	[RFC6396]",
    12: "TABLE_DUMP	[RFC6396]",
    13: "TABLE_DUMP_V2	[RFC6396]",
    16: "BGP4MP	[RFC6396]",
    17: "BGP4MP_ET	[RFC6396]",
    32: "ISIS	[RFC6396]",
    33: "ISIS_ET	[RFC6396]",
    48: "OSPFv3	[RFC6396]",
    49: "OSPFv3_ET	[RFC6396]",
}
MRTHeaderSubType = {
    0: "Reserved	[RFC6396]",
    1: "PEER_INDEX_TABLE	[RFC6396]",
    2: "RIB_IPV4_UNICAST	[RFC6396]",
    3: "RIB_IPV4_MULTICAST	[RFC6396]",
    4: "RIB_IPV6_UNICAST	[RFC6396]",
    5: "RIB_IPV6_MULTICAST	[RFC6396]",
    6: "RIB_GENERIC	[RFC6396]",
    7: "GEO_PEER_TABLE	[RFC6397]",
    8: "RIB_IPV4_UNICAST_ADDPATH	[RFC8050]",
    9: "RIB_IPV4_MULTICAST_ADDPATH	[RFC8050]",
    10: "RIB_IPV6_UNICAST_ADDPATH	[RFC8050]",
    11: "RIB_IPV6_MULTICAST_ADDPATH	[RFC8050]",
    12: "RIB_GENERIC_ADDPATH	[RFC8050]",
}


def analyze(
    pic: str, fmt: Dict[int, Dict], obj: Any, block: bytes, addr: int
) -> Tuple[int, List[str]]:
    """
    create lines for analysis output

    :param pic: the struct pic of the structure
    :param fmt: the format specifier
    :param obj:
    :param block:
    :param addr:
    :return: List of Lines, number of bytes advanced
    """
    lines = []
    offset = 0
    for i, c in enumerate(pic):
        if c == ">":
            continue
        nbytes = struct.calcsize(c)

        hex_part = hexline(
            block[offset:], addr + offset, size=1, width=nbytes, skipAscii=True
        )

        f: Dict[int, Union[str, Dict]] = fmt.get(i)
        if f:
            attr: str = f.get("attr")
            lookup: Dict = f.get("lookup")
            convertor: Callable[[int], str] = f.get("convert", lambda x: str(x))
            name: str = f.get("name")

            default_format_spec: str = "{value}"
            if name:
                default_format_spec = "{name} - {value}"
            format_spec: str = f.get("fmt", default_format_spec)

            if attr and hasattr(obj, attr):
                value = getattr(obj, attr)
            else:
                if c == "P":  # special pascal type string
                    (length) = struct.unpack(">H", block[offset : offset + 2])
                    value = bytes[offset + 2 : offset + 2 + length].decode()
                else:
                    value = struct.unpack(">" + c, block[offset : offset + nbytes])
            if lookup:
                lookup_value = lookup.get(value)
            if convertor:
                converted_value = convertor(value)
            expl_part = format_spec.format(**locals())
        else:
            expl_part = "<unknown>"

        line: str = f"{hex_part:<40} - {expl_part}"

        lines.append(line)
        offset += nbytes

    return (offset, lines)


class Analyzer(object):
    pic: str = None
    format: Dict[int, Union[str, Dict]] = None
    block: bytes = None

    def __init__(self, obj, fmt: Dict = None):
        self.obj = obj
        self.format = fmt
        if hasattr(obj, "PIC"):
            self.pic = obj.PIC

    def analyze(self, block: bytes, addr: int) -> Tuple[int, List[str]]:
        return analyze(self.pic, self.format, self.obj, block, addr)


class MRTAnalyzer(Analyzer):
    def __init__(self, obj: Any, fmt: Dict):
        Analyzer.__init__(self, obj, fmt)

    def analyze(self, block: bytes, addr: int) -> Tuple[int, List[str]]:
        return super().analyze(block, addr)


class MRTHeaderAnalyzer(MRTAnalyzer):
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           Timestamp                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             Type              |            Subtype            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             Length                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Message... (variable)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    format: Dict[int, Dict] = {
        1: {
            "attr": "ts",
            "name": "TimeStamp",
            "convert": lambda x: arrow.get(x).format("YYYY-MM-DD hh:mm:ss"),
            "fmt": "{name} - {value} ({converted_value})",
        },
        2: {
            "attr": "type",
            "name": "Type",
            "lookup": MRTHeaderTypes,
            "fmt": "{value} ({lookup_value})",
        },
        3: {
            "attr": "subtype",
            "name": "SubType",
            "lookup": MRTHeaderSubType,
            "fmt": "{value} ({lookup_value})",
        },
        4: {"attr": "len", "name": "Length"},
    }

    def __init__(self, obj):
        MRTAnalyzer.__init__(self, obj, self.format)

    def analyze(self, block: bytes, addr: int) -> Tuple[int, List[str]]:
        return super().analyze(block, addr)


class MRTTableAnalyzer(MRTAnalyzer):
    pass


class MRTV2TableAnalyzer(MRTTableAnalyzer):
    pass


class MRTV2RibTableAnalyzer(MRTV2TableAnalyzer):
    pass


class MRTV2PeerIndexTableAnalyzer(MRTV2TableAnalyzer):
    """

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Collector BGP ID                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       View Name Length        |     View Name (variable)      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Peer Count           |    Peer Entries (variable)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    format: Dict[int, Dict] = {
        1: {
            "attr": "collector_id",
            "name": "Collector BGP ID",
            "convert": lambda x: ipaddress.IPV4,
            "fmt": "{name} - {value} ({converted_value})",
        },
        2: {
            "attr": "type",
            "name": "Type",
            "lookup": MRTHeaderTypes,
            "fmt": "{value} ({lookup_value})",
        },
        3: {
            "attr": "subtype",
            "name": "SubType",
            "lookup": MRTHeaderSubType,
            "fmt": "{value} ({lookup_value})",
        },
        4: {"attr": "len", "name": "Length"},
    }

    def __init__(self, obj):
        MRTV2TableAnalyzer.__init__(self, obj)

    def analyze(self, block: bytes, addr: int) -> Tuple[int, List[str]]:
        return super().analyze(block, addr)


class MRTV2RibEntryAnalyzer(MRTV2TableAnalyzer):
    def __init__(self, obj):
        MRTV2TableAnalyzer.__init__(self, obj)

    def analyze(self, block: bytes, addr: int) -> Tuple[int, List[str]]:
        return super().analyze(block, addr)


class MRTV2RibEntryGenericAnalyzer(MRTV2RibEntryAnalyzer):
    format: Dict[int, Dict] = {
        1: {"attr": "ts", "name": "TimeStamp", "fmt": "{value}"},
        2: {
            "attr": "type",
            "name": "Type",
            "lookup": MRTHeaderTypes,
            "fmt": "{value} ({lookup_value})",
        },
        3: {
            "attr": "subtype",
            "name": "SubType",
            "lookup": MRTHeaderSubType,
            "fmt": "{value} ({lookup_value})",
        },
        4: {"attr": "len", "name": "Length"},
    }

    def __init__(self, obj):
        MRTAnalyzer.__init__(self, obj, self.format)

    def analyze(self, block: bytes, addr: int) -> Tuple[int, List[str]]:
        return super().analyze(block, addr)


class MRTHeader(object):
    """a replacement for dpkt.mrt.MRTHeader"""

    HEADER_LENGTH: int = 12
    PIC: str = ">IHHI"
    ANALYZER = MRTHeaderAnalyzer

    def __init__(self, block=None):
        self.ts = 0
        self.type = 0
        self.subtype = 0
        self.len = 0
        if block:
            self.unpack(block)

    def unpack(self, block):
        self.ts, self.type, self.subtype, self.len = struct.unpack(self.PIC, block[:12])


class MRTV2AsPath(object):
    """AS4 as path object"""

    """
    __hdr__ = (
        ('flags', 'b', 0),
        ('type', 'b', 0),
        ('length', 'b', 0),
        ('seq_type', 'b', 0),
        ('no_of_seq', 'b', 0)
    )
    """

    def __init__(self, block=None):
        self.flags = 0
        self.type = 0
        self.length = 0
        self.seq_type = 0
        self.no_of_seq = 0
        if block:
            self.unpack(block)

    def __len__(self):
        if self.length:
            return 5 + self.no_of_seq * 4
        return 3  # null aspath is 3 bytes

    def unpack(self, buf):
        self.flags, self.type, self.length = struct.unpack(">BBB", buf[:3])
        self.aspaths = []
        if self.length == 0:
            return

        self.data = buf[3:]
        self.seq_type, self.no_of_seq = struct.unpack(">BB", self.data[:2])

        left = self.no_of_seq
        while left > 0:
            the_as = int.from_bytes(self.data[:4], byteorder="big")
            self.aspaths.append(the_as)
            self.data = self.data[4:]
            left = left - 1
        self.data = []  # to make len work


class MRTV2PeerIndexTable(object):
    PIC = ">IPH"  # P is special indicates a pascal string for parsing

    collector_id: str = None
    view_name: str = None
    peer_cout: int = None

    def __init__(self, block: bytes):
        if block:
            self.unpack(block)

    def unpack(self, block: bytes):
        (self.collector_id) = struct.unpack_from(">I", block, 0)
        (view_name_length) = struct.unpack_from(">H", block, 4)
        self.view_name = block[7 : 7 + view_name_length].decode()
        (self.peer_count) = struct.unpack_from(">H", block, 7 + view_name_length)


class MRTV2RibTable(object):
    ANALYZER = MRTV2RibTableAnalyzer

    def __init__(self, block: bytes = None):
        if block:
            self.unpack(block)

    def unpack(self, block: bytes):
        pass


class MRTV2RibEntry(object):
    """MRT V2 type RIB Entry"""

    PIC: str = ">HIH"
    # ANALYZER = MRTV2
    """
    __hdr__ = (
        ('peer_index', 'h', 0),
        ('originating_time', 'I', 0),
        ('attribute_length', 'h', 0)
    )
    """

    def __init__(self, block=None):
        self.peer_index = 0
        self.originating_time = 0
        self.attribute_length = 0
        if block:
            self.unpack(block)

    def unpack(self, block):
        self.peer_index, self.originating_time, self.attribute_length = struct.unpack(
            self.PIC, block[:8]
        )
        self.data = block[8:]


rib_ipv4_unicast = collections.namedtuple(
    "RIB_IPV4_Unicast",
    ["sequence_number", "ip_prefix", "entry_count", "re", "attributes"],
)


def build_entries(type: int, subtype: int, count: int) -> List[Any]:
    """
    given a type, subtype and count build the entries for the associated table

    :param type: mrt type
    :param subtype: mrt subtype
    :param count: number of entries
    :return: List of entries
    """
    if type == 13:
        if subtype == 6:
            result = MRTV2RibTable()

        return []

    return []


class Indexer(object):
    """
    This class indexes an mrt dump and tracks the sections of headers and entries
    """

    def __init__(self):
        self.reset()

    def reset(self):
        self.mrt_headers = []
        self.payload_pos = []
        self.raw_headers = []
        self.content = None

    def index(self, content):
        self.content = content
        pos = 0
        hl = MRTHeader.HEADER_LENGTH
        while pos < len(content):
            header = content[pos : pos + hl]
            self.raw_headers.append((header, pos, pos + hl))
            mrt_header = MRTHeader(header)
            self.mrt_headers.append(mrt_header)
            self.payload_pos.append(pos + hl)
            pos = pos + hl + mrt_header.len

    def __len__(self):
        return len(self.mrt_headers)

    def __repr__(self):
        if self.content:
            return "{0} headers in {1} bytes".format(
                len(self.mrt_headers), len(self.content)
            )
        return "Not indexed"

    def header_block(self, index):
        data, start, end = self.raw_headers[index]
        return Block(data, start, end)

    def mrt_header(self, index):
        return self.mrt_headers[index]

    def payload_block(self, index):
        start = self.payload_pos[index]
        end = start + self.mrt_headers[index].len
        return Block(self.content[start:end], start, end)
