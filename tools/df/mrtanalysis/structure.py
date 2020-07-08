import collections
import struct

from df.mrtanalysis.analysis import MRTHeaderAnalyzer
from df.mrtanalysis.util import Block


class MRTHeader(object):
    """ a replacement for dpkt.mrt.MRTHeader"""

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
    """AS4 as path object """

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


class MRTV2RibEntry(object):
    """MRT V2 type RIB Entry"""

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
            ">HIH", block[:8]
        )
        self.data = block[8:]


rib_ipv4_unicast = collections.namedtuple(
    "RIB_IPV4_Unicast",
    ["sequence_number", "ip_prefix", "entry_count", "re", "attributes"],
)


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