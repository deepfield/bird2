from __future__ import print_function
import sys
import argparse
import time
import struct
import collections
import ipaddress

"""
These are utility functions for outputting hexdumps
"""


def hexline(block, addr=0, size=1, width=16, byteorder="little", sep=" "):
    addr_part = "%08x" % addr
    chunk_format = "%0" + str(size * 2) + "x"
    result = addr_part
    result_symbols = []
    pos = 0
    while pos < width:
        chunk = int.from_bytes(block[pos : pos + size], byteorder)
        result = result + sep
        if pos % 8 == 0:
            result = result + sep
        if pos < len(block):
            result = result + chunk_format % chunk
            symbol = "."
            if size == 1 and 0x20 <= chunk <= 0x7E:
                symbol = chr(chunk)
            result_symbols.append(symbol * size)
        else:
            result = result + " " * (size * 2)
            result_symbols.append(" ")
        pos = pos + size

    result = result + sep * 2 + "".join(result_symbols)
    return result


def hexdump(block, start_addr=0, size=1, width=16, byteorder="little", sep=" "):
    """
    return an array of strings in hexdump format
    00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 0U0 00 ..................
    """
    offset = 0
    end = len(block)
    result = []
    addr = start_addr
    while offset < end:
        line = hexline(block[offset:], addr, size, width, byteorder, sep)
        result.append(line)
        addr = addr + width
        offset = offset + width

    return result


class HexDump(object):
    def __init__(self, addr=0, size=1, width=16, byteorder="little", sep=" "):
        self.addr = addr
        self.size = size
        self.width = width
        self.byteorder = byteorder
        self.sep = sep

    def line(self, block):
        return hexline(
            block, self.addr, self.size, self.width, self.byteorder, self.sep
        )

    def dump(self, block):
        return hexdump(
            block, self.addr, self.size, self.width, self.byteorder, self.sep
        )


class Block(object):
    """ a block of bytes with starting and ending position """

    def __init__(self, content, start, end):
        self._content = content
        self._start = start
        self._end = end

    def __len__(self):
        if self.content:
            return len(self.content)
        return 0

    def __repr__(self):
        return "[{0:x},{1:x}] {2} bytes".format(self.start, self.end, len(self.content))

    @property
    def content(self):
        return self._content

    @property
    def start(self):
        return self._start

    @property
    def end(self):
        return self._end

    def consume(self, length=0):
        if length:
            self._content = self._content[length:]
            self._start = self._start + length

    def hexdump(self):
        dumper = HexDump(addr=self.start)
        return "\n".join(dumper.dump(self.content))


"""
Objects related to MRT dump
"""


class ProgressReporter:
    def __init__(self, total=1000, every=1000, fmt=None):
        self._total = total
        self._every = every
        if not fmt:
            self._fmt = "Processed {0} of {1} blocks {2:4.1f}% done"

    @property
    def total(self):
        return self._total

    @total.setter
    def total(self, total):
        self._total = total

    @property
    def percent(self):
        return self._percent

    @property
    def every(self):
        return self._every

    @every.setter
    def every(self, value):
        self._every

    def should_report(self, block):
        return block % self.every == 0

    def _update_progress(self, block, total=None):
        if not total:
            total = self._total
        self._percent = float(block) * 100.0 / float(total)

    def update(self, block, total=None):
        if self.should_report(block):
            self._update_progress(block, total)
            print(self._fmt.format(block, total, self._percent))


class TimedProgressReporter(ProgressReporter):
    def __init__(self, total=1000, every=1000, fmt=None):
        super(TimedProgressReporter, self).__init__(total, every, fmt)
        self._start_time = None
        self._fmt = fmt
        if not fmt:
            self._fmt = "{0:10.3f}s {1:4.5f}% done - {2:8} blocks left - {3:4.5f} blocks/s - {4:4.5f}s left"

    def start(self):
        self._start_time = time.monotonic()

    def update(self, block, total=None):
        if not self._start_time:
            self.start()

        if not total:
            total = self._total
        if self.should_report(block):
            super(TimedProgressReporter, self)._update_progress(block, total)
            self._now = time.monotonic()
            self._passed = self._now - self._start_time
            self._left = total - block
            self._performance = float(block) / self._passed
            self._forecast_left = self._left / self._performance
            self._last_message = self._fmt.format(
                self._passed,
                self._percent,
                self._left,
                self._performance,
                self._forecast_left,
            )
            print(self._last_message)


class MRTHeader(object):
    """ a replacement for dpkt.mrt.MRTHeader"""

    HEADER_LENGTH = 12

    def __init__(self, block=None):
        self.ts = 0
        self.type = 0
        self.subtype = 0
        self.len = 0
        if block:
            self.unpack(block)

    def unpack(self, block):
        self.ts, self.type, self.subtype, self.len = struct.unpack(">IHHI", block[:12])


class MRT_V2_AsPath(object):
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


class MRT_V2_RibEntry(object):
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


class BGPAttribute(object):
    """replacement for dpkt.bgp.BGP.Attribute"""

    def __init__(self, block=None):
        self.flag = 0
        self.type = 0
        self.length = 0
        self.payload = None
        if block:
            self.unpack(block)

    def __len__(self):
        if self.is_extended_length:
            return self.length + 4
        return self.length + 3

    @property
    def is_extended_length(self):
        return self.flag & 0x10

    @property
    def is_known_type(self):
        return (
            self.type in range(1, 10)
            or self.type in range(12, 29)
            or self.type in range(32, 36)
            or self.type == 40
            or self.type == 128
        )

    def unpack(self, block):
        self.flag, self.type = struct.unpack(">BB", block[:2])
        self.data = block[2:]
        if self.is_extended_length:
            self.length = struct.unpack(">H", self.data[:2])[0]
            self.data = self.data[2:]
        else:
            self.length = struct.unpack(">B", self.data[:1])[0]
            self.data = self.data[1:]

        self.payload = Block(self.data, 0, len(self.data))


class RouteIPV4(object):
    def __init__(self, block=None):
        self.prefix_length = 0
        self.ipv4 = None
        if block:
            self.unpack(block)

    def __len__(self):
        if self.ipv4:
            return (self.prefix_length + 7) // 8 + 1  # one for the length byte
        return 0

    def unpack(self, block):
        self.prefix_length = struct.unpack(">B", block[:1])[0]
        no_of_bytes = (self.prefix_length + 7) // 8
        byte_buf = block[1 : 1 + no_of_bytes] + bytes(4 - no_of_bytes)
        v4 = struct.unpack(">I", byte_buf[:5])[0]
        ipv4 = ipaddress.IPv4Address(v4)
        self.ipv4 = ipaddress.IPv4Network(str(ipv4) + "/{0}".format(self.prefix_length))


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


"""
Analysis Section
"""


def stats_inc_count(stat_obj, category, key):
    entry = stat_obj.setdefault(category, {})
    result = entry.setdefault(key, 0)
    result = result + 1
    entry[key] = result
    return result


def get_stats_value(stat_item, category, key):
    cat = stat_item.get(category)
    if not cat:
        return 0
    entry = cat.get(key)
    if not entry:
        return 0
    return entry


class Analysis(object):
    def __init__(self):
        self.statistics = {}
        self.location = None  # where the analysis is currently
        self._show_progress = False
        self._show_errors = False

    @property
    def show_progress(self):
        return self._show_progress

    @show_progress.setter
    def show_progress(self, value):
        self._show_progress = value

    @property
    def show_errors(self):
        return self._show_errors

    @show_errors.setter
    def show_errors(self, value):
        self._show_errors = value

    @property
    def loc_str(self):
        if self.location:
            file = self.location.get("File", "")
            op = self.location.get("current op", "<None>")
            block = self.location.get("block", "<None>")
            attr = self.location.get("attr", None)
            fmt_str = "{file},{op},{block},"
            if attr:
                fmt_str = fmt_str + "{attr}"
            fmt_str = fmt_str + ":"
            return fmt_str.format(**locals())
        return "Analysis not started"

    def print_loc(self, *args, **kwargs):
        if self._show_errors:
            print(self.loc_str, *args, **kwargs)

    def _start_analysis(self, filename, op="Analyzing", verbose=False):
        self.location = {}
        self.location.setdefault("File", filename)
        if verbose:
            print("{1} {0}".format(filename, op))
        self.location.setdefault("current op", "Reading")
        if verbose:
            print("Reading....")
        indexer = Indexer()
        with open(filename, "rb") as f:
            content = f.read()
        self.location["current op"] = "Indexing"
        if verbose:
            print("Indexing.....")
        indexer.index(content)
        if verbose:
            print(repr(indexer))
        return indexer

    def _parse_rib_table_start(self, block):
        sequence_number = struct.unpack(">I", block.content[0:4])[0]
        ip_prefix = RouteIPV4(block.content[4:])
        start = len(ip_prefix) + 4
        rib_entry_count = struct.unpack(">H", block.content[start : start + 2])
        start = start + 2
        rib_entry_block = Block(
            block.content[start:], start, len(block.content) + start
        )
        re = MRT_V2_RibEntry(rib_entry_block.content)
        attributes_block = Block(
            rib_entry_block.content[8:], start + 8, len(block.content) + start
        )
        return (
            attributes_block,
            ip_prefix,
            re,
            rib_entry_block,
            rib_entry_count,
            sequence_number,
        )

    def parse_bgp_attributes(self, attributes_block, re, rib_entry_block):
        """
        parse bgp_attributes list
        - rib_entry_block is in the argument list for future analysis
        """
        attributes = []
        Done = False
        count = 0
        while not Done:
            self.location.setdefault("attr", 0)
            self.location["attr"] = count
            peek_attribute_type = struct.unpack(">B", attributes_block.content[1:2])[0]
            peek_attribute_len = struct.unpack(">B", attributes_block.content[2:3])[0]
            if peek_attribute_type == 2:  # ASPaths requires special handling
                attr = MRT_V2_AsPath(attributes_block.content)
                attributes.append(attr)
                # peek ahead and see if the next record based on attr length is correct
                advance = len(attr)
                next_type = struct.unpack(
                    ">B", attributes_block.content[advance + 1 : advance + 2]
                )[0]
                if next_type == 3:
                    attributes_block.consume(len(attr))
                else:
                    advance = (
                        peek_attribute_len + 3
                    )  # interpret the rib entry length as a 1 byte entry
                    next_type = struct.unpack(
                        ">B", attributes_block.content[advance + 1 : advance + 2]
                    )[0]
                    if next_type == 3:
                        attributes_block.consume(advance)
                    else:
                        self.print_loc(
                            "BGP Attribute #{0} was the well formed attribute, we are no in the weeds".format(
                                count
                            )
                        )
                        break
            else:
                attr = BGPAttribute(attributes_block.content)
                attributes.append(attr)
                if not attr.is_known_type:
                    self.print_loc(
                        "BGP Attribute #{0} with type {1} is not of known type -> most likely corrupted".format(
                            count, peek_attribute_type
                        )
                    )
                    break
                else:
                    if len(attr) > re.attribute_length:
                        self.print_loc(
                            "BGP Attribute type 0x{0:02x} has invalid length of {0} (> {1} rib_entry_block.length)".format(
                                len(attr), re.attribute_length
                            )
                        )
                        self.print_loc("Abort scan of attribute table")
                        break
                attributes_block.consume(len(attr))

            count = count + 1
            Done = not len(attributes_block) > 0

        del self.location["attr"]
        return attributes

    def parse_rib_ipv4_unicast(self, block):
        attributes_block, ip_prefix, re, rib_entry_block, rib_entry_count, sequence_number = self._parse_rib_table_start(
            block
        )
        attrs = self.parse_bgp_attributes(attributes_block, re, rib_entry_block)
        result = rib_ipv4_unicast(
            sequence_number, ip_prefix, rib_entry_count, re, attrs
        )
        return result

    def block_analysis(self, filename, args):
        progress_reporter = TimedProgressReporter(every=10000)

        self.indexer = self._start_analysis(filename, "Block Analysis", verbose=args.verbose)
        self.location["current op"] = "Block Analysis"
        stat_blocks = self.statistics.setdefault("Blocks", {})
        stat_mrt_header = self.statistics.setdefault("MRT_Header", {})
        stat_bgp = self.statistics.setdefault("BGP", {})
        stat_bgp_attr = stat_bgp.setdefault("Attributes", {})
        stat_bgp_pkt = stat_bgp.setdefault("Packet", {})

        progress_reporter.total = len(self.indexer)
        previous_sequence = 0
        for i in range(0, len(self.indexer)):
            self.location.setdefault("block", 0)
            self.location["block"] = i
            mrt_header = self.indexer.mrt_header(i)
            raw_header_block = Block(*self.indexer.raw_headers[i])
            payload_block = self.indexer.payload_block(i)
            stats_inc_count(stat_mrt_header, "Lengths", mrt_header.len)
            stats_inc_count(stat_mrt_header, "Type", mrt_header.type)
            stats_inc_count(stat_mrt_header, "SubType", mrt_header.subtype)

            if mrt_header.type != 13:
                self.print_loc(
                    "MRT Header [{0}] is not of MRT_TABLE_DUMP_V2<0x0d> but of 0x{1:04x}".format(
                        i, mrt_header.type
                    )
                )
            if i == 0:
                # skip the peer table entry right now
                if mrt_header.subtype != 1:
                    self.print_loc(
                        "MRT Header [0] is not of PeerIndexTable subtype<0x0001> but of 0x{0:4x}".format(
                            mrt_header.subtype
                        )
                    )
                continue

            if mrt_header.subtype != 2:
                self.print_loc(
                    "MRT Header [{0}] is not of RIB_TABLE subtype <0x0002> but of 0x{1:4x}".format(
                        i, mrt_header.subtype
                    )
                )
                continue

            # payload analysis
            attributes_block, ip_prefix, re, rib_entry_block, rib_entry_count, sequence_number = self._parse_rib_table_start(
                payload_block
            )
            if not sequence_number == 0 and sequence_number != (previous_sequence + 1):
                self.print_loc(
                    "RIB Table sequence number {0} out of sequence (last seen = {1})".format(
                        sequence_number, previous_sequence
                    )
                )
            previous_sequence = sequence_number

            attribute_types = {}
            attribute_sequence = []
            # analyse the payload block for structural deficencies
            pos = 0  # position into attributes_block - only advance at end
            while pos < len(attributes_block):
                offset = 0  # offset into current attribute
                attr_flag = struct.unpack(
                    ">B", attributes_block.content[pos + offset : pos + offset + 1]
                )[0]
                attr_type = struct.unpack(
                    ">B", attributes_block.content[pos + offset + 1 : pos + offset + 2]
                )[0]
                if attr_flag & 0x10:
                    attr_len = struct.unpack(
                        ">H",
                        attributes_block.content[pos + offset + 2 : pos + offset + 4],
                    )[0]
                    stats_inc_count(stat_bgp_attr, "Extended Length", "Count")
                    offset = 4
                else:
                    attr_len = struct.unpack(
                        ">B",
                        attributes_block.content[pos + offset + 2 : pos + offset + 3],
                    )[0]
                    offset = 3

                stats_inc_count(stat_bgp_attr, "Flags", attr_flag)
                stats_inc_count(stat_bgp_attr, "Types", attr_type)
                stats_inc_count(stat_bgp_attr, "Lengths", attr_len)

                # for hexdump purposes
                examined_attribute_block = Block(
                    attributes_block.content[pos : pos + attr_len], pos, pos + attr_len
                )
                _ = examined_attribute_block

                if attr_type in attribute_types:
                    self.print_loc(
                        "BGP Attribute of type 0x{0:02x} has already been seen".format(
                            attr_type
                        )
                    )
                    stats_inc_count(stat_bgp_attr, "Duplicate Type", attr_type)
                    stats_inc_count(stat_bgp_attr, "Duplicate Type", "Count")

                if attr_len > len(attributes_block):
                    self.print_loc(
                        "BGP Attribute has invalid length of {0} (>attribute block length = {1}".format(
                            attr_len, len(attributes_block)
                        )
                    )
                    stats_inc_count(stat_bgp_attr, "Length Violations", attr_type)

                if attr_type == 1:
                    origin = struct.unpack(
                        ">B",
                        attributes_block.content[pos + offset + 1 : pos + offset + 2],
                    )[0]
                    stats_inc_count(stat_bgp_attr, "Origins", origin)
                elif (
                    attr_type == 2
                ):  # check if length of as paths is consistent with attribute length
                    seq_type = struct.unpack(
                        ">B", attributes_block.content[pos + offset : pos + offset + 1]
                    )[0]
                    seq_count = struct.unpack(
                        ">B",
                        attributes_block.content[pos + offset + 1 : pos + offset + 2],
                    )[0]
                    if seq_type == 2 or seq_type == 1:
                        stats_inc_count(stat_bgp_attr, "Sequence Type", seq_type)
                        if seq_type == 2:
                            stats_inc_count(
                                stat_bgp_attr, "AS_Sequence Length", seq_count
                            )
                        else:
                            stats_inc_count(stat_bgp_attr, "AS_Set Length", seq_count)
                    else:
                        stats_inc_count(stat_bgp_attr, "Invalid Seq Type", seq_type)
                elif attr_type == 8:  # community
                    if self.location.get("block", 0) == 128029:
                        _ = 1

                attribute_types.setdefault(attr_type, 1)
                attribute_sequence.append(attr_type)
                pos = (
                    pos + attr_len + 3
                )  # one for flag, one for type and one for length

            # post rib entry analysis
            if 1 not in attribute_sequence:
                stats_inc_count(stat_bgp_attr, "Missing Mandatory Attr Types", 1)
                stats_inc_count(stat_bgp_attr, "Missing Mandatory Attributes", "Count")
            if 2 not in attribute_sequence:
                stats_inc_count(stat_bgp_attr, "Missing Mandatory Attr Types", 2)
                stats_inc_count(stat_bgp_attr, "Missing Mandatory Attributes", "Count")
            if 3 not in attribute_sequence:
                stats_inc_count(stat_bgp_attr, "Missing Mandatory Attr Types", 3)
                stats_inc_count(stat_bgp_attr, "Missing mandatory Attributes", "Count")

            if attribute_sequence[0:3] != [1, 2, 3]:
                stats_inc_count(
                    stat_bgp_attr, "Incorrect Attribute Sequence", "[1,2,3]"
                )
                stats_inc_count(stat_bgp_attr, "Incorrect Attribute Sequence", "Count")

            stats_inc_count(stat_blocks, "Processed", "Count")
            if self._show_progress:
                progress_reporter.update(i)
        # conclusion
        print(
            "{0} block read, {1} blocks processed".format(
                len(self.indexer),
                stat_blocks.get("Processed", {"Count": 0}).get("Count") + 1,
            )
        )

    def hexdump(self, args):
        """
        dump the headers and payload blocks
        :param args:
        :return:
        """
        print("Hexdump")
        for i in range( 0, len(self.indexer)):
            mrt_header = self.indexer.mrt_headers[i]
            raw_header = self.indexer.raw_headers[i]
            payload_block =self.indexer.payload_block(i)
            # -- mrt header
            print( "-" * 80)
            print( "Header #{0} - Type - {1} - SubType {2} - {3:04x} bytes".format(i, mrt_header.type, mrt_header.subtype, mrt_header.len))
            raw_header_block = Block(raw_header[0], raw_header[1], raw_header[2])
            print(raw_header_block.hexdump())
            print( "Payload - {0} bytes".format( len(payload_block)))
            print(payload_block.hexdump())

    def report(self, args):
        print("Statistical analyis")
        # bgp attributes
        if args.bgp:
            print("BGP Attributes")
            stat_bgp = self.statistics.get("BGP")
            if not stat_bgp:
                return
            stat_bgp_attr = stat_bgp.get("Attributes")
            if not stat_bgp_attr:
                return

            print(
                "missing mandatory attributes...........: {0}".format(
                    get_stats_value(stat_bgp_attr, "Missing mandatory Attributes", "Count")
                )
            )
            print(
                "incorrect attribute sequences..........: {0}".format(
                    get_stats_value(stat_bgp_attr, "Incorrect Attribute Sequence", "Count")
                )
            )
            print(
                "duplicate types seen...................: {0}".format(
                    get_stats_value(stat_bgp_attr, "Duplicate Type", "Count")
                )
            )
            if args.seen:
                #     'Attributes': {'Flags': {64: 1, 80: 1, 232: 1, 0: 2, 5: 1}, 'Types': {1: 1, 2: 1, 0: 2, 7: 1, 4: 1},
                #                    'Lengths': {1: 1, 4008: 1, 3: 1, 0: 2, 100: 1}, 'Origins': {80: 1},
                #                    'Extended Length': {'Count': 1}, 'Sequence Type': {2: 1}, 'AS_Sequence Length': {255: 1},
                #                    'Duplicate Type': {0: 1}, 'Missing Mandatory Attr Types': {3: 1},
                #                    'Missing mandatory Attributes': {'Count': 1},
                #                    'Incorrect Attribute Sequence': {'[1,2,3]': 1}}, }
                print( "# of Attributes with extended length .: {0}".format(get_stats_value( stat_bgp_attr, "Extended Length", "Count")))
                print( "Seen attr types (w/count) ............: <{0}>".format( ",".join([ "{0}:{1}".format(k, v) for k, v in stat_bgp_attr.get( "Types", {}).items() ])))
                print( "Seen lengths (w/count) ...............: <{0}>".format( ",".join([ "{0}:{1}".format(k, v) for k, v in stat_bgp_attr.get( "Lengths", {}).items() ])))
                print( "Seen flags (w/count) .................: <{0}>".format( ",".join([ "{0}:{1}".format(k, v) for k, v in stat_bgp_attr.get( "Flags", {}).items() ])))
                print( "Seen as sequence lengths (w/count) ...: <{0}>".format( ",".join([ "{0}:{1}".format(k, v) for k, v in stat_bgp_attr.get( "AS_Sequence Length", {}).items() ])))

    def pass1(self, filename):
        indexer = self._start_analysis(filename)

        self.location["current op"] = "Analysis"
        stat_mrt_header = self.statistics.setdefault("MRT_Header", {})
        stat_bgp = self.statistics.setdefault("BGP", {})
        stat_bgp_attr = stat_bgp.setdefault("Attributes", {})
        stat_bgp_pkt = stat_bgp.setdefault("Packet", {})

        previous_sequence = 0
        for i in range(0, len(indexer)):
            self.location.setdefault("block", 0)
            self.location["block"] = i
            mrt_header = indexer.mrt_header(i)
            raw_header_block = Block(*indexer.raw_headers[i])
            payload_block = indexer.payload_block(i)
            stats_inc_count(stat_mrt_header, "Lengths", mrt_header.len)
            stats_inc_count(stat_mrt_header, "Type", mrt_header.type)
            stats_inc_count(stat_mrt_header, "SubType", mrt_header.subtype)

            if mrt_header.type != 13:
                self.print_loc(
                    "MRT Header [{0}] is not of MRT_TABLE_DUMP_V2<0x0d> but of 0x{1:04x}".format(
                        i, mrt_header.type
                    )
                )
            if i == 0:
                # skip the peer table entry right now
                if mrt_header.subtype != 1:
                    self.print_loc(
                        "MRT Header [0] is not of PeerIndexTable subtype<0x0001> but of 0x{0:4x}".format(
                            mrt_header.subtype
                        )
                    )
                continue

            if mrt_header.subtype != 2:
                self.print_loc(
                    "MRT Header [{0}] is not of RIB_TABLE subtype <0x0002> but of 0x{1:4x}".format(
                        i, mrt_header.subtype
                    )
                )
                continue

            # payload analysis
            rib_table = self.parse_rib_ipv4_unicast(payload_block)
            if not rib_table.sequence_number == 0 and rib_table.sequence_number != (
                previous_sequence + 1
            ):
                self.print_loc(
                    "RIB Table sequence number {0} out of sequence (last seen = {1})".format(
                        rib_table.sequence, previous_sequence
                    )
                )
            previous_sequence = rib_table.sequence_number

            attribute_types = {}
            stat_bgp_pkt = stats_inc_count(
                stat_bgp_attr, "count", len(rib_table.attributes)
            )

            for attr in rib_table.attributes:
                stats_inc_count(stat_bgp_attr, "Types", attr.type)
                stats_inc_count(stat_bgp_attr, "Lengths", attr.length)
                if isinstance(attr, BGPAttribute):
                    if attr.type in attribute_types:
                        self.print_loc(
                            "BGP Attribute of type 0x{0:02x} has already been seen".format(
                                attr.type
                            )
                        )

                    if attr.length > len(payload_block):
                        self.print_loc(
                            "BGP Attribute has invalid length of {0} (> payload length = {1}",
                            attr.length,
                            len(payload_block),
                        )
                elif isinstance(attr, MRT_V2_AsPath):
                    if 2 in attribute_types:
                        self.print_loc(
                            "BGP Attribute of type 0x02 has already been seen"
                        )

                attribute_types.setdefault(attr.type, 1)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="verbose output")
    parser.add_argument("--version", action="version", version="%{prog} 0.0.1")
    parser.add_argument("--progress", action="store_true", default=False, help="show progress")
    parser.add_argument("--errors", action="store_true", default=False, help="show detailed error messages")
    parser.add_argument("--bgp", action="store_true", default=True, help="show stats on bgp attributes")
    parser.add_argument("--seen", action="store_true", default=False, help="show stats on seen attributes")
    parser.add_argument("--hexdump", action="store_true", default=False, help="hexdump the header and rib entry blocks")
    parser.add_argument("files", type=str, nargs="+", default=[], help="mrt files to parse")
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    for f in args.files:
        the_analysis = Analysis()
        the_analysis.show_progress = args.progress
        the_analysis.block_analysis(f, args)
        the_analysis.report(args)
        if args.hexdump:
            the_analysis.hexdump(args)



if __name__ == "__main__":
    main()