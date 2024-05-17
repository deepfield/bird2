import struct
from typing import Dict, Any, Tuple, List, Union, Optional, Callable
import ipaddress

import arrow

from df.mrtanalysis.util import hexline, Block
from df.mrtanalysis.progress import TimedProgressReporter
from df.mrtanalysis.bgp import RouteIPV4, BGPAttribute
from df.mrtanalysis.structure import (
    Indexer,
    MRTV2RibEntry,
    MRTV2AsPath,
    rib_ipv4_unicast,
    MRTHeader,
)

from df.mrtanalysis.structure import (
    Analyzer,
    MRTHeaderAnalyzer,
    MRTV2RibTableAnalyzer,
    MRTV2RibEntryAnalyzer,
    MRTV2RibEntryGenericAnalyzer,
    MRTV2PeerIndexTableAnalyzer,
)


def get_analyzer_class(mrt_header: MRTHeader) -> Analyzer:
    type: int = mrt_header.type
    subtype: int = mrt_header.subtype

    type_dict: Optional[Dict[int, Analyzer]] = {
        13: {
            1: MRTV2PeerIndexTableAnalyzer,
        }
    }.get(type)
    if type is None:
        raise RuntimeError(f"No analyzer for mrt table type {type}")

    subtype_analyzer = type_dict.get(subtype)
    if subtype_analyzer is None:
        raise RuntimeError(f"No analyzer of subtype {subtype} of table type {type}")

    return subtype_analyzer


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


def analyze_payload(mrt_header: MRTHeader, payload: bytes, addr: int) -> Analyzer:
    the_class = get_analyzer_class(mrt_header)

    return the_class(
        obj,
        the_class.format,
    ).analyze(payload, addr)


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
        re = MRTV2RibEntry(rib_entry_block.content)
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
                attr = MRTV2AsPath(attributes_block.content)
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
        (
            attributes_block,
            ip_prefix,
            re,
            rib_entry_block,
            rib_entry_count,
            sequence_number,
        ) = self._parse_rib_table_start(block)
        attrs = self.parse_bgp_attributes(attributes_block, re, rib_entry_block)
        result = rib_ipv4_unicast(
            sequence_number, ip_prefix, rib_entry_count, re, attrs
        )
        return result

    def block_analysis(self, filename, args):
        progress_reporter = TimedProgressReporter(every=10000)

        self.indexer = self._start_analysis(
            filename, "Block Analysis", verbose=args.verbose
        )
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
            (
                attributes_block,
                ip_prefix,
                re,
                rib_entry_block,
                rib_entry_count,
                sequence_number,
            ) = self._parse_rib_table_start(payload_block)
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
        for i in range(0, len(self.indexer)):
            mrt_header = self.indexer.mrt_headers[i]
            raw_header = self.indexer.raw_headers[i]
            payload_block = self.indexer.payload_block(i)
            # -- mrt header
            print("-" * 80)
            print(
                "Header #{0} - Type - {1} - SubType {2} - {3:04x} bytes".format(
                    i, mrt_header.type, mrt_header.subtype, mrt_header.len
                )
            )
            raw_header_block = Block(raw_header[0], raw_header[1], raw_header[2])
            print(raw_header_block.hexdump())
            print("Payload - {0} bytes".format(len(payload_block)))
            print(payload_block.hexdump())

    def blockdump(self):
        addr: int = 0
        lines: List[str] = []
        for i in range(0, len(self.indexer)):
            print("-" * 80)
            print("Header")
            mrt_header = self.indexer.mrt_headers[i]
            (raw_header, start, end) = self.indexer.raw_headers[i]
            analyzer: Analyzer = mrt_header.ANALYZER(mrt_header)
            (offset, output) = analyzer.analyze(raw_header, start)
            print("\n".join(output))
            addr += offset
            payload_block = self.indexer.payload_block(i)
            (offset, output) = analyze_payload(mrt_header, payload_block, addr)
            addr += offset

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
                    get_stats_value(
                        stat_bgp_attr, "Missing mandatory Attributes", "Count"
                    )
                )
            )
            print(
                "incorrect attribute sequences..........: {0}".format(
                    get_stats_value(
                        stat_bgp_attr, "Incorrect Attribute Sequence", "Count"
                    )
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
                print(
                    "# of Attributes with extended length .: {0}".format(
                        get_stats_value(stat_bgp_attr, "Extended Length", "Count")
                    )
                )
                print(
                    "Seen attr types (w/count) ............: <{0}>".format(
                        ",".join(
                            [
                                "{0}:{1}".format(k, v)
                                for k, v in stat_bgp_attr.get("Types", {}).items()
                            ]
                        )
                    )
                )
                print(
                    "Seen lengths (w/count) ...............: <{0}>".format(
                        ",".join(
                            [
                                "{0}:{1}".format(k, v)
                                for k, v in stat_bgp_attr.get("Lengths", {}).items()
                            ]
                        )
                    )
                )
                print(
                    "Seen flags (w/count) .................: <{0}>".format(
                        ",".join(
                            [
                                "{0}:{1}".format(k, v)
                                for k, v in stat_bgp_attr.get("Flags", {}).items()
                            ]
                        )
                    )
                )
                print(
                    "Seen as sequence lengths (w/count) ...: <{0}>".format(
                        ",".join(
                            [
                                "{0}:{1}".format(k, v)
                                for k, v in stat_bgp_attr.get(
                                    "AS_Sequence Length", {}
                                ).items()
                            ]
                        )
                    )
                )

    # old code - deprecated
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
                elif isinstance(attr, MRTV2AsPath):
                    if 2 in attribute_types:
                        self.print_loc(
                            "BGP Attribute of type 0x02 has already been seen"
                        )

                attribute_types.setdefault(attr.type, 1)
