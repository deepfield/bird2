"""
analysis of a mrt dump file
work in progress, not all sections are implemented so far
but this should provide a good framework
- almost all objects have nbytes to indicate how big they are in binary/dump form
- almost all objects have explain which will provide the right section of a detail explanation
"""
import struct
import ipaddress

from typing import List, Union, Tuple, Any


def read_mrt(filename: str = "master6.mrt") -> bytes:
    with open(filename, "rb") as infile:
        mrt6_bytes = infile.read()
        infile.close()
    return mrt6_bytes


def explain(address: int, raw: bytes, right_lines: List[str]) -> List[str]:
    return []


IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class MRTObject(object):
    """
    Common base class :
    - all object have a nbytes property which is their size in octets on disk/memory
    - all objects have a explain method which returns a s
    """

    _size: int

    def __init__(self, size: int):
        self._size = size

    def explain(self) -> List[str]:
        pass

    @property
    def nbytes(self) -> int:
        return self._size


class MRTPrefix(MRTObject):
    _ip_version: int
    _prefix_size: int
    _prefix: IPNetwork

    def __init__(self, ip_version: int, prefix_size: int, prefix: IPNetwork):
        super(MRTPrefix, self).__init__(prefix_size + 1)
        self._ip_version = ip_version
        self._prefix_size = prefix_size
        self._prefix = prefix

    @classmethod
    def unpack_from(
        cls, ip_version: int, buffer: bytes, offset: int = 0
    ) -> "MRTPrefix":

        prefix_length = struct.unpack_from("!b", buffer, offset)[0]
        prefix_size = prefix_length // 8
        fmt = f"!{prefix_size}s"
        prefix_bytes = struct.unpack_from(fmt, buffer, offset + 1)[0]
        if ip_version == 4:
            padded = prefix_bytes + b"\x00" * (4 - prefix_size)
            prefix = ipaddress.IPv4Network((padded, prefix_length))
        if ip_version == 6:
            padded = prefix_bytes + b"\x00" * (16 - prefix_size)
            prefix = ipaddress.IPv6Network((padded, prefix_length))
        return MRTPrefix(ip_version, prefix_size, prefix)

    @property
    def size(self) -> int:
        return self._prefix_size

    # @property
    # def prefix(self)->Union[ipaddress.IPv4Network,ipaddress.IPv6Network]:
    #     return self._prefix
    @property
    def prefix(self) -> IPAddress:
        return self._prefix


class MRTType(MRTObject):
    _code_to_str = {
        11: "OSPFv2",
        12: "Table Dump",
        13: "Table Dump V2",
        16: "BGP4MP",
        17: "BGP4MP_ET",
    }
    _code: int

    def __init__(self, type_code: int):
        super(MRTType, self).__init__(2)
        self._code = type_code

    @property
    def code(self) -> int:
        return self._code

    def __str__(self):
        return self._code_to_str.get(self._code, f"MRTType: unkown 0x{self._code:04x}")


class MRTSubType(MRTObject):
    _code_to_str = {
        0: "Reserved",
        1: "PEER_INDEX_TABLE",
        2: "RIB_IPV4_UNICAST",
        3: "RIB_IPV4_MULTICAST",
        4: "RIB_IPV6_UNICAST",
        5: "RIB_IPV6_MULTICAST",
        6: "RIB_GENERIC",
        7: "GEO_PEER_TABLE",
        8: "RIB_IPV4_UNICAST_ADDPATH",
        9: "RIB_IPV4_MULTICAST_ADDPATH",
        10: "RIB_IPV6_UNICAST_ADDPATH",
        11: "RIB_IPV6_MULTICAST_ADDPATH",
        12: "RIB_GENERIC_ADDPATH",
    }
    _subtype: int

    def __init__(self, subtype: int):
        super(MRTSubType, self).__init__(1)
        self._subtype = subtype

    def __str__(self):
        return self._code_to_str.get(
            self._subtype, f"MRTSubType: unknown 0x{self._subtype:04x}"
        )

    @property
    def code(self):
        return self._subtype


class MRTHeader(MRTObject):
    _timestamp: int
    _type: MRTType
    _subtype: int
    _length: int

    def __init__(
        self,
        timestamp: int,
        peer_type: MRTType,
        subtype: MRTSubType,
        length: int,
        size: int,
    ):
        super(MRTHeader, self).__init__(size)
        self._timestamp = timestamp
        self._type = peer_type
        self._subtype = subtype
        self._length = length

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0):
        timestamp = struct.unpack_from("!l", buffer, offset)[0]
        mrt_type = struct.unpack_from("!h", buffer, offset + 4)[0]
        mrt_subtype = struct.unpack_from("!h", buffer, offset + 6)[0]
        mrt_length = struct.unpack_from("!l", buffer, offset + 8)[0]
        return MRTHeader(
            timestamp, MRTType(mrt_type), MRTSubType(mrt_subtype), mrt_length, 12
        )

    @property
    def type(self) -> MRTType:
        return self._type

    @property
    def subtype(self) -> MRTSubType:
        return self._subtype

    def __len__(self):
        return self._length


class PeerType(MRTObject):
    _value: int

    def __init__(self, value):
        super(PeerType, self).__init__(1)
        self._value = value

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0):
        value = struct.unpack_from("b", buffer, offset)[0]
        return PeerType(value)

    @property
    def ipversion(self) -> int:
        if self._value & 1:
            return 6
        return 4

    @property
    def is_ipv4(self) -> bool:
        return self._value & 1 == 0

    @property
    def is_ipv6(self) -> bool:
        return self._value & 1 == 1

    @property
    def ipaddress_size(self) -> int:
        return 16 if self._value & 1 else 4

    @property
    def asn_size(self) -> int:
        return 4 if self._value & 2 else 2

    def explain(self) -> List[str]:
        lines = list()
        lines.append(f"peer type      - {self._value:1d} = b{self._value:08b}")
        indent = len(lines[0]) - 1
        pad = " " * indent
        line = "-" * 3
        lines.append(f"{pad}{line}IPv{self.ipversion}")
        lines.append(
            f"{pad[1:]}{line}- AS{self.asn_size}- AS size = {self.asn_size} octets"
        )
        return lines


class PeerIndexEntry(MRTObject):
    _type: PeerType
    _bgp_id: int
    _ipaddress_size: int
    _ipaddress: bytes
    _asn_size: int
    _asn: int

    def __init__(
        self,
        peer_type: PeerType,
        bgp_id: int,
        ipaddress_size: int,
        address: bytes,
        asn_size: int,
        asn: int,
        size: int,
    ):
        super(PeerIndexEntry, self).__init__(size)
        self._type = peer_type
        self._bgp_id = bgp_id
        self._ipaddress_size = ipaddress_size
        self._ipaddress = address
        self._asn_size = asn_size
        self._asn = asn

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0) -> "PeerIndexEntry":
        peer_type = PeerType.unpack_from(buffer, offset + 0)
        peer_bgp_id = struct.unpack_from("!l", buffer, offset + 1)[0]
        ipaddress_size = peer_type.ipaddress_size
        fmt = f"!{ipaddress_size}b"
        ip = struct.unpack_from(fmt, buffer, offset + 5)[0]
        asn_size = peer_type.asn_size
        fmt = "!l" if asn_size == 4 else "!h"
        asn = struct.unpack_from(fmt, buffer, offset + 5 + ipaddress_size)[0]
        return PeerIndexEntry(
            peer_type,
            peer_bgp_id,
            ipaddress_size,
            ip,
            asn_size,
            asn,
            5 + ipaddress_size + asn_size,
        )

    @property
    def type(self) -> PeerType:
        return self._type

    @property
    def asn_size(self) -> int:
        return self._asn_size

    def explain(self) -> List[str]:
        return []


class PeerIndexTable(MRTObject):
    _collector_bgp_id: int
    _view_name_length: int
    _view_name: str
    _peer_count: int
    _peers: []

    def __init__(
        self,
        collector_bgp_id: int,
        view_name_length: int,
        view_name: str,
        peer_count: int,
        peers: List[PeerIndexEntry],
        size: int,
    ):
        super(PeerIndexTable, self).__init__(size)
        self._collector_bgp_id = collector_bgp_id
        self._view_name_length = -view_name_length
        self._view_name = view_name
        self._peer_count = peer_count
        self._peers = peers

    def __len__(self):
        return self._size

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0) -> "PeerIndexTable":
        collector_bgp_id = struct.unpack_from("!l", buffer, offset)[0]
        view_name_length = struct.unpack_from("!h", buffer, offset + 4)[0]
        fmt = f"!{view_name_length}s"
        view_name = struct.unpack_from(fmt, buffer, offset + 6)[0]
        peer_count = struct.unpack_from("!h", buffer, offset + 6 + view_name_length)[0]
        peers = []
        pos = 6 + view_name_length + 2
        for i in range(0, peer_count):
            peer = PeerIndexEntry.unpack_from(buffer, offset + pos)
            pos += peer.nbytes
            peers.append(peer)
        return PeerIndexTable(
            collector_bgp_id, view_name_length, view_name, peer_count, peers, pos
        )

    @property
    def view_name(self) -> str:
        return self._view_name

    @property
    def peers(self) -> List[PeerIndexEntry]:
        return self._peers

    def explain(self) -> List[str]:
        return []


class BGPAttrFlag(MRTObject):
    _value: int

    def __init__(self, value: int):
        super(BGPAttrFlag, self).__init__(1)
        self._value = value

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0):
        value = struct.unpack_from("b", buffer, offset)[0]
        return BGPAttrFlag(value)

    @property
    def extended_length(self) -> bool:
        return self._value & 0x10

    @property
    def partial(self) -> bool:
        return self._value & 0x20

    @property
    def transitive(self) -> bool:
        return self._value & 0x40

    @property
    def optional(self) -> bool:
        return self._value & 0x80

    def explain(self) -> List[str]:
        lines = list()
        lines.append(f"bgp attr flag {self._value:1d} = b{self._value:08b}")
        indent = len(lines[0]) - 1
        pad = " " * indent
        line = "-" * 3
        lines.append(
            pad + "|" + line + " extended length"
            if self.extended_length
            else " not extended length"
        )
        lines.append(
            pad[1:] + "|" + line + "- " + " partial" if self.partial else " not partial"
        )
        lines.append(
            pad[2:] + "|" + line + "-- " + " transitive"
            if self.transitive
            else " not transitive"
        )
        lines.append(
            pad[3:] + "|" + line + "---" + " optional"
            if self.optional
            else " not optional"
        )
        return lines


class BGPAttrHeader(MRTObject):
    _flag: BGPAttrFlag
    _code: int
    _length: int
    _length_size: int

    _code_to_str = {
        0: "Reserved",
        1: "ORIGIN",
        2: "AS_PATH",
        3: "NEXT_HOP",
        4: "MULTI_EXIT_DISC",
        5: "LOCAL_PREF",
        6: "ATOMIC_AGGREGATE",
        7: "AGGREGATOR",
        8: "COMMUNITY",
        9: "ORIGINATOR_ID",
        10: "CLUSTER_LIST",
        14: "MP_REACH_NLRI",
        15: "MP_UNREACH_NLRI",
        16: "EXTENDED COMMUNITIES",
        17: "AS4_PATH",
        18: "AS4_AGGREGATOR",
    }

    def __init__(
        self, flag: BGPAttrFlag, code: int, length_size: int, length: int, size: int
    ):
        super(BGPAttrHeader, self).__init__(size)
        self._flag = flag
        self._code = code
        self._length_size = length_size
        self._length = length

    @classmethod
    def unpack_from(
        cls, buffer: bytes, offset: int = 0
    ) -> Tuple[int, int, int, int, int]:
        flag_value = struct.unpack_from("b", buffer, offset)[0]
        flag = BGPAttrFlag(flag_value)
        code = struct.unpack_from("b", buffer, offset + 1)[0]
        fmt = "b"
        length_size = 1
        if flag.extended_length:
            fmt = "!h"
            length_size = 2
        length = struct.unpack_from(fmt, buffer, offset + 2)[0]
        size = 2 + length_size
        return flag, code, length_size, length, size

    @property
    def flag(self) -> BGPAttrFlag:
        return self._flag

    @property
    def code(self) -> int:
        return self.code

    @property
    def length(self) -> int:
        return self._length

    @property
    def length_size(self) -> int:
        return self._length_size

    def explain(self) -> List[str]:
        return ["incomplete base class explain"]


class BGPAttrOrigin(BGPAttrHeader):
    _value: int
    _header_size: int

    def __init__(
        self,
        flag: BGPAttrFlag,
        code: int,
        length_size,
        length: int,
        header_size: int,
        size: int,
        value: int,
    ):
        super(BGPAttrOrigin, self).__init__(flag, code, length_size, length, size)
        self._value = value
        self._header_size = header_size

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0):
        (flag, code, length_size, length, header_size) = BGPAttrHeader.unpack_from(
            buffer, offset
        )
        value = struct.unpack_from("b", buffer, offset + header_size)[0]
        return BGPAttrOrigin(
            flag, code, length_size, length, header_size, header_size + 1, value
        )

    @property
    def nbytes(self) -> int:
        return self._header_size + 1

    @property
    def is_incomplete(self) -> bool:
        return self._value == 2

    @property
    def value(self) -> int:
        return self._value

    @property
    def header_size(self) -> int:
        return self._header_size

    def explain(self):
        pass


class BGPAttrASPath(BGPAttrHeader):
    _header_size: int
    _asn_size: int
    _type: int
    _segments: List[int]

    def __init__(
        self,
        flag: int,
        code: int,
        length_size: BGPAttrFlag,
        length: int,
        header_size: int,
        size: int,
        asn_size: int,
        path_type: int,
        segments: List[int],
    ):
        super(BGPAttrASPath, self).__init__(flag, code, length_size, length, size)
        self._asn_size = asn_size
        self._header_size = header_size
        self._type = path_type
        self._segments = segments

    # noinspection PyMethodOverriding
    @classmethod
    def unpack_from(cls, asn_size: int, buffer: bytes, offset: int = 0):
        (flag, code, length_size, length, header_size) = BGPAttrHeader.unpack_from(
            buffer, offset
        )
        path_type = struct.unpack_from("!b", buffer, offset + header_size)[0]
        segments = []
        asn_fmt = "!h" if asn_size == 2 else "!l"
        remaining = length - 2
        segment_length = struct.unpack_from("!b", buffer, offset + 1 + header_size)[0]
        for i in range(0, segment_length):
            asn = struct.unpack_from(
                asn_fmt, buffer, offset + 2 + header_size + i * asn_size
            )[0]
            segments.append(asn)

        return BGPAttrASPath(
            flag=flag,
            code=code,
            length_size=length_size,
            length=length,
            header_size=header_size,
            size=2 + header_size + segment_length * asn_size,
            asn_size=asn_size,
            path_type=path_type,
            segments=segments,
        )

    @property
    def nbytes(self):
        return self._size

    @property
    def asn_size(self) -> int:
        return self._asn_size

    @property
    def header_size(self) -> int:
        return self._header_size

    @property
    def segments(self) -> List[int]:
        return self._segments

    @property
    def type(self) -> int:
        return self._type


class BGPAttrNextHop(BGPAttrHeader):
    _ip_version: int
    _next_hop: IPAddress

    def __init__(
        self,
        flag: BGPAttrFlag,
        code: int,
        length_size: int,
        length: int,
        header_size: int,
        size: int,
        ip_version: int,
        next_hop: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    ):
        super(BGPAttrNextHop, self).__init__(flag, code, length_size, length, size)
        self._header_size = header_size
        self._ip_version = ip_version
        self._next_hop = next_hop

    # noinspection PyMethodOverriding
    @classmethod
    def unpack_from(cls, ip_version: int, buffer: bytes, offset: int = 0):
        (flag, code, length_size, length, header_size) = BGPAttrHeader.unpack_from(
            buffer, offset
        )
        # unpack prefix
        if ip_version == 4:
            size = header_size + 4
            packed = buffer[header_size : header_size + 4]
            next_hop = ipaddress.IPv4Address(packed)
        if ip_version == 6:
            size = header_size + 16
            packed = buffer[header_size : header_size + 16]
            next_hop = ipaddress.IPv6Address(packed)
        return BGPAttrNextHop(
            flag, length, code, length_size, header_size, size, ip_version, next_hop
        )

    @property
    def nbytes(self) -> int:
        return self._size

    @property
    def ip_version(self) -> int:
        return self._ip_version

    @property
    def header_size(self) -> int:
        return self._header_size

    @property
    def next_hop(self) -> IPAddress:
        return self._next_hop


class BGPAttrLocalPref(BGPAttrHeader):
    _header_size: int
    _value: int

    def __init__(
        self,
        flag: BGPAttrFlag,
        code: int,
        length_size: int,
        length: int,
        header_size: int,
        size: int,
        value: int,
    ):
        super(BGPAttrLocalPref, self).__init__(flag, length, code, length_size, size)
        self._header_size = header_size
        self._value = value

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0):
        (flag, code, length_size, length, header_size) = BGPAttrHeader.unpack_from(
            buffer, offset
        )
        value = struct.unpack_from("!l", buffer, offset + header_size)[0]
        return BGPAttrLocalPref(
            flag, code, length_size, length, header_size, header_size + 4, value
        )

    @property
    def nbytes(self) -> int:
        return self._size

    @property
    def value(self) -> int:
        return self._value


class BGPAttrMPReachNLRI(BGPAttrHeader):
    _afi: int
    _safi: int
    _next_hop_len: int
    _next_hop: int
    _nlri: bytes

    def __init__(
        self,
        flag: BGPAttrFlag,
        code: int,
        length_size: int,
        length: int,
        size: int,
        afi: int,
        safi: int,
        next_hop_len: int,
        next_hop: Union[ipaddress.IPv4Network, ipaddress.IPv6Network],
        packet_length: int,
        nlri: bytes,
    ):
        super(BGPAttrMPReachNLRI, self).__init__(flag, code, length_size, length, size)
        self._afi = afi
        self._safi = safi
        self._next_hop_len = next_hop_len
        self._next_hop = next_hop
        self._packet_length = packet_length
        self._nlri = nlri

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0, packet_length: int) -> "BGPAttrMPReachNLRI":
        (flag, code, length_size, length, header_size) = BGPAttrHeader.unpack_from(
            buffer, offset
        )
        afi = struct.unpack_from("!h", buffer, offset + header_size)[0]
        safi = struct.unpack_from("!b", buffer, offset + header_size + 2)[0]
        next_hop_len = struct.unpack_from("!b", buffer, offset + header_size + 3)[0]

        begin_of_nlri = header_size + 4 + next_hop_len + 1
        return BGPAttrMPReachNLRI(
            flag,
            code,
            length_size,
            length,
            header_size + 4 + next_hop_len + 1 + 1,
            afi,
            safi,
            next_hop_len,
            packet_length,
            buffer[ begin_of_nlri: packet_length ]
        )


bgp_attribute_decoder = {
    1: BGPAttrOrigin,
    2: BGPAttrASPath,
    3: BGPAttrNextHop,
    # 4: "MULTI_EXIT_DISC",
    5: BGPAttrLocalPref,
    # 6: "ATOMIC_AGGREGATE",
    # 7: "AGGREGATOR",
    # 8: "COMMUNITY",
    # 9: "ORIGINATOR_ID",
    # 10: "CLUSTER_LIST",
    14: BGPAttrMPReachNLRI,
    # 15: "MP_UNREACH_NLRI",
    # 16: "EXTENDED COMMUNITIES",
    # 17: "AS4_PATH",
    # 18: "AS4_AGGREGATOR",
}


class BGPAttributeFactory(object):
    @classmethod
    def decode_attributes(
        cls, ip_version: int, asn_size: int, buffer: bytes, length: int, offset: int = 0
    ) -> Tuple[List[BGPAttrHeader], int]:
        result: List[BGPAttrHeader] = []
        remaining = length
        pos = 0
        while remaining > 0:
            # look ahead to code
            code = struct.unpack_from("b", buffer, offset + pos + 1)[0]
            decoder = bgp_attribute_decoder.get(code, None)
            if not decoder:
                raise RuntimeError(f"Decoder for BPG Attribute type {code} not known")
            if code == 2:
                a = decoder.unpack_from(asn_size, buffer, offset + pos)
            elif code == 3:
                a = decoder.unpack_from(ip_version, buffer, offset + pos)
            elif code == 14:
                a = decoder.unpack_from(buffer, offset + pos)
            else:
                a = decoder.unpack_from(buffer, offset + pos)
            result.append(a)
            pos += a.nbytes
            remaining -= a.nbytes

        return result, pos


class BGPAttributes(MRTObject):
    _asn_size: int
    _attributes: List

    def __init__(self, asn_size: int, attributes: list):
        self._asn_size = asn_size
        self._attributes = attributes
        size = 0
        for a in self._attributes:
            size += a.nbytes
        super(BGPAttributes, self).__init__(size)

    @classmethod
    def unpack_from(
        cls,
        ip_version: int,
        asn_size: int,
        section_length: int,
        buffer: bytes,
        offset: int = 0,
    ):
        remaining = section_length
        attrs = []
        while remaining > 0:
            (a, pos) = BGPAttributeFactory.decode_attributes(
                ip_version, asn_size, buffer, section_length, offset
            )
            attrs.extend(a)
            remaining -= pos
        return BGPAttributes(asn_size, attrs)

    def __len__(self):
        return len(self._attributes)

    @property
    def asn_size(self) -> int:
        return self._asn_size

    @property
    def attributes(self) -> List:
        return self._attributes


class RibTableEntry(MRTObject):
    def __init__(self, size):
        super(RibTableEntry, self).__init__(size)


class RibTableEntryIPv6Unicast(RibTableEntry):
    _peer_index: int
    _originating_time: int
    _attribute_length: int
    _attributes: BGPAttributes

    def __init__(self, peer_index: int, originating_time: int, attrs: BGPAttributes):
        self._peer_index = peer_index
        self._originating_time = originating_time
        self._attributes = attrs
        super(RibTableEntryIPv6Unicast, self).__init__(8 + self._attributes.nbytes)

    @classmethod
    def unpack_from(cls, asn_size: int, buffer: bytes, offset: int = 0):
        peer_index = struct.unpack_from("!h", buffer, offset)[0]
        originating_time = struct.unpack_from("!l", buffer, offset + 2)[0]
        attributes_length = struct.unpack_from("!h", buffer, offset + 6)[0]
        attrs = BGPAttributes.unpack_from(
            6, asn_size, attributes_length, buffer, offset + 8
        )
        return RibTableEntryIPv6Unicast(peer_index, originating_time, attrs)

    @property
    def peer_index(self) -> int:
        return self._peer_index

    @property
    def originating_time(self) -> int:
        return self._originating_time

    @property
    def attributes(self) -> BGPAttributes:
        return self._attributes

    @property
    def asn_size(self):
        return self._attributes.asn_size


class RibTable(MRTObject):
    _address_family: int

    def __init__(self, address_family: int, size):
        super(RibTable, self).__init__(size)
        self._address_family = address_family

    @property
    def address_family(self) -> int:
        return self._address_family


class RibTableIPv6Unicast(RibTable):
    _sequence_number: int
    _prefix: MRTPrefix
    _entries: List[RibTableEntryIPv6Unicast]
    _size: int

    def __init__(
        self,
        sequence_number: int,
        prefix: MRTPrefix,
        entries: List[RibTableEntryIPv6Unicast],
    ):
        self._sequence_number = sequence_number
        self._prefix = prefix
        self._entries = entries
        #
        size = 0
        for entry in entries:
            size += entry.nbytes
        super(RibTableIPv6Unicast, self).__init__(6, size)

    @classmethod
    def unpack_from(cls, asn_size, buffer: bytes, offset: int = 0):
        sequence_number = struct.unpack_from("!l", buffer, offset)[0]
        prefix = MRTPrefix.unpack_from(6, buffer, offset + 4)
        pos = 4 + prefix.nbytes
        entry_count = struct.unpack_from("!h", buffer, offset + pos)[0]
        pos += 2
        entries = []
        for i in range(0, entry_count):
            entry = RibTableEntryIPv6Unicast.unpack_from(asn_size, buffer, offset + pos)
            entries.append(entry)
            pos += entry.nbytes

        return RibTableIPv6Unicast(sequence_number, prefix, entries)

    @property
    def nbytes(self) -> int:
        return self._size

    @property
    def entries(self) -> List[RibTableEntryIPv6Unicast]:
        return self._entries

    def __len__(self):
        return len(self._entries)

    @property
    def length(self):
        return len(self._entries)

    @property
    def sequence_number(self) -> int:
        return self._sequence_number

    @property
    def prefix(self) -> MRTPrefix:
        return self._prefix


class MRTSection(MRTObject):
    TYPE_TABLE_DUMPV2: int = 13
    SUBTYPE_PEER_INDEX_TABLE = 1
    SUBTYPE_RIB_IPV4_UNICAST = 2
    SUBTYPE_RIB_IPV4_MULTICAST = 3
    SUBTYPE_RIB_IPV6_UNICAST = 4
    SUBTYPE_RIB_IPV6_MULTICAST = 5

    _header: MRTHeader
    _content: Union[PeerIndexTable, RibTable]

    def __init__(
        self, header: MRTHeader, entry: Union[PeerIndexTable, RibTable], size: int
    ):
        super(MRTSection, self).__init__(size)
        self._header = header
        self._entry = entry

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0, asn_size: int = None):
        header = MRTHeader.unpack_from(buffer, offset)
        type_code = header.type.code
        if type_code == 13:
            """ supported subtypes 
        1: "PEER_INDEX_TABLE",
        2: "RIB_IPV4_UNICAST",
        3: "RIB_IPV4_MULTICAST",
        4: "RIB_IPV6_UNICAST",
        5: "RIB_IPV6_MULTICAST",
            """
            subtype_code = header.subtype.code
            if subtype_code == 1:
                entry = PeerIndexTable.unpack_from(buffer, offset + header.nbytes)
                # get asn_size from peer index table
                asn_size = entry.peers[0].asn_size
                same_size_count = [e.asn_size for e in entry.peers].count(asn_size)
                different_count = len(entry.peers) - same_size_count
                if different_count:
                    raise RuntimeError(
                        f"Do not know how to handle {different_count} peers with different asn_size than {asn_size}"
                    )
            elif subtype_code == 4:
                if asn_size is None:
                    raise RuntimeError(f"Encountered RibTable without asn_size set")
                entry = RibTableIPv6Unicast.unpack_from(
                    asn_size, buffer, offset + header.nbytes
                )
            else:
                raise RuntimeError(f"Unsupported mrtdump subtype 0x{subtype_code:04x}")

        else:
            raise RuntimeError(f"Unsupported mrtdump type 0x{type_code:04x}")
        return MRTSection(header, entry, header.nbytes + entry.nbytes)

    @property
    def entry_type(self) -> Tuple[int, int]:
        return self._header.type.code, self._header.subtype.code

    @property
    def header(self) -> MRTHeader:
        return self._header

    @property
    def entry(self) -> Union[PeerIndexTable, RibTable]:
        return self._entry


class MRTDump(MRTObject):
    _sections: List[MRTSection]

    def __init__(self, sections: List[MRTSection]):
        self._sections = sections
        size = 0
        for i in range(0, len(sections)):
            size += sections[i].nbytes
        super(MRTDump, self).__init__(size)

    @classmethod
    def unpack_from(cls, buffer: bytes, offset: int = 0):
        sections = []
        remaining = len(buffer)
        asn_size = None
        pos = 0
        while remaining > 0:
            section = MRTSection.unpack_from(buffer, offset + pos, asn_size)
            info = section.entry_type
            if (
                info[0] == MRTSection.TYPE_TABLE_DUMPV2
                and info[1] == MRTSection.SUBTYPE_PEER_INDEX_TABLE
            ):
                asn_size = section.entry.peers[0].asn_size
            sections.append(section)
            pos += section.nbytes
            remaining -= section.nbytes
        return MRTDump(sections)

    def __len__(self):
        return len(self._sections)

    @property
    def sections(self) -> List[MRTSection]:
        return self._sections


class MRTFile(object):
    pass


def main():
    import sys

    with open(sys.argv[1], "rb") as dumpfile:
        content = dumpfile.read()
        dumpfile.close()

    dump = MRTDump.unpack_from(content, 0)
    print("\n".join(dump.explain()))


if __name__ == "__main__":
    main()
