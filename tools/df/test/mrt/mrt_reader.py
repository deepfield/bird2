"""
Strict, dependency-free reader for the MRT files BIRD writes (RFC 6396).

TABLE_DUMP_V2 is decoded fully: PEER_INDEX_TABLE, the RIB_IPV4/IPV6 unicast and
multicast subtypes, their ADDPATH variants (RFC 8050) and RIB_GENERIC for AFI 1/2 with
SAFI 1/2/128. Records of any other type are kept raw in MrtFile.other.

"Strict" means every length and count is checked and all bytes must be accounted for:
a malformed record raises MrtFormatError with its file offset instead of being skipped.
Nothing is normalised on the way: attribute flags, the route distinguisher and the MPLS
label stack are returned exactly as written, so tests can assert on BIRD's bytes.

Path attributes in a RIB entry use the table-dump layout, which differs from the wire
in one place: MP_REACH_NLRI keeps only the next hop length and next hop (RFC 6396
4.3.4). parse_mp_reach(table_dump=False) decodes the wire layout.
"""

import ipaddress
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# MRT types and TABLE_DUMP_V2 subtypes
TABLE_DUMP_V2 = 13
BGP4MP = 16

PEER_INDEX_TABLE = 1
RIB_IPV4_UNICAST = 2
RIB_IPV4_MULTICAST = 3
RIB_IPV6_UNICAST = 4
RIB_IPV6_MULTICAST = 5
RIB_GENERIC = 6
RIB_IPV4_UNICAST_ADDPATH = 8
RIB_IPV4_MULTICAST_ADDPATH = 9
RIB_IPV6_UNICAST_ADDPATH = 10
RIB_IPV6_MULTICAST_ADDPATH = 11
RIB_GENERIC_ADDPATH = 12

AFI_IPV4, AFI_IPV6 = 1, 2
SAFI_UNICAST, SAFI_MULTICAST, SAFI_MPLS_VPN = 1, 2, 128

# subtype -> (afi, safi, add_path) for the fixed-family RIB subtypes
_RIB_FAMILY = {
    RIB_IPV4_UNICAST: (AFI_IPV4, SAFI_UNICAST, False),
    RIB_IPV4_MULTICAST: (AFI_IPV4, SAFI_MULTICAST, False),
    RIB_IPV6_UNICAST: (AFI_IPV6, SAFI_UNICAST, False),
    RIB_IPV6_MULTICAST: (AFI_IPV6, SAFI_MULTICAST, False),
    RIB_IPV4_UNICAST_ADDPATH: (AFI_IPV4, SAFI_UNICAST, True),
    RIB_IPV4_MULTICAST_ADDPATH: (AFI_IPV4, SAFI_MULTICAST, True),
    RIB_IPV6_UNICAST_ADDPATH: (AFI_IPV6, SAFI_UNICAST, True),
    RIB_IPV6_MULTICAST_ADDPATH: (AFI_IPV6, SAFI_MULTICAST, True),
}
RIB_SUBTYPES = set(_RIB_FAMILY) | {RIB_GENERIC, RIB_GENERIC_ADDPATH}

# BGP path attribute codes and flags
ORIGIN = 1
AS_PATH = 2
NEXT_HOP = 3
MED = 4
LOCAL_PREF = 5
ATOMIC_AGGREGATE = 6
AGGREGATOR = 7
COMMUNITY = 8
ORIGINATOR_ID = 9
CLUSTER_LIST = 10
MP_REACH_NLRI = 14
MP_UNREACH_NLRI = 15
EXT_COMMUNITY = 16
AS4_PATH = 17
AS4_AGGREGATOR = 18
IPV6_EXT_COMMUNITY = 25
LARGE_COMMUNITY = 32

FLAG_OPTIONAL = 0x80
FLAG_TRANSITIVE = 0x40
FLAG_PARTIAL = 0x20
FLAG_EXTENDED = 0x10

AS_SET, AS_SEQUENCE, AS_CONFED_SEQUENCE, AS_CONFED_SET = 1, 2, 3, 4

MRT_HEADER_LEN = 12


class MrtFormatError(ValueError):
    def __init__(self, msg: str, offset: Optional[int] = None):
        super().__init__(msg if offset is None else f"{msg} (at file offset {offset})")
        self.offset = offset


class _Cursor:
    """Bounds-checked reader over `data`; `base` is the file offset of data[0]."""

    def __init__(self, data: bytes, base: int = 0):
        self.data, self.base, self.pos = data, base, 0

    @property
    def offset(self) -> int:
        return self.base + self.pos

    def take(self, n: int, what: str = "field") -> bytes:
        if n > len(self.data) - self.pos:
            raise MrtFormatError(
                f"{what}: need {n} bytes, only {len(self.data) - self.pos} left", self.offset)
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self, what: str = "u8") -> int:
        return self.take(1, what)[0]

    def u16(self, what: str = "u16") -> int:
        return struct.unpack("!H", self.take(2, what))[0]

    def u32(self, what: str = "u32") -> int:
        return struct.unpack("!I", self.take(4, what))[0]

    def done(self) -> bool:
        return self.pos == len(self.data)

    def expect_end(self, what: str) -> None:
        if not self.done():
            raise MrtFormatError(f"{what}: {len(self.data) - self.pos} trailing bytes", self.offset)


# -- records -----------------------------------------------------------------------

@dataclass
class Record:
    offset: int          # file offset of the MRT header
    timestamp: int
    type: int
    subtype: int
    body: bytes

    @property
    def body_offset(self) -> int:
        return self.offset + MRT_HEADER_LEN


def iter_records(data: bytes) -> Iterator[Record]:
    pos = 0
    while pos < len(data):
        if len(data) - pos < MRT_HEADER_LEN:
            raise MrtFormatError(f"truncated MRT header ({len(data) - pos} bytes)", pos)
        timestamp, rtype, subtype, length = struct.unpack_from("!IHHI", data, pos)
        end = pos + MRT_HEADER_LEN + length
        if end > len(data):
            raise MrtFormatError(
                f"record length {length} runs {end - len(data)} bytes past the end", pos)
        yield Record(pos, timestamp, rtype, subtype, data[pos + MRT_HEADER_LEN:end])
        pos = end


# -- PEER_INDEX_TABLE ------------------------------------------------------------

@dataclass
class Peer:
    index: int
    peer_type: int
    bgp_id: ipaddress.IPv4Address
    ip: IPAddress
    asn: int


@dataclass
class PeerIndexTable:
    record: Record
    collector_id: ipaddress.IPv4Address
    view_name: str
    peers: List[Peer]


def parse_peer_index_table(rec: Record) -> PeerIndexTable:
    c = _Cursor(rec.body, rec.body_offset)
    collector = ipaddress.IPv4Address(c.take(4, "collector BGP ID"))
    name = c.take(c.u16("view name length"), "view name")
    try:
        view_name = name.decode("ascii")
    except UnicodeDecodeError:
        raise MrtFormatError(f"view name is not ASCII: {name!r}", rec.body_offset + 6)
    peers = []
    for i in range(c.u16("peer count")):
        at = c.offset
        ptype = c.u8("peer type")
        if ptype & ~0x03:
            raise MrtFormatError(f"peer {i}: unknown peer type bits 0x{ptype:02x}", at)
        bgp_id = ipaddress.IPv4Address(c.take(4, "peer BGP ID"))
        if ptype & 0x01:
            ip: IPAddress = ipaddress.IPv6Address(c.take(16, "peer IPv6 address"))
        else:
            ip = ipaddress.IPv4Address(c.take(4, "peer IPv4 address"))
        asn = c.u32("peer AS") if ptype & 0x02 else c.u16("peer AS")
        peers.append(Peer(i, ptype, bgp_id, ip, asn))
    c.expect_end("PEER_INDEX_TABLE")
    return PeerIndexTable(rec, collector, view_name, peers)


# -- path attributes ----------------------------------------------------------------

@dataclass
class Attribute:
    flags: int
    code: int
    value: bytes
    offset: int          # file offset of the attribute header

    def decode(self, table_dump: bool = True):
        return decode_attribute(self.code, self.value, table_dump)


def parse_attributes(data: bytes, base: int = 0) -> List[Attribute]:
    c = _Cursor(data, base)
    attrs: List[Attribute] = []
    seen = set()
    while not c.done():
        at = c.offset
        flags = c.u8("attribute flags")
        code = c.u8("attribute code")
        if flags & 0x0F:
            raise MrtFormatError(f"attribute {code}: unused flag bits set (0x{flags:02x})", at)
        length = c.u16("attribute length") if flags & FLAG_EXTENDED else c.u8("attribute length")
        value = c.take(length, f"attribute {code} value")
        if code in seen:
            raise MrtFormatError(f"attribute {code} appears twice", at)
        seen.add(code)
        attrs.append(Attribute(flags, code, value, at))
    return attrs


@dataclass
class MpReach:
    next_hops: List[IPAddress]
    afi: Optional[int] = None        # wire layout only
    safi: Optional[int] = None       # wire layout only
    nlri: bytes = b""                # wire layout only, undecoded


def _next_hops(raw: bytes) -> List[IPAddress]:
    """Next hop field of MP_REACH_NLRI: IPv4, IPv6, IPv6 + link-local, or RD-prefixed (VPN)."""
    n = len(raw)
    if n == 4:
        return [ipaddress.IPv4Address(raw)]
    if n in (16, 32):
        return [ipaddress.IPv6Address(raw[i:i + 16]) for i in range(0, n, 16)]
    if n == 12:
        return [ipaddress.IPv4Address(raw[8:])]
    if n in (24, 48):
        return [ipaddress.IPv6Address(raw[i + 8:i + 24]) for i in range(0, n, 24)]
    raise MrtFormatError(f"next hop length {n} is not 4, 12, 16, 24, 32 or 48")


def parse_mp_reach(value: bytes, table_dump: bool = True) -> MpReach:
    c = _Cursor(value)
    if table_dump:
        nh = c.take(c.u8("next hop length"), "next hop")
        c.expect_end("MP_REACH_NLRI (table dump layout)")
        return MpReach(_next_hops(nh))
    afi, safi = c.u16("AFI"), c.u8("SAFI")
    nh = c.take(c.u8("next hop length"), "next hop")
    c.u8("reserved")
    return MpReach(_next_hops(nh), afi, safi, c.take(len(value) - c.pos))


def _fixed(value: bytes, size: int, name: str) -> bytes:
    if len(value) != size:
        raise MrtFormatError(f"{name}: length {len(value)}, expected {size}")
    return value


def _chunks(value: bytes, size: int, name: str) -> List[bytes]:
    if len(value) % size:
        raise MrtFormatError(f"{name}: length {len(value)} is not a multiple of {size}")
    return [value[i:i + size] for i in range(0, len(value), size)]


def _origin(v: bytes) -> int:
    o = _fixed(v, 1, "ORIGIN")[0]
    if o > 2:
        raise MrtFormatError(f"ORIGIN value {o}")
    return o


def _as_path(v: bytes) -> List[Tuple[int, List[int]]]:
    """Segments as (type, [asn, ...]); TABLE_DUMP_V2 always uses 4-byte ASNs."""
    c = _Cursor(v)
    segments = []
    while not c.done():
        stype = c.u8("AS_PATH segment type")
        if stype not in (AS_SET, AS_SEQUENCE, AS_CONFED_SEQUENCE, AS_CONFED_SET):
            raise MrtFormatError(f"AS_PATH segment type {stype}")
        count = c.u8("AS_PATH segment length")
        segments.append((stype, [c.u32("ASN") for _ in range(count)]))
    return segments


def _u32(name):
    return lambda v: struct.unpack("!I", _fixed(v, 4, name))[0]


def _atomic(v: bytes) -> bool:
    _fixed(v, 0, "ATOMIC_AGGREGATE")
    return True


def _aggregator(v: bytes) -> Tuple[int, ipaddress.IPv4Address]:
    _fixed(v, 8, "AGGREGATOR")
    return struct.unpack("!I", v[:4])[0], ipaddress.IPv4Address(v[4:])


_DECODERS = {
    ORIGIN: _origin,
    AS_PATH: _as_path,
    NEXT_HOP: lambda v: ipaddress.IPv4Address(_fixed(v, 4, "NEXT_HOP")),
    MED: _u32("MED"),
    LOCAL_PREF: _u32("LOCAL_PREF"),
    ATOMIC_AGGREGATE: _atomic,
    AGGREGATOR: _aggregator,
    COMMUNITY: lambda v: [struct.unpack("!HH", x) for x in _chunks(v, 4, "COMMUNITY")],
    ORIGINATOR_ID: lambda v: ipaddress.IPv4Address(_fixed(v, 4, "ORIGINATOR_ID")),
    CLUSTER_LIST: lambda v: [ipaddress.IPv4Address(x) for x in _chunks(v, 4, "CLUSTER_LIST")],
    EXT_COMMUNITY: lambda v: _chunks(v, 8, "EXT_COMMUNITY"),
    AS4_PATH: _as_path,
    IPV6_EXT_COMMUNITY: lambda v: _chunks(v, 20, "IPV6_EXT_COMMUNITY"),
    LARGE_COMMUNITY: lambda v: [struct.unpack("!III", x) for x in _chunks(v, 12, "LARGE_COMMUNITY")],
}


def decode_attribute(code: int, value: bytes, table_dump: bool = True):
    """Decoded value of one attribute; unknown codes come back as raw bytes."""
    if code == MP_REACH_NLRI:
        return parse_mp_reach(value, table_dump)
    decoder = _DECODERS.get(code)
    return decoder(value) if decoder else value


# -- RIB records ------------------------------------------------------------------

@dataclass
class VpnPrefix:
    """SAFI 128 NLRI exactly as written: label stack entries, RD bytes, prefix."""
    labels: List[int]    # 24-bit entries: label << 4 | exp << 1 | bottom-of-stack
    rd: bytes            # 8 bytes, uninterpreted (the fork does not write RFC 4364 byte order)
    prefix: IPNetwork
    length_bits: int     # the NLRI length byte, which counts label and RD bits too


@dataclass
class RibEntry:
    peer_index: int
    originated: int
    path_id: Optional[int]
    attributes: List[Attribute]

    def attr(self, code: int) -> Optional[Attribute]:
        for a in self.attributes:
            if a.code == code:
                return a
        return None

    def get(self, code: int):
        """Decoded value of attribute `code`, or None if the entry does not carry it."""
        a = self.attr(code)
        return a.decode() if a else None

    def codes(self) -> List[int]:
        return [a.code for a in self.attributes]

    def next_hops(self) -> List[IPAddress]:
        """NEXT_HOP and/or the MP_REACH_NLRI next hops, in that order."""
        hops: List[IPAddress] = []
        nh = self.get(NEXT_HOP)
        if nh is not None:
            hops.append(nh)
        mp = self.get(MP_REACH_NLRI)
        if mp is not None:
            hops.extend(mp.next_hops)
        return hops


@dataclass
class Rib:
    record: Record
    sequence: int
    afi: int
    safi: int
    add_path: bool
    prefix: Union[IPNetwork, VpnPrefix]
    entries: List[RibEntry]

    @property
    def network(self) -> IPNetwork:
        """The IP prefix, without the VPN label stack and RD."""
        return self.prefix.prefix if isinstance(self.prefix, VpnPrefix) else self.prefix


def _network(afi: int, raw: bytes, plen: int, at: int) -> IPNetwork:
    size = 4 if afi == AFI_IPV4 else 16
    addr = ipaddress.ip_address(raw + bytes(size - len(raw)))
    try:
        return ipaddress.ip_network((addr, plen))
    except ValueError:
        raise MrtFormatError(f"prefix {addr}/{plen} has host bits set", at)


def _max_len(afi: int) -> int:
    return 32 if afi == AFI_IPV4 else 128


def _parse_prefix(c: _Cursor, afi: int) -> IPNetwork:
    at = c.offset
    plen = c.u8("prefix length")
    if plen > _max_len(afi):
        raise MrtFormatError(f"prefix length {plen} for AFI {afi}", at)
    return _network(afi, c.take((plen + 7) // 8, "prefix"), plen, at)


def _parse_vpn_nlri(c: _Cursor, afi: int) -> VpnPrefix:
    at = c.offset
    bits = c.u8("NLRI length")
    remaining = bits
    labels = []
    while True:
        if remaining < 24:
            raise MrtFormatError(f"NLRI length {bits} too short for the label stack", at)
        entry = int.from_bytes(c.take(3, "label"), "big")
        labels.append(entry)
        remaining -= 24
        if entry & 1:
            break
    if remaining < 64:
        raise MrtFormatError(f"NLRI length {bits} too short for the route distinguisher", at)
    rd = c.take(8, "route distinguisher")
    remaining -= 64
    if remaining > _max_len(afi):
        raise MrtFormatError(f"NLRI length {bits} leaves a {remaining}-bit prefix", at)
    prefix = _network(afi, c.take((remaining + 7) // 8, "prefix"), remaining, at)
    return VpnPrefix(labels, rd, prefix, bits)


def parse_rib(rec: Record) -> Rib:
    c = _Cursor(rec.body, rec.body_offset)
    sequence = c.u32("sequence number")
    if rec.subtype in (RIB_GENERIC, RIB_GENERIC_ADDPATH):
        add_path = rec.subtype == RIB_GENERIC_ADDPATH
        at = c.offset
        afi, safi = c.u16("AFI"), c.u8("SAFI")
        if afi not in (AFI_IPV4, AFI_IPV6):
            raise MrtFormatError(f"RIB_GENERIC AFI {afi}", at)
        if safi == SAFI_MPLS_VPN:
            prefix: Union[IPNetwork, VpnPrefix] = _parse_vpn_nlri(c, afi)
        elif safi in (SAFI_UNICAST, SAFI_MULTICAST):
            prefix = _parse_prefix(c, afi)
        else:
            raise MrtFormatError(f"RIB_GENERIC SAFI {safi} is not supported", at)
    else:
        afi, safi, add_path = _RIB_FAMILY[rec.subtype]
        prefix = _parse_prefix(c, afi)
    entries = []
    for _ in range(c.u16("entry count")):
        peer_index = c.u16("peer index")
        originated = c.u32("originated time")
        path_id = c.u32("path identifier") if add_path else None
        alen = c.u16("attribute length")
        base = c.offset
        attrs = parse_attributes(c.take(alen, "attributes"), base)
        entries.append(RibEntry(peer_index, originated, path_id, attrs))
    c.expect_end("RIB record")
    return Rib(rec, sequence, afi, safi, add_path, prefix, entries)


# -- files ----------------------------------------------------------------------

@dataclass
class Section:
    """A PEER_INDEX_TABLE and the RIB records that follow it."""
    peer_table: PeerIndexTable
    ribs: List[Rib] = field(default_factory=list)


@dataclass
class MrtFile:
    sections: List[Section]
    other: List[Record]      # records this reader does not interpret, e.g. BGP4MP

    def ribs(self) -> Iterator[Rib]:
        for s in self.sections:
            yield from s.ribs

    def by_network(self) -> Dict[IPNetwork, List[Rib]]:
        out: Dict[IPNetwork, List[Rib]] = {}
        for rib in self.ribs():
            out.setdefault(rib.network, []).append(rib)
        return out

    def rib(self, network: str) -> Rib:
        """The single RIB record for `network` (e.g. '10.0.0.0/24'); fails if not exactly one."""
        ribs = self.by_network().get(ipaddress.ip_network(network), [])
        if len(ribs) != 1:
            raise LookupError(f"{len(ribs)} RIB records for {network}, expected 1")
        return ribs[0]


def parse_file(data: bytes) -> MrtFile:
    """
    Parse a whole file. Beyond each record's own checks: RIB records must follow a
    PEER_INDEX_TABLE, their peer indexes must exist in it, and sequence numbers must go up
    by one within a section (a new section, i.e. a new table or an appended dump, may
    start anywhere).
    """
    sections: List[Section] = []
    other: List[Record] = []
    for rec in iter_records(data):
        if rec.type == TABLE_DUMP_V2 and rec.subtype == PEER_INDEX_TABLE:
            sections.append(Section(parse_peer_index_table(rec)))
        elif rec.type == TABLE_DUMP_V2 and rec.subtype in RIB_SUBTYPES:
            if not sections:
                raise MrtFormatError("RIB record before any PEER_INDEX_TABLE", rec.offset)
            section = sections[-1]
            rib = parse_rib(rec)
            if section.ribs and rib.sequence != section.ribs[-1].sequence + 1:
                raise MrtFormatError(
                    f"sequence number {rib.sequence} after {section.ribs[-1].sequence}", rec.offset)
            npeers = len(section.peer_table.peers)
            for e in rib.entries:
                if e.peer_index >= npeers:
                    raise MrtFormatError(
                        f"peer index {e.peer_index}, peer table has {npeers} peers", rec.offset)
            section.ribs.append(rib)
        else:
            other.append(rec)
    return MrtFile(sections, other)


def read(path: Union[str, Path]) -> MrtFile:
    return parse_file(Path(path).read_bytes())
