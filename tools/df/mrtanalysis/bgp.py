import ipaddress
import struct

from df.mrtanalysis.util import Block


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