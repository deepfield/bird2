def hexline(
    block: bytes,
    addr: int = 0,
    size: int = 1,
    width: int = 16,
    byteorder: str = "little",
    sep: str = " ",
    sep_interval: int = 8,
    skipAscii: bool = True,
):
    """
    produce a hexdump line

    :param block: the bytes
    :param addr: addr to start line with
    :param size: value size (1 = bytes, 2 = words)
    :param width: number of bytes to dump
    :param byteorder: passed to int.from_bytes as byteorder
    :param sep: separator char between hex values
    :param sep_interval: repeat interval for separator (every n bytes/words)
    :param skipAscii: skip the appending of Ascii character
    :return:
    """
    addr_part = "%08x" % addr
    chunk_format = "%0" + str(size * 2) + "x"
    result = addr_part
    result_symbols = []
    pos = 0
    while pos < width:
        chunk = int.from_bytes(block[pos : pos + size], byteorder)
        result = result + sep
        if pos % sep_interval == 0:
            result = result + sep
        if pos < len(block):
            result = result + chunk_format % chunk
            if not skipAscii:
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