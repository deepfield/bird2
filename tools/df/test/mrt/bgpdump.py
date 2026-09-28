"""
The consumer's view of a dump: run the product's bgpdump with -m and split its output.

bgpdump 1.4.99.14 as shipped in the deepfield-pipedream package prints one line per RIB
entry:

  TABLE_DUMP_V2(<afi>,<safi>)|<time>|B|<peer ip>|<peer as>|[<rd>|]<prefix>|<as path>|
  <origin>|<next hop>|<local pref>|<med>|<communities>|<AG|NAG>|<aggregator>|

The RD field is present only for SAFI 128, and a VPN prefix length counts the label and
RD bits (a VPNv4 /24 prints as /112). A missing LOCAL_PREF or MED prints as 0.

bgpdump exits 0 even on a malformed file: it logs `[warn]`/`[error]` lines (to stderr
with -v) and may silently drop the broken record. run() therefore returns those lines
and tests assert there are none.
"""

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Union

_TYPE_RE = re.compile(r"^TABLE_DUMP_V2\((\d+),(\d+)\)$")
_LOG_RE = re.compile(r"^\S+ \S+ \[(\w+)\] (.*)$")


class BgpdumpError(RuntimeError):
    pass


@dataclass
class Row:
    afi: int
    safi: int
    timestamp: int
    peer_ip: str
    peer_as: int
    rd: Optional[str]
    prefix: str
    as_path: str
    origin: str
    next_hop: str
    local_pref: int
    med: int
    communities: str
    atomic_aggregate: str
    aggregator: str
    line: str


@dataclass
class Result:
    rows: List[Row]
    problems: List[str]      # bgpdump's [warn]/[error] log lines
    stderr: str

    def by_prefix(self) -> dict:
        out: dict = {}
        for row in self.rows:
            out.setdefault(row.prefix, []).append(row)
        return out

    def row(self, prefix: str) -> Row:
        """The single row for `prefix` as bgpdump prints it; fails if not exactly one."""
        rows = self.by_prefix().get(prefix, [])
        if len(rows) != 1:
            raise LookupError(f"{len(rows)} bgpdump rows for {prefix}, expected 1")
        return rows[0]


def parse_line(line: str) -> Row:
    fields = line.split("|")
    m = _TYPE_RE.match(fields[0])
    if not m:
        raise BgpdumpError(f"not a TABLE_DUMP_V2 line: {line!r}")
    if fields[-1] != "":
        raise BgpdumpError(f"line does not end with '|': {line!r}")
    afi, safi = int(m.group(1)), int(m.group(2))
    fields = fields[:-1]
    vpn = safi == 128
    if len(fields) != (15 if vpn else 14):
        raise BgpdumpError(f"{len(fields)} fields for SAFI {safi}: {line!r}")
    rd = fields.pop(5) if vpn else None
    (_, ts, kind, peer_ip, peer_as, prefix, as_path, origin, next_hop,
     local_pref, med, communities, atomic, aggregator) = fields
    if kind != "B":
        raise BgpdumpError(f"entry kind {kind!r}, expected 'B': {line!r}")
    return Row(afi, safi, int(ts), peer_ip, int(peer_as), rd, prefix, as_path, origin,
               next_hop, int(local_pref), int(med), communities, atomic, aggregator, line)


def run(path: Union[str, Path], binary: Union[str, Path] = "bgpdump") -> Result:
    proc = subprocess.run([str(binary), "-m", "-v", str(path)], capture_output=True, text=True)
    if proc.returncode != 0:
        raise BgpdumpError(f"bgpdump exited {proc.returncode}: {proc.stderr.strip()}")
    problems = []
    for line in proc.stderr.splitlines():
        m = _LOG_RE.match(line)
        if not m or m.group(1) not in ("info", "debug"):
            problems.append(line)
    rows = [parse_line(line) for line in proc.stdout.splitlines() if line]
    return Result(rows, problems, proc.stderr)
