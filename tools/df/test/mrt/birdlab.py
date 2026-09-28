"""
BIRD process driver for the MRT test lab.

A Lab owns a working directory, a set of namespaces (netns.py) and the BIRD daemons
running in them. Each daemon starts as root inside its namespace and drops to the test
user with -u/-g, so its control socket, pidfile and MRT dumps belong to the test user.
Unix sockets are not namespaced: the tests talk to every control socket from the host.
"""

import grp
import ipaddress
import os
import pwd
import re
import socket
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import netns

# Peer 0 of every PEER_INDEX_TABLE stands in for non-BGP routes. BIRD writes it with
# IPA_NONE, the IPv6 zero address in BIRD 2: (peer type, BGP ID, IP, AS) is below.
MRT_FAKE_PEER = (3, ipaddress.IPv4Address("0.0.0.0"), ipaddress.IPv6Address("::"), 0)


class BirdError(RuntimeError):
    pass


def wait_until(predicate: Callable[[], object], timeout: float, what: str,
               interval: float = 0.2, diagnostics: Callable[[], str] = lambda: ""):
    """Poll until predicate() is truthy and return its value; fail with `what` on timeout."""
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value:
            return value
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out after {timeout}s waiting for {what}{diagnostics()}")
        time.sleep(interval)


class BirdCtl:
    """
    Client for BIRD's control socket. Reply lines are `NNNN-text` (more follows),
    ` text` (continues the previous code), `+text` (asynchronous) or `NNNN text` (last).
    Codes 8xxx and 9xxx are errors.
    """

    def __init__(self, path: Path, timeout: float = 60.0):
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(str(path))
        self.buf = b""
        code, _ = self._read_reply()
        if code != 1:
            raise BirdError(f"unexpected greeting from {path}: code {code}")

    def close(self) -> None:
        self.sock.close()

    def _read_line(self) -> str:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise BirdError(f"control socket {self.path} closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode(errors="replace")

    def _read_reply(self) -> Tuple[int, List[str]]:
        lines = []
        while True:
            line = self._read_line()
            if line.startswith("+"):
                continue
            if len(line) >= 5 and line[:4].isdigit() and line[4] in " -":
                lines.append(line[5:])
                if line[4] == " ":
                    return int(line[:4]), lines
            else:
                lines.append(line[1:] if line.startswith(" ") else line)

    def cmd(self, command: str, check: bool = True) -> List[str]:
        """Run one CLI command and return the reply lines."""
        self.sock.sendall(command.encode() + b"\n")
        code, lines = self._read_reply()
        if check and code >= 8000:
            raise BirdError(f"{command!r} failed ({code}): {' / '.join(lines)}")
        return lines


class Bird:
    """One BIRD daemon, optionally inside a namespace, with its files in `workdir`."""

    def __init__(self, name: str, binary: Path, workdir: Path, ns: netns.Namespace):
        self.name = name
        self.binary = Path(binary)
        self.ns = ns
        self.workdir = workdir
        self.conf = workdir / "bird.conf"
        self.ctl_path = workdir / "bird.ctl"
        self.pidfile = workdir / "bird.pid"
        self.log = workdir / "bird.log"
        self.pid: Optional[int] = None
        self._ctl: Optional[BirdCtl] = None

    def start(self, config: str, timeout: float = 10.0) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.conf.write_text(config)
        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        argv = [str(self.binary), "-c", str(self.conf), "-s", str(self.ctl_path),
                "-P", str(self.pidfile), "-u", user, "-g", group]
        proc = netns.sudo("ip", "netns", "exec", self.ns.name, *argv, check=False)
        if proc.returncode != 0:
            raise BirdError(f"{self.name}: bird failed to start: {proc.stderr.strip()}")
        # bird daemonizes; the child writes the pidfile and serves the socket.
        wait_until(lambda: self.pidfile.exists() and self.pidfile.read_text().strip(),
                   timeout, f"{self.name} pidfile", diagnostics=self.log_tail)
        self.pid = int(self.pidfile.read_text().split()[0])
        self._ctl = wait_until(self._try_connect, timeout, f"{self.name} control socket",
                               diagnostics=self.log_tail)

    def _try_connect(self) -> Optional[BirdCtl]:
        try:
            return BirdCtl(self.ctl_path)
        except OSError:
            return None

    @property
    def ctl(self) -> BirdCtl:
        if not self._ctl:
            raise BirdError(f"{self.name} is not running")
        return self._ctl

    def cmd(self, command: str, check: bool = True) -> List[str]:
        return self.ctl.cmd(command, check=check)

    def running(self) -> bool:
        return self.pid is not None and Path(f"/proc/{self.pid}").exists()

    def stop(self, timeout: float = 10.0) -> None:
        if self._ctl:
            try:
                self._ctl.cmd("down", check=False)
            except (OSError, BirdError):
                pass
            self._ctl.close()
            self._ctl = None
        if self.pid is None:
            return
        try:
            wait_until(lambda: not self.running(), timeout, f"{self.name} to exit")
        except AssertionError:
            netns.sudo("kill", "-KILL", str(self.pid), check=False)
        self.pid = None

    def log_tail(self, lines: int = 30) -> str:
        try:
            text = self.log.read_text(errors="replace").splitlines()[-lines:]
        except OSError:
            return ""
        return f"\n--- last {len(text)} lines of {self.log} ---\n" + "\n".join(text)

    # -- queries ---------------------------------------------------------------

    def protocols(self) -> Dict[str, List[str]]:
        """`show protocols` as name -> [proto, table, state, since, info...]."""
        out = {}
        for line in self.cmd("show protocols"):
            fields = line.split()
            if len(fields) >= 5 and fields[0] != "Name":
                out[fields[0]] = fields[1:]
        return out

    def protocol_state(self, proto: str) -> str:
        """The Info column of `show protocols <proto>`, e.g. 'Established'."""
        for line in self.cmd(f"show protocols {proto}"):
            fields = line.split()
            if fields and fields[0] == proto:
                return " ".join(fields[5:])
        raise BirdError(f"{self.name}: no protocol {proto}")

    def wait_established(self, proto: str, timeout: float = 30.0) -> None:
        wait_until(lambda: self.protocol_state(proto).startswith("Established"), timeout,
                   f"{self.name}: {proto} to reach Established", diagnostics=self.log_tail)

    def route_count(self, table: str) -> int:
        """Number of routes in `table` (`show route table <t> count`)."""
        for line in self.cmd(f"show route table {table} count"):
            m = re.match(r"(\d+) of \d+ routes", line)
            if m:
                return int(m.group(1))
        raise BirdError(f"{self.name}: cannot count routes in {table}")

    def route_attributes(self, table: str) -> Dict[str, Dict[str, str]]:
        """
        `show route table <t> all` as net -> {attribute: value}, e.g. 'BGP.next_hop'.
        VPN nets are keyed '<rd> <prefix>'. Attribute lines start with a tab; lines
        starting with spaces are further routes for the same net and are skipped.
        """
        out: Dict[str, Dict[str, str]] = {}
        current = None
        for line in self.cmd(f"show route table {table} all"):
            if not line.strip() or line.startswith("Table "):
                continue
            if line.startswith("\t"):
                if current and ":" in line:
                    key, value = line.strip().split(":", 1)
                    out[current][key] = value.strip()
            elif line.startswith(" "):
                current = None
            else:
                f = line.split()
                current = f[0] if "/" in f[0] else f"{f[0]} {f[1]}"
                out[current] = {}
        return out

    def wait_routes(self, table: str, n: int, timeout: float = 30.0) -> None:
        wait_until(lambda: self.route_count(table) == n, timeout,
                   f"{self.name}: {n} routes in {table}", diagnostics=self.log_tail)

    def mrt_dump(self, table: str, path: Path) -> Path:
        """
        Dump `table` (a table name, or a quoted pattern like '"*"') into `path` and return
        it once the dump is complete. The fork appends to an existing file, so callers
        that want one dump per file must use a fresh path.
        """
        self.cmd(f'mrt dump table {table} to "{path}"')
        return path

    # -- periodic dumps (protocol mrt) ------------------------------------------
    #
    # These rely on `debug protocols { events }` in the config: an MRT protocol then logs
    # "<name>: RIB table dump started" and "... done" around every periodic dump.

    _DUMP_EVENT_RE = re.compile(r"<TRACE> (\S+): RIB table dump (started|done)$")

    def mrt_protocols(self) -> List[str]:
        return sorted(name for name, fields in self.protocols().items() if fields[0] == "MRT")

    def mrt_dump_events(self) -> Dict[str, Dict[str, int]]:
        """Per MRT protocol, how many periodic dumps have started and finished so far."""
        counts = {name: {"started": 0, "done": 0} for name in self.mrt_protocols()}
        for line in self.log.read_text(errors="replace").splitlines():
            m = self._DUMP_EVENT_RE.search(line)
            if m and m.group(1) in counts:
                counts[m.group(1)][m.group(2)] += 1
        return counts

    def wait_periodic_dumps(self, since: Dict[str, Dict[str, int]],
                            timeout: float = 30.0) -> Dict[str, Dict[str, int]]:
        """
        Wait until every MRT protocol has finished a dump that started after the snapshot
        `since` (from mrt_dump_events()), and return the new counts. Dumps of one protocol
        never overlap, so its dump number since[p]["started"] (0-based) is the first one
        that started after the snapshot.
        """
        def ready():
            now = self.mrt_dump_events()
            return now if all(now[p]["done"] > since[p]["started"] for p in since) else None
        return wait_until(ready, timeout, f"{self.name}: a periodic MRT dump of every table",
                          diagnostics=self.log_tail)

    def disable(self, proto: str, timeout: float = 30.0) -> None:
        """Disable `proto` and wait until it is down (an MRT dump in progress finishes first)."""
        self.cmd(f"disable {proto}")
        wait_until(lambda: self.protocols()[proto][2] == "down", timeout,
                   f"{self.name}: {proto} to go down", diagnostics=self.log_tail)


class Lab:
    """Namespaces, links and daemons for one test module, torn down by close()."""

    def __init__(self, workdir: Path, run_id: Optional[int] = None):
        self.workdir = workdir
        self.run_id = run_id if run_id is not None else os.getpid()
        self.namespaces: Dict[str, netns.Namespace] = {}
        self.birds: Dict[str, Bird] = {}
        self._links = 0

    def namespace(self, role: str) -> netns.Namespace:
        if role not in self.namespaces:
            ns = netns.Namespace(role, self.run_id)
            ns.create()
            self.namespaces[role] = ns
        return self.namespaces[role]

    def link(self, a: str, b: str) -> netns.Link:
        self._links += 1
        link = netns.Link(self.namespace(a), self.namespace(b), self._links)
        link.create()
        return link

    def log_path(self, role: str) -> Path:
        """Where the daemon for `role` logs; configs pass it to prolog()."""
        return self.workdir / role / "bird.log"

    def bird(self, role: str, config: str, binary: Path) -> Bird:
        bird = Bird(role, binary, self.workdir / role, self.namespace(role))
        self.birds[role] = bird
        bird.start(config)
        return bird

    def close(self) -> None:
        for bird in self.birds.values():
            bird.stop()
        for ns in self.namespaces.values():
            ns.delete()
        self.birds.clear()
        self.namespaces.clear()


def prolog(router_id: str, log: Path, debug: bool = False) -> str:
    """Config lines every lab daemon starts with."""
    lines = [f'log "{log}" all;', f"router id {router_id};"]
    if debug:
        lines.append("debug protocols all;")
    lines.append("protocol device { scan time 10; }")
    return "\n".join(lines) + "\n"
