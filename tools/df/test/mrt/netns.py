"""
Network namespaces for the MRT test lab.

Every daemon gets its own namespace, named mrt-<pid>-<role>, and namespaces are joined
by veth pairs created directly inside them, so nothing is added to the host namespace.
All of this needs root; commands go through `sudo -n`.

Safety: the production BIRD runs on the dev box. Nothing here kills by process name.
Processes are only ever killed because they live inside one of our namespaces
(`ip netns pids`).
"""

import ipaddress
import os
import re
import subprocess
from typing import Dict, List, Optional

PREFIX = "mrt-"
_NAME_RE = re.compile(r"^mrt-(\d+)-[\w]+$")


class NetnsError(RuntimeError):
    pass


def sudo(*cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    proc = subprocess.run(["sudo", "-n", *cmd], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise NetnsError(f"{' '.join(cmd)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc


def available() -> Optional[str]:
    """None if namespaces can be used here, otherwise the reason they cannot."""
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        return "passwordless sudo is not available"
    if sudo("ip", "netns", "list", check=False).returncode != 0:
        return "`ip netns` does not work"
    return None


def list_namespaces() -> List[str]:
    out = sudo("ip", "netns", "list").stdout
    return [line.split()[0] for line in out.splitlines() if line.strip()]


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _kill_members(name: str) -> None:
    """Kill whatever still runs inside namespace `name`, and only that."""
    pids = sudo("ip", "netns", "pids", name, check=False).stdout.split()
    if pids:
        sudo("kill", "-KILL", *pids, check=False)


def delete(name: str) -> None:
    if not name.startswith(PREFIX):
        raise NetnsError(f"refusing to delete namespace {name!r}: not ours")
    _kill_members(name)
    sudo("ip", "netns", "del", name, check=False)


def cleanup_stale() -> List[str]:
    """Delete mrt-<pid>-* namespaces left behind by test runs that are no longer alive."""
    removed = []
    for name in list_namespaces():
        m = _NAME_RE.match(name)
        if m and not _pid_alive(int(m.group(1))):
            delete(name)
            removed.append(name)
    return removed


class Namespace:
    def __init__(self, role: str, run_id: int):
        self.role = role
        self.name = f"{PREFIX}{run_id}-{role}"
        self.links: Dict[str, "Link"] = {}   # peer role -> link

    def create(self) -> None:
        sudo("ip", "netns", "add", self.name)
        # Addresses must be usable at once, link-local ones included: no DAD.
        self.exec("sysctl", "-q", "-w",
                  "net.ipv6.conf.all.accept_dad=0",
                  "net.ipv6.conf.default.accept_dad=0")
        self.ip("link", "set", "lo", "up")

    def delete(self) -> None:
        delete(self.name)

    def exec(self, *cmd: str, check: bool = True) -> subprocess.CompletedProcess:
        return sudo("ip", "netns", "exec", self.name, *cmd, check=check)

    def ip(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return sudo("ip", "-n", self.name, *args, check=check)

    def exec_prefix(self) -> List[str]:
        """argv prefix that runs a command inside this namespace (as root)."""
        return ["sudo", "-n", "ip", "netns", "exec", self.name]

    def __repr__(self) -> str:
        return f"Namespace({self.name})"


class Link:
    """
    A veth pair between namespaces `a` and `b`, one IPv4 /24 and one IPv6 /64:
    10.99.<n>.1 and fd99:<n>::1 on the a side, .2 and ::2 on the b side.
    Inside each namespace the interface is named after the other end (`to_<role>`).
    """

    def __init__(self, a: Namespace, b: Namespace, n: int):
        if not 1 <= n <= 254:
            raise NetnsError(f"link number {n} out of range")
        self.a, self.b, self.n = a, b, n
        self.ifname = {a.role: f"to_{b.role}"[:15], b.role: f"to_{a.role}"[:15]}
        self.ip4 = {a.role: ipaddress.ip_address(f"10.99.{n}.1"),
                    b.role: ipaddress.ip_address(f"10.99.{n}.2")}
        self.ip6 = {a.role: ipaddress.ip_address(f"fd99:{n:x}::1"),
                    b.role: ipaddress.ip_address(f"fd99:{n:x}::2")}

    def create(self) -> None:
        a, b = self.a, self.b
        a.ip("link", "add", self.ifname[a.role], "type", "veth",
             "peer", "name", self.ifname[b.role], "netns", b.name)
        for ns in (a, b):
            ifname = self.ifname[ns.role]
            ns.ip("addr", "add", f"{self.ip4[ns.role]}/24", "dev", ifname)
            ns.ip("-6", "addr", "add", f"{self.ip6[ns.role]}/64", "dev", ifname, "nodad")
            ns.ip("link", "set", ifname, "up")
        a.links[b.role] = self
        b.links[a.role] = self

    def peer_of(self, role: str) -> str:
        return self.b.role if role == self.a.role else self.a.role
