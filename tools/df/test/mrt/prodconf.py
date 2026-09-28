"""
DUT configs as pipedream renders them for analytics collection sessions, with lab
addresses. Mirrors, as of pipedream 3f90b1e3f09 (2026-09-28):

  lib/deepy/bird/config.py               the bgp_peer template (:113), the family ->
                                         table / channel maps (:13), make_table_name (:56)
  lib/deepy/bird/manager/bird_conf_renderer.py
                                         _render_analytics_block (sessions, merged tables,
                                         pipes) and _render_analytics_mrt (protocol mrt)

Two session shapes: an analytics session binds bgp_session_<ip>_<family> directly; a
merged session (analytics + mitigation announcer on one peer) binds
merged_session_<ip>_<afi> for ipv4/ipv6, fed with the device's mitigation statics by a
mit_bridge pipe, and an analytics_mrt pipe copies only RTS_BGP routes on to the dumped
table. Other families (vpn4, vpn6, ...) bind the dumped table directly either way.

The only lines the renderer does not produce are the log file and
`debug protocols { events }`, which lets tests see when a periodic dump is complete.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

LOCAL_AS = 2500
DEVICE_ID = 56000

FAMILY_TO_TABLE_TYPE = {"ipv4": "ipv4", "ipv6": "ipv6", "vpn4": "vpn4", "vpn6": "vpn6",
                        "ipv4-mpls": "ipv4", "ipv6-mpls": "ipv6"}
FAMILY_TO_CHANNEL_TYPE = {"ipv4": "ipv4", "ipv6": "ipv6", "vpn4": "vpn4 mpls",
                          "vpn6": "vpn6 mpls", "ipv4-mpls": "ipv4 mpls", "ipv6-mpls": "ipv6 mpls"}
UNICAST = ("ipv4", "ipv6")

BGP_PEER_TEMPLATE = """
template bgp bgp_peer {
    debug all;
    mrtdump all;
    local as myas;
    ipv4 { import all; extended next hop on; export none; };
    ipv6 { import all; extended next hop on; export none; };
    vpn4 mpls { import all; export none; extended next hop on; table mastervpn4; };
    vpn6 mpls { import all; export none; extended next hop on; table mastervpn6; };
    ipv4 mpls { import all; export none; extended next hop on; table masteripv4mpls; };
    ipv6 mpls { import all; export none; extended next hop on; table masteripv6mpls; };
    multihop;
    graceful restart on;
    long lived graceful restart on;
    enable as4 on;
    enable extended messages off;
    capabilities on;
    interpret communities off;
    deterministic med on;
}
"""


@dataclass
class Session:
    remote_ip: object
    source_ip: object
    remote_as: int
    families: List[str] = field(default_factory=lambda: list(UNICAST))
    merged: bool = False


def session_name(remote_ip) -> str:
    return "session_" + str(remote_ip).replace(".", "_").replace(":", "_")


def analytics_table(remote_ip, family) -> str:
    return f"bgp_{session_name(remote_ip)}_{family.replace('-', '')}"


def merged_table(remote_ip, family) -> str:
    return f"merged_{session_name(remote_ip)}_{family.replace('-', '')}"


def dump_file(dumpdir: Path, remote_as, remote_ip, family) -> Path:
    return Path(dumpdir) / f"local_bgpdump.{remote_as}.{remote_ip}.{family}.mrt"


def render_dut(log, dumpdir, sessions: List[Session], mrt_period: int,
               mitigations: Optional[Dict[str, str]] = None) -> str:
    """`mitigations`: afi -> prefix of a static in dev_<afi>_<DEVICE_ID>, bridged into
    every merged session."""
    out = [f'log "{log}" all;\ndebug protocols {{ events }};\n',
           "router id 0.0.0.1;\ndefine myas = 0;\n\n"
           "vpn4 table mastervpn4;\nvpn6 table mastervpn6;\n"
           "ipv4 table masteripv4mpls;\nipv6 table masteripv6mpls;\n",
           BGP_PEER_TEMPLATE]
    for family in ("ipv4", "ipv6", "flow4", "flow6"):
        out.append(f"{family} table dev_{family}_{DEVICE_ID};\n")
    for afi, prefix in (mitigations or {}).items():
        out.append(f"protocol static mit_{DEVICE_ID}_{afi} {{\n"
                   f"    {afi} {{ table dev_{afi}_{DEVICE_ID}; }};\n"
                   f"    route {prefix} blackhole;\n}}\n")

    for s in sessions:
        name = session_name(s.remote_ip)
        merged = [f for f in s.families if f in UNICAST] if s.merged else []
        out.append("\n")
        for family in s.families:
            out.append(f"{FAMILY_TO_TABLE_TYPE[family]} table {analytics_table(s.remote_ip, family)};\n")
        for family in merged:
            out.append(f"{FAMILY_TO_TABLE_TYPE[family]} table {merged_table(s.remote_ip, family)};\n")
        out.append(f"\nprotocol bgp {name} from bgp_peer {{\n"
                   f"    neighbor {s.remote_ip} as {s.remote_as};\n")
        for family in s.families:
            channel = FAMILY_TO_CHANNEL_TYPE[family]
            if family in merged:
                out.append(f"    {channel} {{ table {merged_table(s.remote_ip, family)}; "
                           f"export where source = RTS_STATIC; next hop keep on; }};\n")
            else:
                out.append(f"    {channel} {{ table {analytics_table(s.remote_ip, family)}; }};\n")
        if s.merged:
            for family in ("flow4", "flow6"):
                out.append(f"    {family}  {{ table dev_{family}_{DEVICE_ID}; "
                           f"import none; export all; extended next hop; }};\n")
        out.append(f"    source address {s.source_ip};\n"
                   f"    local as {LOCAL_AS};\n"
                   f"    allow local as {LOCAL_AS};\n}}\n")
        for family in merged:
            out.append(f"\nprotocol pipe mit_bridge_{DEVICE_ID}_{family} {{\n"
                       f"    table dev_{family}_{DEVICE_ID};\n"
                       f"    peer table {merged_table(s.remote_ip, family)};\n"
                       f"    import none;\n    export all;\n}}\n"
                       f"protocol pipe analytics_mrt_{name}_{family} {{\n"
                       f"    table {merged_table(s.remote_ip, family)};\n"
                       f"    peer table {analytics_table(s.remote_ip, family)};\n"
                       f"    import none;\n    export where source = RTS_BGP;\n}}\n")

    for s in sessions:
        for family in s.families:
            out.append(f"\nprotocol mrt {{\n"
                       f"    table {analytics_table(s.remote_ip, family)};\n"
                       f'    filename "{dump_file(dumpdir, s.remote_as, s.remote_ip, family)}";\n'
                       f"    period {mrt_period};\n}}\n")
    return "".join(out)
