# BIRD MRT dump regression tests — plan

**Goal:** a regression suite for the MRT TABLE_DUMP_V2 files this BIRD fork writes for
analytics. Every BGP path attribute in a dump must be byte-correct, value *and* flags,
and so must the fork-specific parts: VPN `RIB_GENERIC` records, the MP_REACH next hop, and
how dumps are written to disk.

## Status: design only, nothing built

Branch `2.0.4-mrt-dump-tests` (off `2.0.4`). An earlier container-based version of this
suite (`compile-stack/`, 31 tests) is not available. Its design and findings are carried
over below; its code is not, and the suite is rebuilt here to the decisions that follow.

## Decisions (2026-09-28)

| topic | decision |
|---|---|
| location | self-contained `tools/df/test/mrt/`; all our test code lives under `tools/df/test/` |
| runner | native pytest, no Docker for now (a CI image can come later, in this directory) |
| dependencies | helpers are stdlib-only; pytest is the only third-party package |
| isolation | root network namespaces, one per daemon, joined by veth pairs; needs passwordless sudo |
| peers | BIRD2 announcers, no gobgp: this is a regression suite for BIRD's dump, not an interop test |
| peer binary | same as the binary under test by default; `PEER_BIRD=` overrides it with a known-good build |
| dumps | forced with `mrt dump table <t> to "<f>"`; tests never wait for `period` |
| configs | minimal, purpose-built, rendered by `birdlab.py` (the real `deepy.bird.config` renderer is phase A) |
| consumer check | every dump is also run through `bgpdump -m` and the fields analytics reads are asserted; skipped if bgpdump is missing, `BGPDUMP=` overrides the path |
| known bugs | findings 4, 12, 13, 14: the test asserts the correct behaviour and is marked `xfail(strict=True)` citing the finding, so a fix flips it and forces the marker off; other findings are pinned as current behaviour |

Why the peer binary is configurable: when the peers run the binary under test, one change
can break BGP encode and decode in matching ways, and the dump still looks right. Pointing
`PEER_BIRD` at a known-good build (on the dev box: `/pipedream/local/venv/bird2/sbin/bird`,
2.0.4.12.df) rules that out.

The consumer check uses the product's own parser: on the dev box `/usr/local/sbin/bgpdump`
is bgpdump 1.4.99.14 from the `deepfield-pipedream` package, built with RIB_GENERIC support.
The byte-level reader says what BIRD wrote; bgpdump says what analytics will see.

## Layout

```
tools/df/test/mrt/
  PLAN.md                  this file
  README.md                build bird, run the suite
  conftest.py              locate $BIRD / $PEER_BIRD, sudo check (skip if missing), fixtures
  netns.py                 create/tear down namespaces and veth links, stale-run cleanup
  birdlab.py               start/stop bird in a namespace, control-socket client, config renderers
  mrt_reader.py            strict RFC 6396 TABLE_DUMP_V2 reader, unknown attributes kept raw
  bgpdump.py               run `bgpdump -m`, split its pipe-separated fields
  test_mrt_reader.py       reader unit tests against hand-built bytes (no bird)
  test_production_path.py  eBGP → bgp_session table → pipe → merged table → dump
  test_attributes.py       tier 1: filter-set attributes, no peer
  test_attributes_bgp.py   tier 2: attributes received over BGP
  test_record_types.py     VPN RIB_GENERIC, prefix encodings
  test_dump_mechanics.py   >2048 routes, append mode, table selection, stale next hop
```

## Harness

### Network namespaces

```
 [mrt-<pid>-peer_e]              [mrt-<pid>-dut]                  [mrt-<pid>-peer_i]
 BIRD announcer, AS 65001        BIRD under test, AS 65000        BIRD announcer, AS 65000
 10.99.1.2  fd99:1::2  ──veth──  10.99.1.1 | 10.99.2.1  ──veth──  10.99.2.2  fd99:2::2
                                 fd99:1::1 | fd99:2::1
                                 writes the MRT dumps
```

- Tier 1 brings up `dut` only; tier 2 adds the peers.
- Sessions are directly connected, not `multihop` over loopback. That is the shape of a
  real collection session, and on a direct IPv6 link BIRD sends global + link-local next
  hops, which exercises the 32-byte next hop handling in `mrt.c:597-606`.
- IPv6 DAD is disabled inside the namespaces so addresses are usable immediately.
- Namespaces are named `mrt-<pid>-<role>`, created by a session fixture and deleted at
  teardown. At startup, leftover `mrt-*` namespaces whose `<pid>` is dead are removed.
- Unprivileged user namespaces are blocked on the dev box
  (`kernel.apparmor_restrict_unprivileged_userns = 1`), hence sudo.

### Processes

- Start: `sudo ip netns exec <ns> $BIRD -c <tmp>/bird.conf -s <tmp>/ctl -P <tmp>/pid -u $USER`.
  `-u` drops root after startup (as production does with `-u dfdaemon`), so the control
  socket and the dumps are owned by the test user.
- Unix sockets are not namespaced: pytest talks to each control socket directly from the
  host and reads dumps from `tmp_path`.
- Readiness is polled (`show protocols` until `Established`, `show route count` until the
  expected number), never slept for.
- Stop through the daemon's own pidfile or control socket. **Never kill by process name,
  never use the host namespace's port 179, never touch `/var/run/bird.ctl`**: the
  production BIRD runs on the dev box.

## Test design: two tiers, because one cannot cover flags

**Tier 1: filter-set attributes, no peer** (`test_attributes.py`). Each prefix is a
blackhole static route whose attributes are set by its own import filter, one attribute
per prefix. A failure therefore points at BIRD's MRT encoder (`proto/mrt/mrt.c` →
`bgp_encode_attrs`) and nothing else: no session, no filters in the way, no peer
behaviour to explain away. One daemon and one forced dump serve the whole module.

**Tier 2: attributes off the wire** (`test_attributes_bgp.py`). A BIRD announcer
originates static routes and sets attributes in its export filter; the DUT decodes,
stores and re-encodes them. This is the only tier that can assert the *received*
attribute flags. It cross-checks the RIB dump against the DUT's BGP4MP capture
(`mrtdump "<file>"; mrtdump protocols all;`) of the UPDATE that carried the route.
Two sessions, because LOCAL_PREF survives only from an internal peer:

| session | AS | DUT side | why |
|---|---|---|---|
| `peer_e` | 65001 | 10.99.1.1 / fd99:1::1 | eBGP, the shape of an analytics collection session |
| `peer_i` | 65000 | 10.99.2.1 / fd99:2::1 | iBGP, the only way a received LOCAL_PREF is kept |

## Findings carried over

Reproduced in the earlier container build (2.0.4-12.df-x) unless marked. **Each is
re-verified once this harness runs**, then pinned by a test.

1. **`mrt dump table … to …` needs no `protocol mrt` instance.** The CLI command is
   registered by the module (`proto/mrt/config.Y:53`); `mrt_dump_cmd` only wants a table
   and a filename.
2. **The RIB-dump MP_REACH_NLRI is truncated.** RFC 6396 4.3.4 keeps only the next hop
   length and address (no AFI/SAFI, no NLRI), and `mrt.c:588-617` writes exactly that
   (`flags, 14, len=17, 16, <16 bytes>`). The reader must decode RIB next hops with the
   table-dump layout, not the wire layout (the old reader returned `None` for every IPv6
   route until `attr_next_hop`/`parse_mp_reach` took `table_dump=`).
3. **IPv4 RIB entries use the legacy NEXT_HOP attribute**, because `mrt.c` sets
   `bws->mp_reach = !s->ipv4`.
4. **An IPv6 next hop on an IPv4 route dumps with no next hop at all**: not as MP_REACH,
   not as attribute 3. `bgp_encode_next_hop` (`proto/bgp/attrs.c:291`) drops it ("FIXME:
   skip IPv6 next hops for IPv4 routes during MRT dump"). Production enables
   `extended next hop on` for ipv4, so these routes reach analytics without a next hop.
   **Test: `xfail(strict=True)`.**
5. **Attribute flags differ by provenance**, and the dump shows it:
   - filter-set attributes → all flags `0x00` (the eattr has none to write back);
   - received transitive attributes → flags preserved (`0x40`, `0x80`, `0xc0`);
   - NEXT_HOP → `0x40` on the wire, `0x00` in the RIB dump;
   - LOCAL_PREF → `0x40` when received from an iBGP peer, `0x00` when BIRD generated the
     default 100 for an eBGP route. The flags are what tell the two apart in a dump.
6. **`mrtdump protocols all;` alone writes nowhere.** The output file comes from a
   separate `mrtdump "<file>";` (`sysdep/unix/config.Y:89`). The production prolog
   (`lib/deepy/bird/config.py:95`) and template (`:115`) set the mask and never the file,
   so no BGP4MP dump is produced in production today.
7. **`mrtdump` captures received messages only**: `bgp_dump_message` is called from
   `bgp_rx_packet` (`proto/bgp/packets.c:2988`) and nowhere else. Asserting on bytes BIRD
   *emits* means reading the peer's capture.
8. **Loopback peers need `multihop;`** or BIRD refuses the session with "Invalid next
   hop". Moot with directly connected veth sessions; kept for anyone running peers on
   loopback.
9. **`bgp_origin = 0;` is rejected** ("Setting int attribute to non-int value"); the
   filter language wants the `ORIGIN_IGP` / `ORIGIN_EGP` / `ORIGIN_INCOMPLETE` enum.
10. *(source-read)* **Flowspec routes are never dumped.** `mrt_rib_table_dump` switches on
    `NET_IP4/IP6/VPN4/VPN6` and returns for anything else, so `flow4`/`flow6` tables
    produce empty dumps.

## New from source reading (2026-09-28, all unverified)

11. **VPN RIB_GENERIC encoding is fork code with no tests** (`mrt.c:446-529`). AFI 1/2,
    SAFI 128; a fake label `0x000001` (label 0, bottom of stack); an 8-byte RD written as
    raw host memory, with the IP part of type-1 RDs byte-swapped for libbgpdump
    (`mrt_make_rd_u64`, `mrt.c:376-414`); prefix length includes the 88 label + RD bits.
    The old sanity harness expected, via `bgpdump -m`, vpn4 `8.8.8.0/24` rd `100:100` →
    `8.8.8.0/112`, next hop `::ffff:172.22.0.0`. Production has `mastervpn4`/`mastervpn6`.
12. **A wildcard table pattern skips VPN tables.** `mrt_next_table_` accepts only
    `NET_IP4`/`NET_IP6` tables when matching a pattern (`mrt.c:230-232`); a VPN table is
    dumped only when named explicitly. **Test: `xfail(strict=True)`.**
13. **Suspected stale MP next hop.** `bgp_encode_next_hop` stores the next hop in
    `bws->mp_next_hop` (`attrs.c:306`) and nothing resets it between routes; one `bws`
    serves a whole dump step (`mrt.c:736`). An IPv6 entry that has attributes but no
    NEXT_HOP would get the previous route's next hop. **Test: `xfail(strict=True)`.**
14. **VPN + ADD-PATH writes an unparseable record.** The subtype is always `RIB_GENERIC`,
    never `RIB_GENERIC_ADDPATH` (`mrt.c:640-643`), but the 4-byte path ID is still written
    when `add_path` is set (`mrt.c:564-565`). **Test: `xfail(strict=True)`.**
15. **Dumps of more than 2048 routes pause and resume** (`s->max`, `mrt.c:738`). The fork
    patched the resume path to re-set `mp_reach` (`mrt.c:741-744`); nothing guards it.
    Needs a table of more than 2048 IPv6 routes.
16. **The filename is literal and opened for append** (`mrt.c:263-264`); upstream's
    `%N`/strftime expansion was removed. Repeated dumps, and multi-table patterns, append
    to one file, each section with its own PEER_INDEX_TABLE and a sequence number
    restarting at 0. The `strcpy` into a `PATH_MAX` buffer is unbounded.
17. **Production dumps pipe-fed tables.** The `merged_session_*` tables are filled by
    `analytics_mrt_session_*` pipes. The peer index is looked up from the route's source
    protocol (`mrt.c:549-555`), so it should still resolve to the BGP peer, not to
    peer 0. Pin it.
18. **MP_REACH flags in the RIB dump are copied from the NEXT_HOP eattr** (`mrt.c:608`),
    not set to the RFC's optional `0x80`. If `mp_next_hop` were neither 16 nor 32 bytes,
    `alen += 1 + lh` (`mrt.c:616`) would still count one unwritten byte (probably
    unreachable: BIRD stores next hops as `ip_addr`).

## Coverage (planned)

| attribute | code | tier 1 | tier 2 | notes |
|---|---|---|---|---|
| ORIGIN | 1 | all three values | ✓ | |
| AS_PATH | 2 | order, 32-bit ASN, single AS_SEQUENCE, exact length | ✓ | 4-byte ASNs always |
| NEXT_HOP | 3 | v4 legacy; v6-on-v4 dropped (4) | value + flag loss (5) | |
| MED | 4 | full 32-bit range | ✓ | |
| LOCAL_PREF | 5 | ✓ | iBGP kept / eBGP defaulted | |
| COMMUNITY | 8 | + extended-length flag at 70 communities | ✓ | |
| ORIGINATOR_ID / CLUSTER_LIST | 9 / 10 | ✓ | — | |
| MP_REACH_NLRI | 14 | truncated form (2), stale next hop (13) | 16- and 32-byte next hops | |
| EXT_COMMUNITY | 16 | rt + ro | ✓ | |
| IPV6_EXT_COMMUNITY | 25 | v4 and v6 routes, byte-exact | ✓ BIRD announcer | DEFBE-9172; redirect subtype `0x0c` |
| LARGE_COMMUNITY | 32 | incl. 32-bit fields | ✓ | |
| prefix encoding | — | default route, /32, /128 | ✓ | |
| VPN RIB_GENERIC | — | static vpn4/vpn6 routes | vpn4/vpn6 mpls sessions | (11), (14) |

### Known gaps

- **ATOMIC_AGGREGATE (6) and AGGREGATOR (7)**: no way to set either. `bgp_aggregator` is
  declared `EAF_TYPE_INT` in 2.0.4 (`proto/bgp/config.Y:288`), which cannot hold the
  8-byte value, and a BIRD announcer has the same limitation. Uncovered.
- **AS4_PATH (17)**: an announcer with `enable as4 off` sends one, but the DUT merges it
  into AS_PATH on receipt, so a dump should never contain it. Assert that, nothing more.
- **AS_SET segments**: no way to build one in 2.0.4 filters. Uncovered.
- **Unknown attribute codes**: the reader keeps them raw, but BIRD cannot originate one.
  Uncovered.

## Phases

Agreed 2026-09-28.

0. **Build.** Install `bison`, `flex`, `libreadline-dev` on the dev box; build BIRD in the
   tree (`-fcommon` with modern GCC, as `test_draft00/build.sh` does).
1. **Harness.** `netns.py`, `birdlab.py`, `mrt_reader.py` + `test_mrt_reader.py`,
   `bgpdump.py`.
2. **Production path.** A BIRD peer announces over eBGP into a `bgp_session` table, a
   pipe copies it into a `merged` table, and that table is dumped. Asserts peer index,
   prefix, next hop, AS path and communities, in the reader and in `bgpdump -m`.
   Finding 17. If the suite had one test, it would be this one.
3. **Tier 1 attributes.** Findings 2–5, 18.
4. **VPN RIB_GENERIC.** Findings 11, 12, 14.
5. **Tier 2 attributes over BGP**, flags and the BGP4MP cross-check.
6. **Dump mechanics and edge cases.** Findings 13, 15, 16.
7. **Later phases** (unchanged in intent):
   - **A. Table topology / isolation.** Route injected by peer A lands in A's table and
     only A's; each protocol (`ipv4`/`ipv6`/`vpn4`/`vpn6`/`ipv4-mpls`/`ipv6-mpls`) dumps to
     its own file with the right AFI/SAFI; neighbor add/remove and reconfigure cross-wire
     nothing. Wants the real `deepy.bird.config` renderer (mount `pipedream/lib`, stub
     `deepy.bgp`, accept the drift risk).
   - **C. Mitigation ↔ analytics coexistence.** With `mitigations/mit-<ns>-*.conf`
     includes present and announcing, analytics dumps stay byte-identical to the
     no-mitigation baseline. Flowspec redirect UPDATE bytes read from the *peer's*
     capture (fact 7).
   - **D. Analytics chain.** Feed a produced MRT into `bgp build` → `bgp.h5` and assert
     the routes surface, reusing `fi_tests/bgp/test_bgp_h5.py`'s helper.

## Open questions

- Jira ticket? (branch is `2.0.4-mrt-dump-tests` until there is one)
- Fixing findings 4, 12, 13, 14: in this branch, or separate tickets?
- Findings 16 and 18 are pinned as current behaviour: are either of them bugs?
- Inert `mrtdump protocols all;` in the production config: separate ticket?
- Promote into `fi_tests` (real renderer, CI) or keep it here?
