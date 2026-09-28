# MRT dump regression tests

pytest suite for the MRT TABLE_DUMP_V2 files BIRD writes for analytics. Design, findings
and phases are in [PLAN.md](PLAN.md).

## Setup (once per box)

```
tools/df/test/mrt/install_prereq.sh   # bison, flex, libreadline-dev, ... (apt, sudo)
tools/df/test/mrt/build_bird.sh       # builds ./bird in the repo root, production flags
```

## Run

```
cd tools/df/test/mrt
python3 -m pytest -q                  # whole suite, a few seconds
python3 -m pytest -q test_mrt_reader.py test_bgpdump.py   # no sudo, no bird
```

| variable | default | |
|---|---|---|
| `BIRD` | `<repo>/bird` | binary under test |
| `PEER_BIRD` | `$BIRD` | binary for the announcing peers, e.g. a known-good release |
| `BGPDUMP` | `bgpdump` on `PATH` | the product's bgpdump (`deepfield-pipedream` package) |

Tests that run BIRD need passwordless sudo, for the network namespaces; they skip
without it, as the bgpdump checks do without bgpdump.

## Isolation

Every daemon runs in its own network namespace (`mrt-<pid>-<role>`), joined to others by
veth pairs; nothing binds in the host namespace. BIRD starts as root inside the namespace
and drops to the test user (`-u`/`-g`), so its control socket, log and dumps land in
pytest's `tmp_path`, owned by you. Teardown stops each daemon through its own pidfile and
deletes the namespaces; namespaces left by a crashed run are removed at the next start.

The production BIRD may run on the same box. The harness never kills by process name and
never uses its control socket or the host's port 179.
