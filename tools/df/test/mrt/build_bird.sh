#!/bin/bash
# Build the BIRD under test in the repo root, configured like the production package
# (tools/df/build/configure-prod.sh). Configures only when there is no Makefile yet;
# run `make distclean` in the repo root to reconfigure. Run install_prereq.sh first.
set -euo pipefail

TESTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$TESTDIR/../../../.." && pwd)"
cd "$REPO"

CFLAGS_BUILD="-g -O2 -pthread -fcommon" # -fcommon: build this BIRD with modern GCC
JOBS="$(nproc 2>/dev/null || echo 2)"

if [ ! -f Makefile ]; then
  [ -x ./configure ] || autoreconf -i
  ./configure --enable-client --enable-pthreads --enable-memcheck \
      "--with-protocols=bfd babel bgp mrt ospf perf pipe radv rip static" \
      --with-iproutedir=/etc/iproute2 CFLAGS="$CFLAGS_BUILD"
fi

make -j"$JOBS"

echo
"$REPO/bird" --version
echo "built $REPO/bird (the suite's default \$BIRD)"
