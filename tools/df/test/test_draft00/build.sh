#!/bin/bash
# Build the two bird binaries for the DRAFT00 flowspec next-hop A/B test:
#   bird_patched - the current tree (DRAFT00 flow next-hop patch)
#   bird_stock   - proto/bgp/packets.c reverted to BASE_TAG (unpatched baseline)
# Both are written to the repo root. Run run.sh afterwards to capture/compare.
set -e

TESTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$TESTDIR/../../../.." && pwd)"
cd "$REPO"

BASE_TAG="${BASE_TAG:-2.0.4-11.df}"     # deployed .df version this patch targets
PATCH_FILE="proto/bgp/packets.c"        # the only file the patch touches
CFLAGS_BUILD="-g -O2 -pthread -fcommon" # -fcommon: build this BIRD with modern GCC
JOBS="$(nproc 2>/dev/null || echo 2)"

if [ ! -f Makefile ]; then
  [ -x ./configure ] || autoreconf -i
  ./configure --disable-client CFLAGS="$CFLAGS_BUILD"
fi

echo "== building PATCHED (current tree) =="
make -j"$JOBS"
cp -f bird bird_patched

echo "== building STOCK ($BASE_TAG:$PATCH_FILE) =="
git checkout "$BASE_TAG" -- "$PATCH_FILE"
make -j"$JOBS"
cp -f bird bird_stock

echo "== restoring patched $PATCH_FILE =="
git checkout HEAD -- "$PATCH_FILE"
cp -f bird_patched bird

cat <<EOF

Built:
  $REPO/bird_patched
  $REPO/bird_stock

Run the A/B capture (needs sudo + the nsa/nsb netns from the test README):
  BIRD=$REPO/bird_stock   PCAP=$TESTDIR/capture_stock.pcap   $TESTDIR/run.sh
  BIRD=$REPO/bird_patched PCAP=$TESTDIR/capture_patched.pcap $TESTDIR/run.sh
EOF
