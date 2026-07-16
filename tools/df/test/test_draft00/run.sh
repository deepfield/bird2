#!/bin/bash
# DRAFT00 flowspec next-hop wire test. Runs two patched BIRDs in netns nsa/nsb,
# captures the BGP UPDATE on the veth, so we can inspect the MP_REACH next hop.
set +e
BIRD="${BIRD:-/home/support/bird2/bird}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR" || exit 1

# --- cleanup any prior test birds (never touch the system bird, pid 1071) ---
for pid in $(pgrep -x bird); do [ "$pid" != 1071 ] && sudo kill "$pid" 2>/dev/null; done
sleep 1
rm -f capture.pcap a.log b.log /tmp/bird_a.pid /tmp/bird_b.pid /tmp/bird_a.ctl /tmp/bird_b.ctl

# --- capture on veth-a inside nsa (packet-buffered) ---
sudo ip netns exec nsa tcpdump -i veth-a -s0 -U -w "${PCAP:-$DIR/capture.pcap}" 'tcp port 179' >/tmp/tcpdump.log 2>&1 &
TDPID=$!
sleep 1

# --- receiver B, then announcer A (daemons; pidfiles for clean shutdown) ---
sudo ip netns exec nsb "$BIRD" -c bird_b.conf -s /tmp/bird_b.ctl -P /tmp/bird_b.pid >b.log 2>&1
sleep 1
sudo ip netns exec nsa "$BIRD" -c bird_a.conf -s /tmp/bird_a.ctl -P /tmp/bird_a.pid >a.log 2>&1

# --- let the session establish + route propagate ---
sleep 12

echo "===== A: announcer protocol state ====="
sudo ip netns exec nsa "$BIRD" -s /tmp/bird_a.ctl show protocols all announcer 2>/dev/null | grep -iE "announcer|state|routes|flow"
echo "===== B: flow routes received (with attrs) ====="
sudo ip netns exec nsb "$BIRD" -s /tmp/bird_b.ctl show route table flowtab4 all 2>/dev/null | head -40

# --- stop cleanly ---
[ -f /tmp/bird_a.pid ] && sudo kill "$(sudo cat /tmp/bird_a.pid)" 2>/dev/null
[ -f /tmp/bird_b.pid ] && sudo kill "$(sudo cat /tmp/bird_b.pid)" 2>/dev/null
sleep 1
sudo kill -INT "$TDPID" 2>/dev/null
sleep 2
sudo chown "$(id -u)" "${PCAP:-$DIR/capture.pcap}" 2>/dev/null

echo "===== capture packet count ====="
tcpdump -r "${PCAP:-$DIR/capture.pcap}" 2>/dev/null | wc -l
