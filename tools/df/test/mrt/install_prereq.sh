#!/bin/bash
# Install what the MRT dump test suite needs on a dev box (Debian/Ubuntu):
# the BIRD build toolchain, plus iproute2 for the network namespaces.
# Only missing packages are installed. Needs sudo.
set -euo pipefail

PACKAGES=(build-essential autoconf flex bison libncurses-dev libreadline-dev iproute2)

missing=()
for pkg in "${PACKAGES[@]}"; do
  dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed' || missing+=("$pkg")
done

if [ ${#missing[@]} -eq 0 ]; then
  echo "all prerequisites already installed"
else
  echo "installing: ${missing[*]}"
  sudo apt-get update
  sudo apt-get -y install "${missing[@]}"
fi

# Not installed by this script: bgpdump ships with the deepfield-pipedream package, and
# pytest comes from the python environment. The suite skips what it cannot find.
command -v "${BGPDUMP:-bgpdump}" >/dev/null || echo "note: bgpdump not found, the bgpdump -m checks will be skipped"
command -v pytest >/dev/null || echo "note: pytest not found"
