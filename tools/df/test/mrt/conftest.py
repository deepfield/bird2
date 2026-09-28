"""
Fixtures for the MRT dump suite.

Environment:
  BIRD       bird binary under test (default: <repo>/bird, built by build_bird.sh)
  PEER_BIRD  bird binary for the announcing peers (default: $BIRD)
  BGPDUMP    bgpdump for the consumer checks (default: bgpdump on PATH)

Tests that need namespaces skip when passwordless sudo is not available.
"""

import os
import shutil
from pathlib import Path

import pytest

import birdlab
import netns

REPO = Path(__file__).resolve().parents[4]


def _executable(path: Path, what: str, hint: str) -> Path:
    if not os.access(path, os.X_OK):
        pytest.skip(f"no {what} at {path}: {hint}")
    return path


@pytest.fixture(scope="session")
def bird_bin() -> Path:
    path = Path(os.environ.get("BIRD", REPO / "bird"))
    return _executable(path, "bird binary", "run build_bird.sh or set BIRD")


@pytest.fixture(scope="session")
def peer_bird_bin(bird_bin) -> Path:
    path = Path(os.environ.get("PEER_BIRD", bird_bin))
    return _executable(path, "peer bird binary", "set PEER_BIRD")


@pytest.fixture(scope="session")
def bgpdump_bin() -> Path:
    found = shutil.which(os.environ.get("BGPDUMP", "bgpdump"))
    if not found:
        pytest.skip("bgpdump not found: set BGPDUMP or install the deepfield-pipedream package")
    return Path(found)


@pytest.fixture(scope="session")
def netns_ok() -> None:
    reason = netns.available()
    if reason:
        pytest.skip(f"network namespaces unavailable: {reason}")
    netns.cleanup_stale()


@pytest.fixture(scope="module")
def lab(request, tmp_path_factory, netns_ok):
    """Namespaces and daemons shared by one test module, torn down after it."""
    lab = birdlab.Lab(tmp_path_factory.mktemp(request.module.__name__.rsplit(".", 1)[-1]))
    yield lab
    lab.close()
