"""Pytest configuration and test fixtures for hermetic_slice tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import SyntheticRepo, build_synthetic_repo


@pytest.fixture
def synthetic_repo(tmp_path: Path) -> SyntheticRepo:
    """Build a synthetic git repository meeting all task requirements."""
    return build_synthetic_repo(tmp_path)
