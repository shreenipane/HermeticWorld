"""Offline cutoff filters for crates.io sparse indexes and Go proxy metadata.

The exported filters transform bounded bytes without file or network operations.
The mirror submodule verifies acquisition blobs and publishes admitted metadata
and artifacts into a frozen offline WorldServer store. No source is fetched.
"""

from .cut import CutError, CutReport, cut_crates_index, cut_go_versions
from .pypi import PyPIIndex, cut_pypi_json, cut_pypi_simple

__all__ = ["CutError", "CutReport", "PyPIIndex", "cut_crates_index", "cut_go_versions",
           "cut_pypi_json", "cut_pypi_simple"]
