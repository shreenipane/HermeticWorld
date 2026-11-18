
from dataclasses import dataclass

from typing import Optional



MAX_INVENTORY_BYTES = 1 * 1024 * 1024

MAX_METADATA_BYTES = 64 * 1024 * 1024

MAX_EXEMPTIONS_BYTES = 1 * 1024 * 1024

MAX_PACKAGES = 20000

MAX_EXEMPTIONS = 5000

MAX_METADATA_PACKAGES_PER_ECOSYSTEM = 200000

MAX_VERSIONS_PER_PACKAGE = 10000

MAX_FILES_PER_VERSION = 1000

MAX_STRING_LEN = 4096

MAX_JSON_DEPTH = 16

READ_CHUNK_BYTES = 65536



ECOSYSTEMS = ("pypi", "conda", "npm", "crates", "dpkg", "apt")

MODES = ("strict", "repo_only")





class D5bError(Exception):

    """Typed error for all D5b validation, parsing, and I/O failures."""





@dataclass(frozen=True, order=True)

class InventoryPackage:

    ecosystem: str

    name: str

    version: str

    file: Optional[str]


    def to_dict(self) -> dict:

        return {

            "ecosystem": self.ecosystem,

            "name": self.name,

            "version": self.version,

            "file": self.file,

        }





@dataclass(frozen=True, order=True)

class Exemption:

    ecosystem: str

    name: str

    version: str

    reason: str





@dataclass(frozen=True, order=True)

class PackageReportEntry:

    ecosystem: str

    name: str

    version: str

    file: Optional[str]

    release_time: Optional[str]

    reason: Optional[str]



    def to_dict(self, include_release_time: bool = False, include_reason: bool = False) -> dict:

        out = {

            "ecosystem": self.ecosystem,

            "name": self.name,

            "version": self.version,

            "file": self.file,

        }

        if include_release_time:

            out["release_time"] = self.release_time

        if include_reason:

            out["reason"] = self.reason

        return out

