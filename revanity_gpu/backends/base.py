from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..patterns import CompiledPattern


@dataclass(frozen=True)
class BackendResult:
    matched_indices: list[int]
    matched_pattern_indices: list[int]
    backend_name: str


class GpuBackend(Protocol):
    name: str

    def available(self) -> bool:
        ...

    def find_matches(
        self, dest_hashes: list[bytes], patterns: list[CompiledPattern]
    ) -> BackendResult:
        ...
