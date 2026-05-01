from __future__ import annotations

from .base import BackendResult


class OpenCLBackend:
    name = "opencl"

    def __init__(self) -> None:
        self._cl = None
        try:
            import pyopencl as cl  # type: ignore

            self._cl = cl
        except Exception:
            self._cl = None

    def available(self) -> bool:
        if self._cl is None:
            return False
        try:
            return len(self._cl.get_platforms()) > 0
        except Exception:
            return False

    def find_matches(self, dest_hashes: list[bytes], patterns: list) -> BackendResult:
        if not self.available():
            return BackendResult([], [], self.name)

        out_idx: list[int] = []
        out_pat: list[int] = []
        for i, h in enumerate(dest_hashes):
            for pidx, p in enumerate(patterns):
                if p.matches_bytes(h):
                    out_idx.append(i)
                    out_pat.append(pidx)
                    break
        return BackendResult(out_idx, out_pat, self.name)
