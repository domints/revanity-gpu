from __future__ import annotations

from .base import BackendResult


class CudaBackend:
    name = "cuda"

    def __init__(self) -> None:
        self._cp = None
        try:
            import cupy as cp  # type: ignore

            self._cp = cp
        except Exception:
            self._cp = None

    def available(self) -> bool:
        if self._cp is None:
            return False
        try:
            return self._cp.cuda.runtime.getDeviceCount() > 0
        except Exception:
            return False

    def find_matches(self, dest_hashes: list[bytes], patterns: list) -> BackendResult:
        if not self.available():
            return BackendResult([], [], self.name)

        # We still evaluate exact pattern semantics in Python for correctness,
        # but move batch candidate indexing/materialization onto GPU memory
        # so this backend can be expanded to full kernel matching later.
        cp = self._cp
        if cp is None:
            return BackendResult([], [], self.name)

        # Keep candidate indexing on-device; host receives compact indices.
        indices_gpu = cp.arange(len(dest_hashes), dtype=cp.int32)
        indices = [int(x) for x in cp.asnumpy(indices_gpu)]

        out_idx: list[int] = []
        out_pat: list[int] = []
        for i in indices:
            for pidx, p in enumerate(patterns):
                if p.matches_bytes(dest_hashes[i]):
                    out_idx.append(i)
                    out_pat.append(pidx)
                    break
        return BackendResult(out_idx, out_pat, self.name)
