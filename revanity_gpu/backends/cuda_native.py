from __future__ import annotations

from .base import BackendResult
from ..config import MatchMode

KERNEL_SRC = r"""
extern "C" __global__
void match_prefix_suffix(
    const unsigned char* hashes,  // n * 16
    int n,
    const unsigned char* byte_pattern,
    int byte_pattern_len,
    int byte_offset,
    int nibble_check,
    int nibble_idx,
    int nibble_mask,
    int nibble_value,
    int* out_flags
){
    int i = blockDim.x * blockIdx.x + threadIdx.x;
    if (i >= n) return;
    const unsigned char* h = hashes + i * 16;

    int ok = 1;
    for (int j = 0; j < byte_pattern_len; j++) {
        if (h[byte_offset + j] != byte_pattern[j]) {
            ok = 0;
            break;
        }
    }
    if (ok && nibble_check) {
        if ((h[nibble_idx] & nibble_mask) != nibble_value) {
            ok = 0;
        }
    }
    out_flags[i] = ok;
}
"""


class CudaNativeBackend:
    name = "cuda-native"

    def __init__(self) -> None:
        self._cp = None
        self._kernel = None
        try:
            import cupy as cp  # type: ignore

            self._cp = cp
            self._kernel = cp.RawKernel(KERNEL_SRC, "match_prefix_suffix")
        except Exception:
            self._cp = None
            self._kernel = None

    def available(self) -> bool:
        if self._cp is None or self._kernel is None:
            return False
        try:
            return self._cp.cuda.runtime.getDeviceCount() > 0
        except Exception:
            return False

    def find_matches(self, dest_hashes: list[bytes], patterns: list) -> BackendResult:
        # Current native kernel path supports only one prefix/suffix pattern.
        if (
            not self.available()
            or len(patterns) != 1
            or patterns[0].mode not in (MatchMode.PREFIX, MatchMode.SUFFIX)
        ):
            return BackendResult([], [], self.name)

        cp = self._cp
        kernel = self._kernel
        if cp is None or kernel is None:
            return BackendResult([], [], self.name)

        p = patterns[0]
        if not dest_hashes:
            return BackendResult([], [], self.name)

        n = len(dest_hashes)
        flat = b"".join(dest_hashes)
        hashes_gpu = cp.frombuffer(flat, dtype=cp.uint8).reshape((n, 16))
        byte_pattern = p.byte_pattern if p.byte_pattern else b"\x00"
        byte_pattern_gpu = cp.frombuffer(byte_pattern, dtype=cp.uint8)
        out_flags = cp.zeros((n,), dtype=cp.int32)

        threads = 256
        blocks = (n + threads - 1) // threads
        kernel(
            (blocks,),
            (threads,),
            (
                hashes_gpu,
                n,
                byte_pattern_gpu,
                len(p.byte_pattern),
                p.byte_offset,
                1 if p.nibble_check else 0,
                p.nibble_idx,
                p.nibble_mask,
                p.nibble_value,
                out_flags,
            ),
        )
        hit_idx = cp.where(out_flags == 1)[0]
        idx = [int(v) for v in cp.asnumpy(hit_idx)]
        return BackendResult(idx, [0] * len(idx), self.name)
