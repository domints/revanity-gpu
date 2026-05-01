from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class NativeHit:
    x_scalar: bytes
    checked: int


class NativeCudaBridge:
    """
    Optional bridge to a compiled CUDA shared library.

    The native library is intentionally optional: when unavailable, callers
    should fall back to the pure-Python path.
    """

    def __init__(self) -> None:
        self._lib = None
        self._load_error = ""
        self._load()

    @property
    def load_error(self) -> str:
        return self._load_error

    def _candidate_paths(self) -> list[str]:
        root = os.path.dirname(__file__)
        return [
            os.path.join(root, "native", "revanity_cuda.dll"),
            os.path.join(root, "native", "revanity_cuda.so"),
            os.path.join(root, "native", "revanity_cuda.dylib"),
        ]

    def _load(self) -> None:
        for path in self._candidate_paths():
            if not os.path.exists(path):
                continue
            try:
                lib = ctypes.CDLL(path)
            except OSError as exc:
                self._load_error = str(exc)
                continue
            try:
                fn = lib.revanity_scan_prefix_suffix
                fn.argtypes = [
                    ctypes.c_void_p,  # x_scalars buffer (n*32)
                    ctypes.c_size_t,  # n
                    ctypes.c_void_p,  # pattern bytes
                    ctypes.c_size_t,  # pattern length
                    ctypes.c_int,  # mode: 0 prefix, 1 suffix
                    ctypes.POINTER(ctypes.c_uint8),  # out x_scalar[32]
                    ctypes.POINTER(ctypes.c_uint64),  # out checked count
                ]
                fn.restype = ctypes.c_int  # 1 hit, 0 miss, <0 error
                self._lib = lib
                self._load_error = ""
                return
            except Exception as exc:  # pragma: no cover
                self._load_error = str(exc)
        if not self._load_error:
            self._load_error = "native CUDA library not found"

    def available(self) -> bool:
        return self._lib is not None

    def scan_prefix_suffix(
        self, x_scalars_flat: bytes, pattern_hex: str, mode: str
    ) -> NativeHit | None:
        if self._lib is None:
            return None
        if mode not in ("prefix", "suffix"):
            return None
        n = len(x_scalars_flat) // 32
        if n <= 0:
            return None

        out_scalar = (ctypes.c_uint8 * 32)()
        out_checked = ctypes.c_uint64(0)
        in_buf = ctypes.create_string_buffer(x_scalars_flat, len(x_scalars_flat))
        pat_bytes = pattern_hex.encode("ascii")
        pat_buf = ctypes.create_string_buffer(pat_bytes, len(pat_bytes))
        mode_int = 0 if mode == "prefix" else 1

        rc = self._lib.revanity_scan_prefix_suffix(
            ctypes.cast(in_buf, ctypes.c_void_p),
            n,
            ctypes.cast(pat_buf, ctypes.c_void_p),
            len(pat_bytes),
            mode_int,
            out_scalar,
            ctypes.byref(out_checked),
        )
        if rc <= 0:
            return None
        return NativeHit(x_scalar=bytes(out_scalar), checked=int(out_checked.value))
