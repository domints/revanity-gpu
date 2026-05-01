# Native CUDA Bridge

This folder contains an optional compiled native library scaffold:

- `revanity_cuda.dll` (Windows)
- `revanity_cuda.so` (Linux)
- `revanity_cuda.dylib` (macOS)

The Python loader (`revanity_gpu/native_cuda.py`) looks for these files here and
can call the symbol:

`int revanity_scan_prefix_suffix(const void* x_scalars, size_t n, const void* pattern_hex, size_t pattern_len, int mode, uint8_t out_scalar[32], uint64_t* out_checked);`

## Behavior Contract

- Return `1` when a hit is found and write matching `out_scalar`.
- Return `0` when no hit in this batch.
- Return `<0` on error.
- Always set `out_checked` to how many candidates were actually processed.

## Build (Windows)

From PowerShell:

```powershell
cd revanity_gpu/native
.\build_windows.ps1
```

This uses CMake + CUDA Toolkit and copies `revanity_cuda.dll` into this folder.

## Safety Model

Even when native CUDA integration is enabled in future stages, accepted matches
must be re-derived and verified by the trusted CPU path when
`--strict-verify` is on (default).

## Current Status

- The native library and Python bridge are scaffolded and testable as components.
- Full end-to-end native search path is intentionally not enabled yet.
- Next stage is implementing complete GPU hot-path compatibility for the bridge.
