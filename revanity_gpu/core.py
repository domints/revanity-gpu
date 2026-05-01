from __future__ import annotations

import os
import time
import hashlib
import multiprocessing as mp
import queue
from dataclasses import dataclass
from typing import Callable

from .config import MatchMode, SearchConfig
from .crypto import (
    create_ed_state,
    derive_from_private_key,
    derive_from_x_scalar,
    get_dest_name_hash,
    verify_private_key_result,
)
from .export import append_result_jsonl, export_payload, save_identity_file, save_identity_text
from .patterns import CompiledPattern
from .backends.cuda import CudaBackend
from .backends.cuda_native import CudaNativeBackend
from .backends.opencl import OpenCLBackend
from .native_cuda import NativeCudaBridge


@dataclass
class GeneratorResult:
    private_key: bytes
    identity_hash: bytes
    dest_hash: bytes
    dest_hash_hex: str
    pattern_idx: int
    pattern_str: str
    elapsed: float
    total_checked: int
    rate: float


@dataclass
class GeneratorStats:
    total_checked: int
    elapsed: float
    rate: float


def _worker_search_blocking(
    stop_event,
    result_queue,
    counter,
    batch_size: int,
    dest_name_hash: bytes,
    mode_value: str,
    pattern_values: list[str],
    seed: str,
    worker_idx: int,
    strict_verify: bool,
) -> None:
    mode = MatchMode(mode_value)
    patterns = [CompiledPattern.compile(mode, p) for p in pattern_values]
    if seed:
        ed_seed = hashlib.sha256(f"{seed}:ed:{worker_idx}".encode("utf-8")).digest()[:32]
    else:
        ed_seed = os.urandom(32)
    _, ed_pub = create_ed_state(ed_seed)

    checked_local = 0
    seed_bytes = seed.encode("utf-8") if seed else b""
    iteration = 0

    while not stop_event.is_set():
        if seed:
            raw = bytearray()
            for i in range(batch_size):
                block = hashlib.sha512(
                    seed_bytes
                    + worker_idx.to_bytes(4, "big")
                    + iteration.to_bytes(8, "big")
                    + i.to_bytes(8, "big")
                ).digest()
                raw.extend(block[:32])
            buf = bytes(raw)
            iteration += 1
        else:
            buf = os.urandom(batch_size * 32)

        mv = memoryview(buf)
        for off in range(0, len(buf), 32):
            x_scalar = bytes(mv[off : off + 32])
            priv, identity_hash, dest_hash = derive_from_x_scalar(
                x_scalar, ed_seed, ed_pub, dest_name_hash
            )
            checked_local += 1
            for pidx, p in enumerate(patterns):
                if p.matches_bytes(dest_hash):
                    if strict_verify:
                        ok = verify_private_key_result(
                            priv, dest_name_hash, identity_hash, dest_hash
                        )
                        if not ok:
                            break
                    with counter.get_lock():
                        counter.value += checked_local
                    result_queue.put((priv, identity_hash, dest_hash, pidx, p.pattern))
                    stop_event.set()
                    return
        with counter.get_lock():
            counter.value += checked_local
        checked_local = 0


def select_backend(name: str):
    if name == "cuda-native":
        return CudaNativeBackend()
    if name == "cuda":
        return CudaBackend()
    if name == "opencl":
        return OpenCLBackend()
    cuda_native = CudaNativeBackend()
    if cuda_native.available():
        return cuda_native
    cuda = CudaBackend()
    if cuda.available():
        return cuda
    return OpenCLBackend()


class VanityGenerator:
    def __init__(self, config: SearchConfig) -> None:
        self.config = config
        self.patterns = [CompiledPattern.compile(config.mode, p) for p in config.patterns]
        self.dest_name_hash = get_dest_name_hash(config.dest_type)
        self.backend = select_backend(config.backend)
        self.backend_available = self.backend.available()
        self.total_checked = 0
        self.start = time.perf_counter()
        self.num_workers = config.workers if config.workers > 0 else max(1, (os.cpu_count() or 2) - 1)
        self.native_bridge = NativeCudaBridge()
        if config.seed:
            fixed_seed = hashlib.sha256((config.seed + ":ed").encode("utf-8")).digest()[:32]
            self.ed_seed, self.ed_pub = create_ed_state(fixed_seed)
        else:
            self.ed_seed, self.ed_pub = create_ed_state()

    def _verified_or_none(
        self, private_key: bytes, identity_hash: bytes, dest_hash: bytes
    ) -> tuple[bytes, bytes] | None:
        if not self.config.strict_verify:
            return identity_hash, dest_hash
        ok = verify_private_key_result(
            private_key, self.dest_name_hash, identity_hash, dest_hash
        )
        if not ok:
            return None
        # Use independently re-derived values as the accepted source of truth.
        return derive_from_private_key(private_key, self.dest_name_hash)

    def _gen_x_scalars(self, count: int) -> list[bytes]:
        if self.config.seed:
            scalars: list[bytes] = []
            for i in range(count):
                block = hashlib.sha512(
                    self.config.seed.encode("utf-8")
                    + self.total_checked.to_bytes(8, "big")
                    + i.to_bytes(8, "big")
                ).digest()
                scalars.append(block[:32])
            return scalars
        return [os.urandom(32) for _ in range(count)]

    def _evaluate_stream(self, x_scalars: list[bytes]) -> list[tuple[int, int, bytes, bytes, bytes]]:
        out: list[tuple[int, int, bytes, bytes, bytes]] = []
        derived: list[tuple[bytes, bytes, bytes]] = []
        for i, x_scalar in enumerate(x_scalars):
            priv, identity_hash, dest_hash = derive_from_x_scalar(
                x_scalar, self.ed_seed, self.ed_pub, self.dest_name_hash
            )
            derived.append((priv, identity_hash, dest_hash))

        if self.backend_available:
            bres = self.backend.find_matches([d[2] for d in derived], self.patterns)
            for idx, pidx in zip(bres.matched_indices, bres.matched_pattern_indices):
                priv, identity_hash, dest_hash = derived[idx]
                out.append((idx, pidx, priv, identity_hash, dest_hash))
            return out

        for i, (_, _, dest_hash) in enumerate(derived):
            for pidx, p in enumerate(self.patterns):
                if p.matches_bytes(dest_hash):
                    priv, identity_hash, _ = derived[i]
                    out.append((i, pidx, priv, identity_hash, dest_hash))
                    break
        return out

    def _evaluate_batch(self, x_scalars: list[bytes]) -> list[tuple[int, int, bytes, bytes, bytes]]:
        return self._evaluate_stream(x_scalars)

    def _stream_batch_blocking(self) -> GeneratorResult | None:
        if self.config.seed:
            x_scalars = self._gen_x_scalars(self.config.batch_size)
            for x_scalar in x_scalars:
                priv, identity_hash, dest_hash = derive_from_x_scalar(
                    x_scalar, self.ed_seed, self.ed_pub, self.dest_name_hash
                )
                self.total_checked += 1
                for pidx, p in enumerate(self.patterns):
                    if p.matches_bytes(dest_hash):
                        verified = self._verified_or_none(priv, identity_hash, dest_hash)
                        if verified is None:
                            break
                        identity_hash, dest_hash = verified
                        now = time.perf_counter()
                        elapsed = now - self.start
                        rate = self.total_checked / max(1e-9, elapsed)
                        return GeneratorResult(
                            private_key=priv,
                            identity_hash=identity_hash,
                            dest_hash=dest_hash,
                            dest_hash_hex=dest_hash.hex(),
                            pattern_idx=pidx,
                            pattern_str=self.patterns[pidx].pattern,
                            elapsed=elapsed,
                            total_checked=self.total_checked,
                            rate=rate,
                        )
            return None

        # Fast random path: one syscall per batch instead of per key.
        raw = os.urandom(self.config.batch_size * 32)
        mv = memoryview(raw)
        for off in range(0, len(raw), 32):
            x_scalar = bytes(mv[off : off + 32])
            priv, identity_hash, dest_hash = derive_from_x_scalar(
                x_scalar, self.ed_seed, self.ed_pub, self.dest_name_hash
            )
            self.total_checked += 1
            for pidx, p in enumerate(self.patterns):
                if p.matches_bytes(dest_hash):
                    verified = self._verified_or_none(priv, identity_hash, dest_hash)
                    if verified is None:
                        break
                    identity_hash, dest_hash = verified
                    now = time.perf_counter()
                    elapsed = now - self.start
                    rate = self.total_checked / max(1e-9, elapsed)
                    return GeneratorResult(
                        private_key=priv,
                        identity_hash=identity_hash,
                        dest_hash=dest_hash,
                        dest_hash_hex=dest_hash.hex(),
                        pattern_idx=pidx,
                        pattern_str=self.patterns[pidx].pattern,
                        elapsed=elapsed,
                        total_checked=self.total_checked,
                        rate=rate,
                    )
        return None

    def stats(self) -> GeneratorStats:
        elapsed = time.perf_counter() - self.start
        rate = self.total_checked / elapsed if elapsed > 0 else 0.0
        return GeneratorStats(self.total_checked, elapsed, rate)

    def run_blocking(self, on_progress: Callable[[GeneratorStats], None] | None = None) -> GeneratorResult | None:
        # Disabled for now: the native bridge is scaffolded, but full end-to-end
        # curve/hash integration is not complete yet.
        if self.num_workers > 1:
            return self._run_blocking_multiprocess(on_progress)

        last_progress = 0.0
        while True:
            result = self._stream_batch_blocking()

            now = time.perf_counter()
            if on_progress and now - last_progress >= 0.5:
                on_progress(self.stats())
                last_progress = now

            if result is not None:
                return result

    def _run_blocking_native_prefix_suffix(
        self, on_progress: Callable[[GeneratorStats], None] | None
    ) -> GeneratorResult | None:
        # Native bridge currently handles only single-pattern prefix/suffix batches.
        if (
            not self.native_bridge.available()
            or len(self.patterns) != 1
            or self.config.mode not in (MatchMode.PREFIX, MatchMode.SUFFIX)
            or self.config.seed
        ):
            return None

        pattern = self.patterns[0].pattern
        last_progress = 0.0
        while True:
            raw = os.urandom(self.config.batch_size * 32)
            hit = self.native_bridge.scan_prefix_suffix(raw, pattern, self.config.mode.value)
            self.total_checked += self.config.batch_size if hit is None else hit.checked

            now = time.perf_counter()
            if on_progress and now - last_progress >= 0.5:
                on_progress(self.stats())
                last_progress = now

            if hit is None:
                continue

            priv, identity_hash, dest_hash = derive_from_x_scalar(
                hit.x_scalar, self.ed_seed, self.ed_pub, self.dest_name_hash
            )
            verified = self._verified_or_none(priv, identity_hash, dest_hash)
            if verified is None:
                continue
            identity_hash, dest_hash = verified
            elapsed = now - self.start
            rate = self.total_checked / max(1e-9, elapsed)
            return GeneratorResult(
                private_key=priv,
                identity_hash=identity_hash,
                dest_hash=dest_hash,
                dest_hash_hex=dest_hash.hex(),
                pattern_idx=0,
                pattern_str=self.patterns[0].pattern,
                elapsed=elapsed,
                total_checked=self.total_checked,
                rate=rate,
            )

    def _run_blocking_multiprocess(
        self, on_progress: Callable[[GeneratorStats], None] | None
    ) -> GeneratorResult | None:
        ctx = mp.get_context("spawn")
        stop_event = ctx.Event()
        result_queue = ctx.Queue()
        counter = ctx.Value("Q", 0)
        workers: list[mp.Process] = []

        for i in range(self.num_workers):
            p = ctx.Process(
                target=_worker_search_blocking,
                args=(
                    stop_event,
                    result_queue,
                    counter,
                    self.config.batch_size,
                    self.dest_name_hash,
                    self.config.mode.value,
                    [p.pattern for p in self.patterns],
                    self.config.seed,
                    i,
                    self.config.strict_verify,
                ),
            )
            p.start()
            workers.append(p)

        try:
            last_progress = 0.0
            while True:
                try:
                    priv, identity_hash, dest_hash, pidx, pattern_str = result_queue.get(
                        timeout=0.1
                    )
                    now = time.perf_counter()
                    self.total_checked = int(counter.value)
                    verified = self._verified_or_none(priv, identity_hash, dest_hash)
                    if verified is None:
                        continue
                    identity_hash, dest_hash = verified
                    elapsed = now - self.start
                    rate = self.total_checked / max(1e-9, elapsed)
                    return GeneratorResult(
                        private_key=priv,
                        identity_hash=identity_hash,
                        dest_hash=dest_hash,
                        dest_hash_hex=dest_hash.hex(),
                        pattern_idx=int(pidx),
                        pattern_str=pattern_str,
                        elapsed=elapsed,
                        total_checked=self.total_checked,
                        rate=rate,
                    )
                except queue.Empty:
                    now = time.perf_counter()
                    self.total_checked = int(counter.value)
                    if on_progress and now - last_progress >= 0.5:
                        on_progress(self.stats())
                        last_progress = now
        finally:
            stop_event.set()
            for p in workers:
                p.join(timeout=1.0)
                if p.is_alive():
                    p.terminate()

    def run_loop(
        self,
        output_dir: str,
        loop_mode: bool,
        no_dupe: bool,
        on_progress: Callable[[GeneratorStats], None] | None = None,
        on_result: Callable[[GeneratorResult], None] | None = None,
    ) -> None:
        print(f"Running loop in directory: {output_dir}")
        found_per_pattern: dict[int, int] = {}
        jsonl_path = os.path.join(
            output_dir,
            f"{self.config.mode.value}_{','.join(self.config.patterns)}.jsonl",
        )
        last_progress = 0.0

        while True:
            x_scalars = self._gen_x_scalars(self.config.batch_size)
            matches = self._evaluate_batch(x_scalars)
            self.total_checked += len(x_scalars)

            now = time.perf_counter()
            if on_progress and now - last_progress >= 0.5:
                on_progress(self.stats())
                last_progress = now

            for _, pidx, key, identity_hash, dest_hash in matches:
                verified = self._verified_or_none(key, identity_hash, dest_hash)
                if verified is None:
                    continue
                identity_hash, dest_hash = verified
                found_per_pattern[pidx] = found_per_pattern.get(pidx, 0) + 1
                is_dupe = found_per_pattern[pidx] > 1
                if no_dupe and is_dupe:
                    continue

                result = GeneratorResult(
                    private_key=key,
                    identity_hash=identity_hash,
                    dest_hash=dest_hash,
                    dest_hash_hex=dest_hash.hex(),
                    pattern_idx=pidx,
                    pattern_str=self.patterns[pidx].pattern,
                    elapsed=now - self.start,
                    total_checked=self.total_checked,
                    rate=self.total_checked / max(1e-9, now - self.start),
                )
                payload = export_payload(
                    key, identity_hash, dest_hash, self.config.dest_type, result.pattern_str
                )
                append_result_jsonl(jsonl_path, payload)
                save_identity_file(key, os.path.join(output_dir, result.dest_hash_hex + ".identity"))
                if on_result:
                    on_result(result)

            if not loop_mode and len(found_per_pattern) >= len(self.patterns):
                return


def persist_single_result(result: GeneratorResult, dest_type: str, output_dir: str, output_prefix: str) -> tuple[str, str]:
    payload = export_payload(
        result.private_key,
        result.identity_hash,
        result.dest_hash,
        dest_type,
        result.pattern_str,
    )
    identity_path = save_identity_file(result.private_key, os.path.join(output_dir, output_prefix + ".identity"))
    txt_path = save_identity_text(payload, os.path.join(output_dir, output_prefix + ".txt"))
    return identity_path, txt_path
