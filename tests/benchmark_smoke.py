from __future__ import annotations

import time

from revanity_gpu.config import MatchMode, SearchConfig
from revanity_gpu.core import VanityGenerator


def main() -> None:
    cfg = SearchConfig(
        patterns=["0"],
        mode=MatchMode.PREFIX,
        dest_type="lxmf.delivery",
        workers=0,
        output="",
        loop=False,
        no_dupe=False,
        dry_run=False,
        quiet=True,
        backend="auto",
        batch_size=8192,
    )
    gen = VanityGenerator(cfg)

    start = time.perf_counter()
    keys = 0
    for _ in range(5):
        batch = gen._gen_x_scalars(cfg.batch_size)
        _ = gen._evaluate_batch(batch)
        keys += len(batch)
    elapsed = time.perf_counter() - start
    print(f"smoke_benchmark: {keys / elapsed:,.0f} keys/sec")


if __name__ == "__main__":
    main()
