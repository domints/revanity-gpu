from __future__ import annotations

import os
from typing import Optional

import typer

from . import __version__
from .config import MatchMode, SearchConfig
from .core import VanityGenerator, persist_single_result
from .patterns import estimate_difficulty

app = typer.Typer(add_completion=False, help="Reticulum/LXMF Vanity Address Generator (GPU)")


def _mode_and_pattern(
    prefix: str, suffix: str, contains: str, regex: str
) -> tuple[MatchMode, str]:
    picks = [(MatchMode.PREFIX, prefix), (MatchMode.SUFFIX, suffix), (MatchMode.CONTAINS, contains), (MatchMode.REGEX, regex)]
    chosen = [(m, p) for m, p in picks if p]
    if len(chosen) != 1:
        raise typer.BadParameter(
            "exactly one pattern flag is required (-prefix, -suffix, -contains, -regex)"
        )
    return chosen[0]


@app.command()
def main(
    prefix: str = typer.Option("", "--prefix", "-p"),
    suffix: str = typer.Option("", "--suffix", "-s"),
    contains: str = typer.Option("", "--contains", "-c"),
    regex: str = typer.Option("", "--regex", "-r"),
    dest: str = typer.Option("lxmf.delivery", "--dest", "-d"),
    workers: int = typer.Option(0, "--workers", "-w"),
    output: str = typer.Option("", "--output", "-o"),
    loop: bool = typer.Option(False, "--loop", "-l"),
    no_dupe: bool = typer.Option(False, "--no-dupe"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    backend: str = typer.Option("auto", "--backend"),
    batch_size: int = typer.Option(4096, "--batch-size"),
    seed: str = typer.Option("", "--seed", help="Deterministic seed (testing/oracle)"),
    strict_verify: bool = typer.Option(
        True,
        "--strict-verify/--no-strict-verify",
        help="Re-derive and verify every match before accepting it",
    ),
    version: Optional[bool] = typer.Option(None, "--version"),
) -> None:
    if version:
        typer.echo(f"revanity-gpu {__version__}")
        raise typer.Exit(0)

    mode, raw_pattern = _mode_and_pattern(prefix, suffix, contains, regex)
    patterns = [p.strip() for p in raw_pattern.split(",") if p.strip()]
    if not patterns:
        raise typer.BadParameter("at least one non-empty pattern is required")

    cfg = SearchConfig(
        patterns=patterns,
        mode=mode,
        dest_type=dest,
        workers=workers,
        output=output,
        loop=loop,
        no_dupe=no_dupe,
        dry_run=dry_run,
        quiet=quiet,
        backend=backend,
        batch_size=batch_size,
        seed=seed,
        strict_verify=strict_verify,
    )
    gen = VanityGenerator(cfg)
    multi_mode = len(patterns) > 1

    if not quiet:
        typer.echo(f"revanity-gpu v{__version__}")
        typer.echo(f"  Pattern mode: {mode.value}")
        typer.echo(f"  Patterns: {', '.join(patterns)}")
        typer.echo(f"  Destination: {dest}")
        typer.echo(f"  Backend: {gen.backend.name} ({'available' if gen.backend.available() else 'fallback(cpu)'})")
        if len(patterns) == 1 and mode != MatchMode.REGEX:
            d = estimate_difficulty(mode, patterns[0])
            if d.can_estimate:
                typer.echo(f"  Expected: ~{d.expected_attempts:,} attempts")
                typer.echo(f"  Difficulty: {d.difficulty_desc}")

    if dry_run:
        raise typer.Exit(0)

    def on_progress(stats):
        if quiet:
            return
        typer.echo(
            f"Checked={stats.total_checked:,} Rate={stats.rate:,.0f}/sec Elapsed={stats.elapsed:.1f}s",
            err=True,
        )

    if loop or multi_mode:
        out_dir = output or "results"
        os.makedirs(out_dir, exist_ok=True)

        def on_result(result):
            if quiet:
                typer.echo(result.dest_hash_hex)
            else:
                typer.echo(
                    f"Match {result.dest_hash_hex} pattern='{result.pattern_str}' checked={result.total_checked:,}"
                )

        gen.run_loop(
            output_dir=out_dir,
            loop_mode=loop,
            no_dupe=no_dupe,
            on_progress=on_progress,
            on_result=on_result,
        )
        return

    result = gen.run_blocking(on_progress=on_progress)
    if result is None:
        raise typer.Exit(1)

    out_prefix = output or result.dest_hash_hex
    id_path, txt_path = persist_single_result(result, dest, "out", out_prefix)
    if quiet:
        typer.echo(result.dest_hash_hex)
    else:
        typer.echo(f"MATCH FOUND: {result.dest_hash_hex}")
        typer.echo(f"Identity file: {id_path}")
        typer.echo(f"Info file: {txt_path}")


if __name__ == "__main__":
    app()
