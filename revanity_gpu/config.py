from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MatchMode(str, Enum):
    PREFIX = "prefix"
    SUFFIX = "suffix"
    CONTAINS = "contains"
    REGEX = "regex"


@dataclass(frozen=True)
class SearchConfig:
    patterns: list[str]
    mode: MatchMode
    dest_type: str
    workers: int
    output: str
    loop: bool
    no_dupe: bool
    dry_run: bool
    quiet: bool
    backend: str
    batch_size: int
    seed: str = ""
    strict_verify: bool = True


DEST_NAME_HASHES = {
    "lxmf.delivery": bytes.fromhex("6ec60bc318e2c0f0d908"),
    "nomadnetwork.node": bytes.fromhex("213e6311bcec54ab4fde"),
}
