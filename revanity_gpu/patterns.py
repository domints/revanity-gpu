from __future__ import annotations

import math
import re
from dataclasses import dataclass

from .config import MatchMode

TRUNCATED_LEN = 16
HEX_ADDR_LEN = 32


def validate_hex_pattern(pattern: str) -> str:
    cleaned = pattern.strip().lower()
    if not cleaned:
        raise ValueError("pattern cannot be empty")
    if any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError(f"pattern '{pattern}' contains non-hex characters")
    if len(cleaned) > HEX_ADDR_LEN:
        raise ValueError(
            f"pattern length {len(cleaned)} exceeds maximum address length of 32"
        )
    return cleaned


@dataclass
class CompiledPattern:
    mode: MatchMode
    pattern: str
    regex: re.Pattern[str] | None = None
    byte_pattern: bytes = b""
    byte_offset: int = 0
    nibble_check: bool = False
    nibble_idx: int = 0
    nibble_mask: int = 0
    nibble_value: int = 0
    pattern_hex: bytes = b""

    @classmethod
    def compile(cls, mode: MatchMode, pattern: str) -> "CompiledPattern":
        if mode == MatchMode.REGEX:
            return cls(mode=mode, pattern=pattern, regex=re.compile(pattern, re.IGNORECASE))
        cleaned = validate_hex_pattern(pattern)
        cp = cls(mode=mode, pattern=cleaned)
        if mode == MatchMode.PREFIX:
            cp._setup_prefix(cleaned)
        elif mode == MatchMode.SUFFIX:
            cp._setup_suffix(cleaned)
        else:
            cp.pattern_hex = cleaned.encode("ascii")
        return cp

    def _setup_prefix(self, hex_str: str) -> None:
        n = len(hex_str)
        n_full = n // 2
        if n_full > 0:
            self.byte_pattern = bytes.fromhex(hex_str[: n_full * 2])
            self.byte_offset = 0
        if n % 2 == 1:
            self.nibble_check = True
            self.nibble_idx = n_full
            self.nibble_mask = 0xF0
            self.nibble_value = _hex_nibble(hex_str[-1]) << 4

    def _setup_suffix(self, hex_str: str) -> None:
        n = len(hex_str)
        n_full = n // 2
        if n % 2 == 1:
            self.nibble_check = True
            self.nibble_idx = TRUNCATED_LEN - n_full - 1
            self.nibble_mask = 0x0F
            self.nibble_value = _hex_nibble(hex_str[0])
            if n_full > 0:
                self.byte_pattern = bytes.fromhex(hex_str[1:])
                self.byte_offset = TRUNCATED_LEN - n_full
        elif n_full > 0:
            self.byte_pattern = bytes.fromhex(hex_str)
            self.byte_offset = TRUNCATED_LEN - n_full

    def matches_bytes(self, hash_bytes: bytes) -> bool:
        if self.mode in (MatchMode.PREFIX, MatchMode.SUFFIX):
            if self.byte_pattern:
                end = self.byte_offset + len(self.byte_pattern)
                if hash_bytes[self.byte_offset:end] != self.byte_pattern:
                    return False
            if self.nibble_check:
                if (hash_bytes[self.nibble_idx] & self.nibble_mask) != self.nibble_value:
                    return False
            return True
        if self.mode == MatchMode.CONTAINS:
            return self.pattern in hash_bytes.hex()
        if self.regex is None:
            return False
        return bool(self.regex.search(hash_bytes.hex()))

    def matches_hex(self, hex_addr: str) -> bool:
        if self.mode == MatchMode.PREFIX:
            return hex_addr.startswith(self.pattern)
        if self.mode == MatchMode.SUFFIX:
            return hex_addr.endswith(self.pattern)
        if self.mode == MatchMode.CONTAINS:
            return self.pattern in hex_addr
        if self.regex is None:
            return False
        return bool(self.regex.search(hex_addr))


def _hex_nibble(c: str) -> int:
    if "0" <= c <= "9":
        return ord(c) - ord("0")
    return ord(c) - ord("a") + 10


@dataclass(frozen=True)
class Difficulty:
    expected_attempts: int
    seconds_per_core: float
    difficulty_desc: str
    can_estimate: bool


def estimate_difficulty(mode: MatchMode, pattern: str) -> Difficulty:
    if mode == MatchMode.REGEX:
        return Difficulty(0, 0.0, "Cannot estimate for regex", False)

    n = len(pattern)
    if mode in (MatchMode.PREFIX, MatchMode.SUFFIX):
        expected = 16**n
    else:
        positions = max(1, HEX_ADDR_LEN - n + 1)
        expected = int((16**n) / positions)

    keys_per_sec = 5000.0
    secs = expected / keys_per_sec

    if expected < 100:
        desc = "Instant"
    elif expected < 100_000:
        desc = "Seconds"
    elif expected < 10_000_000:
        desc = "Minutes"
    elif expected < 1_000_000_000:
        desc = "Hours"
    elif expected < 100_000_000_000:
        desc = "Days"
    else:
        desc = "Weeks+ (consider a shorter pattern)"

    return Difficulty(expected, secs, desc, True)
