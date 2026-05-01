from __future__ import annotations

import hashlib

from .crypto import derive_from_private_key


def deterministic_private_keys(seed: bytes, count: int) -> list[bytes]:
    keys: list[bytes] = []
    for i in range(count):
        block = hashlib.sha512(seed + i.to_bytes(8, "big")).digest()
        keys.append(block[:64])
    return keys


def cpu_reference_hashes(
    private_keys: list[bytes], dest_name_hash: bytes
) -> list[tuple[bytes, bytes, str]]:
    out: list[tuple[bytes, bytes, str]] = []
    for key in private_keys:
        identity_hash, dest_hash = derive_from_private_key(key, dest_name_hash)
        out.append((identity_hash, dest_hash, dest_hash.hex()))
    return out
