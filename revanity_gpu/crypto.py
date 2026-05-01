from __future__ import annotations

import hashlib
import os

from nacl.bindings import crypto_scalarmult_base, crypto_sign_seed_keypair

from .config import DEST_NAME_HASHES

NAME_HASH_LEN = 10
TRUNCATED_LEN = 16


def compute_name_hash(dest_name: str) -> bytes:
    return hashlib.sha256(dest_name.encode("utf-8")).digest()[:NAME_HASH_LEN]


def get_dest_name_hash(dest_name: str) -> bytes:
    return DEST_NAME_HASHES.get(dest_name, compute_name_hash(dest_name))


def derive_from_private_key(private_key: bytes, dest_name_hash: bytes) -> tuple[bytes, bytes]:
    x_scalar = private_key[:32]
    ed_seed = private_key[32:64]

    x_pub = crypto_scalarmult_base(x_scalar)
    ed_pub, _ = crypto_sign_seed_keypair(ed_seed)

    identity_hash = hashlib.sha256(x_pub + ed_pub).digest()[:TRUNCATED_LEN]
    dest_hash = hashlib.sha256(dest_name_hash + identity_hash).digest()[:TRUNCATED_LEN]
    return identity_hash, dest_hash


def derive_from_x_scalar(
    x_scalar: bytes, ed_seed: bytes, ed_pub: bytes, dest_name_hash: bytes
) -> tuple[bytes, bytes, bytes]:
    x_pub = crypto_scalarmult_base(x_scalar)
    identity_hash = hashlib.sha256(x_pub + ed_pub).digest()[:TRUNCATED_LEN]
    dest_hash = hashlib.sha256(dest_name_hash + identity_hash).digest()[:TRUNCATED_LEN]
    private_key = x_scalar + ed_seed
    return private_key, identity_hash, dest_hash


def create_ed_state(ed_seed: bytes | None = None) -> tuple[bytes, bytes]:
    seed = ed_seed if ed_seed is not None else os.urandom(32)
    ed_pub, _ = crypto_sign_seed_keypair(seed)
    return seed, ed_pub


def verify_private_key_result(
    private_key: bytes, dest_name_hash: bytes, identity_hash: bytes, dest_hash: bytes
) -> bool:
    chk_identity, chk_dest = derive_from_private_key(private_key, dest_name_hash)
    return chk_identity == identity_hash and chk_dest == dest_hash
