import hashlib

from nacl.bindings import crypto_scalarmult_base, crypto_sign_seed_keypair

from revanity_gpu.crypto import (
    derive_from_private_key,
    get_dest_name_hash,
    verify_private_key_result,
)


def test_derive_from_private_key_matches_formula():
    priv = bytes(range(64))
    name_hash = get_dest_name_hash("lxmf.delivery")
    identity_hash, dest_hash = derive_from_private_key(priv, name_hash)

    x_pub = crypto_scalarmult_base(priv[:32])
    ed_pub, _ = crypto_sign_seed_keypair(priv[32:64])
    expected_identity = hashlib.sha256(x_pub + ed_pub).digest()[:16]
    expected_dest = hashlib.sha256(name_hash + expected_identity).digest()[:16]

    assert identity_hash == expected_identity
    assert dest_hash == expected_dest


def test_verify_private_key_result():
    priv = bytes(range(64))
    name_hash = get_dest_name_hash("lxmf.delivery")
    identity_hash, dest_hash = derive_from_private_key(priv, name_hash)
    assert verify_private_key_result(priv, name_hash, identity_hash, dest_hash)
    assert not verify_private_key_result(priv, name_hash, identity_hash, b"\x00" * 16)
