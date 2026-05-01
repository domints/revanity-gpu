from revanity_gpu.crypto import get_dest_name_hash
from revanity_gpu.oracle import cpu_reference_hashes, deterministic_private_keys


def test_deterministic_private_keys_are_stable():
    a = deterministic_private_keys(b"seed", 4)
    b = deterministic_private_keys(b"seed", 4)
    assert a == b


def test_cpu_oracle_hashes_are_stable():
    keys = deterministic_private_keys(b"go-parity-seed", 3)
    dest_name_hash = get_dest_name_hash("lxmf.delivery")
    out1 = cpu_reference_hashes(keys, dest_name_hash)
    out2 = cpu_reference_hashes(keys, dest_name_hash)
    assert out1 == out2
    assert len(out1[0][2]) == 32
