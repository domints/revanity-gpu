from __future__ import annotations

import base64
import json
from pathlib import Path


def save_identity_file(private_key: bytes, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(private_key)
    return str(path.resolve())


def save_identity_text(payload: dict, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = (
        f"Destination Hash: {payload['dest_hash_hex']}\n"
        f"Identity Hash: {payload['identity_hash_hex']}\n"
        f"Destination Type: {payload['dest_type']}\n"
        f"Private Key (hex): {payload['private_key_hex']}\n"
        f"Private Key (base64): {payload['private_key_b64']}\n"
    )
    path.write_text(text, encoding="utf-8")
    return str(path.resolve())


def append_result_jsonl(jsonl_path: str, payload: dict) -> None:
    path = Path(jsonl_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, separators=(",", ":")) + "\n")


def export_payload(
    private_key: bytes,
    identity_hash: bytes,
    dest_hash: bytes,
    dest_type: str,
    matched_pattern: str,
) -> dict:
    return {
        "dest_hash_hex": dest_hash.hex(),
        "identity_hash_hex": identity_hash.hex(),
        "dest_type": dest_type,
        "matched_pattern": matched_pattern,
        "private_key_hex": private_key.hex(),
        "private_key_b64": base64.b64encode(private_key).decode("ascii"),
    }
