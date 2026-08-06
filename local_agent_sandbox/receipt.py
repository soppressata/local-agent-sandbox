"""
Receipt storage, loading, and verification module.
"""

import json
import os
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


def load_public_key(path: str) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from a PEM file."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_receipt(signed_receipt: Dict[str, Any], public_key: Any) -> bool:
    """Verifies the signature of a signed receipt using a public key."""
    if not isinstance(signed_receipt, dict) or "signature" not in signed_receipt or "receipt" not in signed_receipt:
        return False
    try:
        sig_bytes = bytes.fromhex(signed_receipt["signature"])
        data_bytes = json.dumps(signed_receipt["receipt"], sort_keys=True).encode("utf-8")
        public_key.verify(sig_bytes, data_bytes)
        return True
    except Exception:
        return False


class ReceiptStore:
    """Directory-backed store for signed run receipts."""

    def __init__(self, store_dir: str):
        self.store_dir = store_dir
        os.makedirs(store_dir, exist_ok=True)

    def write(self, signed_receipt: Dict[str, Any]) -> str:
        receipt_id = signed_receipt.get("receipt", {}).get("id", signed_receipt.get("id", "unknown"))
        filepath = os.path.join(self.store_dir, f"{receipt_id}.json")
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(signed_receipt, f, indent=2)
        return filepath

    def read(self, receipt_id: str) -> Optional[Dict[str, Any]]:
        filepath = os.path.join(self.store_dir, f"{receipt_id}.json")
        if not os.path.exists(filepath):
            return None
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def iter_all(self) -> List[Dict[str, Any]]:
        results = []
        if not os.path.exists(self.store_dir):
            return results
        for filename in sorted(os.listdir(self.store_dir)):
            if filename.endswith(".json"):
                filepath = os.path.join(self.store_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        results.append(json.load(f))
                except Exception:
                    pass
        return results
