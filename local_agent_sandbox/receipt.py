"""
Run-receipt ledger.

Every ``sandboxctl run`` produces a machine-readable :class:`Receipt` describing
what ran, under which trustfile profile, on which node, and whether the profile
was fully enforced. Receipts are signed with the node's Ed25519 key and appended
to a versioned JSONL store (``<root>/v1/<id>.jsonl``), and can be exported as an
SBOM-style document for audit.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any, Dict, Iterator, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import NoEncryption
from pydantic import BaseModel, Field

STORE_SCHEMA_VERSION = "1.0"
"""Schema version of the receipt envelope and store layout."""


class PolicyCheck(BaseModel):
    """Outcome of a single profile-enforcement check."""

    name: str
    applied: bool
    ok: bool
    detail: str = ""


class EnforcementSummary(BaseModel):
    """Aggregate enforcement outcome for a run."""

    checks: List[PolicyCheck] = Field(default_factory=list)
    fully_enforced: bool = False


class NodeInfo(BaseModel):
    """Descriptor of the node a workload ran on."""

    id: str
    hostname: str
    platform: str
    backend: str
    cpu_cores: int
    mem_mb: int


class Receipt(BaseModel):
    """Machine-readable record of a single sandboxctl run."""

    schema_version: str = STORE_SCHEMA_VERSION
    id: str
    trustfile: str
    trustfile_name: str
    image: str
    command: str
    node: NodeInfo
    started_at: str
    finished_at: str
    duration_ms: float
    exit_code: int
    blocked: bool = False
    block_reason: Optional[str] = None
    enforcement: EnforcementSummary
    mounts: List[Dict[str, Any]] = Field(default_factory=list)
    stdout: str = ""
    stderr: str = ""


class SignedReceipt(BaseModel):
    """A receipt wrapped in its Ed25519 signature envelope."""

    schema_version: str = STORE_SCHEMA_VERSION
    receipt: Receipt
    signature: str
    key_id: str


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


def default_keys_dir() -> str:
    """Default directory holding the node's Ed25519 signing keypair."""
    return os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
        "local-agent-sandbox",
        "keys",
    )


def default_store_dir() -> str:
    """Default root of the receipt store."""
    return os.path.join(
        os.environ.get("XDG_DATA_HOME", os.path.expanduser("~/.local/share")),
        "local-agent-sandbox",
        "receipts",
    )


def key_id_from_public(public_key_bytes: bytes) -> str:
    """Return a short fingerprint identifying an Ed25519 public key."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


def generate_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair as raw private and public bytes."""
    private_key = Ed25519PrivateKey.generate()
    return private_key.private_bytes_raw(), private_key.public_key().public_bytes_raw()


def get_or_create_signing_key(keys_dir: Optional[str] = None) -> Tuple[bytes, bytes, str]:
    """Load (or create, on first use) the node signing keypair.

    Returns ``(private_key_bytes, public_key_bytes, key_id)``.
    """
    keys_dir = keys_dir or default_keys_dir()
    os.makedirs(keys_dir, exist_ok=True)
    private_path = os.path.join(keys_dir, "ed25519_private.pem")
    public_path = os.path.join(keys_dir, "ed25519_public.pem")

    if os.path.exists(private_path):
        with open(private_path, "rb") as handle:
            private_key = serialization.load_pem_private_key(handle.read(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        with open(private_path, "wb") as handle:
            handle.write(
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    NoEncryption(),
                )
            )
        with open(public_path, "wb") as handle:
            handle.write(
                private_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )

    private_bytes = private_key.private_bytes_raw()
    public_bytes = private_key.public_key().public_bytes_raw()
    return private_bytes, public_bytes, key_id_from_public(public_bytes)


def load_public_key(path: str) -> bytes:
    """Load an Ed25519 public key (PEM, raw or base64) as raw 32 bytes."""
    with open(path, "rb") as handle:
        data = handle.read()
    try:
        public_key = serialization.load_pem_public_key(data)
        return public_key.public_bytes_raw()
    except (ValueError, TypeError, UnsupportedAlgorithm):
        pass
    try:
        return base64.b64decode(data.strip())
    except Exception:  # noqa: BLE001 - fall through to raw byte check
        pass
    if len(data) == 32:
        return data
    raise ValueError(f"unable to parse public key at {path}")


# ---------------------------------------------------------------------------
# Signing / verification
# ---------------------------------------------------------------------------


def canonical_receipt_bytes(receipt: Receipt) -> bytes:
    """Canonical UTF-8 bytes over which a receipt signature is computed."""
    return json.dumps(
        receipt.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sign_receipt(receipt: Receipt, private_key_bytes: bytes) -> SignedReceipt:
    """Sign a receipt with an Ed25519 private key and wrap it in an envelope."""
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    public_bytes = private_key.public_key().public_bytes_raw()
    signature = private_key.sign(canonical_receipt_bytes(receipt))
    return SignedReceipt(
        receipt=receipt,
        signature=base64.b64encode(signature).decode("ascii"),
        key_id=key_id_from_public(public_bytes),
    )


def verify_receipt(signed: SignedReceipt, public_key_bytes: bytes) -> bool:
    """Verify a signed receipt against an Ed25519 public key.

    Also asserts that the envelope's ``key_id`` matches the key fingerprint.
    """
    if signed.key_id != key_id_from_public(public_key_bytes):
        return False
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(
            base64.b64decode(signed.signature),
            canonical_receipt_bytes(signed.receipt),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


# ---------------------------------------------------------------------------
# JSONL store
# ---------------------------------------------------------------------------


class ReceiptStore:
    """Append-only, versioned JSONL store of signed receipts.

    Layout: ``<root>/v1/<receipt_id>.jsonl``. Each line is one
    :class:`SignedReceipt` envelope; a run id maps to a single line.
    """

    def __init__(self, root_dir: Optional[str] = None) -> None:
        self.root = root_dir or default_store_dir()
        self.version_dir = os.path.join(
            self.root, "v" + STORE_SCHEMA_VERSION.split(".")[0]
        )

    def path_for(self, receipt_id: str) -> str:
        """Return the on-disk path for a receipt id."""
        return os.path.join(self.version_dir, f"{receipt_id}.jsonl")

    def write(self, signed: SignedReceipt) -> str:
        """Append a signed receipt to the store and return its path."""
        os.makedirs(self.version_dir, exist_ok=True)
        path = self.path_for(signed.receipt.id)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(signed.model_dump(mode="json"), separators=(",", ":")) + "\n"
            )
        return path

    def read(self, receipt_id: str) -> Optional[SignedReceipt]:
        """Return the stored signed receipt for ``receipt_id``, if any."""
        path = self.path_for(receipt_id)
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    return SignedReceipt.model_validate(json.loads(line))
        return None

    def iter_all(self) -> Iterator[SignedReceipt]:
        """Yield every signed receipt in the store, oldest first."""
        if not os.path.isdir(self.version_dir):
            return
        for name in sorted(os.listdir(self.version_dir)):
            if not name.endswith(".jsonl"):
                continue
            with open(os.path.join(self.version_dir, name), "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        yield SignedReceipt.model_validate(json.loads(line))


# ---------------------------------------------------------------------------
# SBOM-style audit export
# ---------------------------------------------------------------------------


def receipt_to_sbom(
    signed: SignedReceipt,
    signature_valid: Optional[bool] = None,
) -> Dict[str, Any]:
    """Export a receipt as an SBOM-style (CycloneDX 1.5) audit document."""
    receipt = signed.receipt
    components: List[Dict[str, Any]] = [
        {
            "type": "application",
            "bom-ref": f"image:{receipt.image}",
            "name": receipt.image,
            "version": receipt.trustfile,
            "purl": f"pkg:generic/{receipt.image}",
        }
    ]
    for mount in receipt.mounts:
        components.append(
            {
                "type": "file",
                "bom-ref": f"mount:{mount.get('host_path', '')}",
                "name": mount.get("host_path", ""),
                "properties": [
                    {"name": "container_path", "value": str(mount.get("container_path", ""))},
                    {"name": "mode", "value": str(mount.get("mode", ""))},
                ],
            }
        )

    properties: List[Dict[str, str]] = [
        {"name": "sandboxctl:receipt_id", "value": receipt.id},
        {"name": "sandboxctl:trustfile_name", "value": receipt.trustfile_name},
        {"name": "sandboxctl:trustfile_digest", "value": receipt.trustfile},
        {"name": "sandboxctl:node_id", "value": receipt.node.id},
        {"name": "sandboxctl:backend", "value": receipt.node.backend},
        {"name": "sandboxctl:fully_enforced", "value": str(receipt.enforcement.fully_enforced).lower()},
        {"name": "sandboxctl:exit_code", "value": str(receipt.exit_code)},
        {"name": "sandboxctl:duration_ms", "value": f"{receipt.duration_ms:.1f}"},
        {"name": "sandboxctl:key_id", "value": signed.key_id},
    ]
    for check in receipt.enforcement.checks:
        properties.append(
            {
                "name": f"sandboxctl:check:{check.name}",
                "value": f"applied={check.applied} ok={check.ok} {check.detail}",
            }
        )
    if signature_valid is not None:
        properties.append(
            {"name": "sandboxctl:signature_valid", "value": str(signature_valid).lower()}
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{receipt.id}",
        "version": 1,
        "metadata": {
            "timestamp": receipt.finished_at,
            "tools": [
                {
                    "vendor": "OpenHarness",
                    "name": "local-agent-sandbox",
                    "version": STORE_SCHEMA_VERSION,
                }
            ],
            "component": {
                "type": "application",
                "name": receipt.image,
                "version": receipt.trustfile_name,
            },
        },
        "components": components,
        "properties": properties,
    }
