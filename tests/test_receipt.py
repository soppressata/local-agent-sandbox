"""
Tests for the signed run-receipt ledger: Ed25519 signing and verification,
the versioned JSONL store, and the SBOM-style audit export.
"""

import json

import pytest

from local_agent_sandbox.receipt import (
    EnforcementSummary,
    NodeInfo,
    PolicyCheck,
    Receipt,
    ReceiptStore,
    SignedReceipt,
    generate_keypair,
    get_or_create_signing_key,
    key_id_from_public,
    receipt_to_sbom,
    sign_receipt,
    verify_receipt,
)


def _make_receipt(receipt_id="receipt-1", image="echo hi", exit_code=0, **overrides):
    kwargs = dict(
        id=receipt_id,
        trustfile="deadbeef",
        trustfile_name="build-tool",
        image=image,
        command=image,
        node=NodeInfo(
            id="local-host",
            hostname="host",
            platform="Linux 6.8.0",
            backend="local-agent-sandbox",
            cpu_cores=4,
            mem_mb=8000,
        ),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        duration_ms=12.5,
        exit_code=exit_code,
        enforcement=EnforcementSummary(
            checks=[
                PolicyCheck(name="resources", applied=True, ok=True, detail="ok"),
                PolicyCheck(name="network", applied=True, ok=True, detail="ok"),
            ],
            fully_enforced=True,
        ),
        mounts=[],
        stdout="hello",
        stderr="",
    )
    kwargs.update(overrides)
    return Receipt(**kwargs)


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def test_sign_and_verify_receipt():
    private_key, public_key = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    assert signed.key_id == key_id_from_public(public_key)
    assert verify_receipt(signed, public_key) is True


def test_verify_rejects_wrong_key():
    private_key, _ = generate_keypair()
    _, other_public = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    assert verify_receipt(signed, other_public) is False


def test_verify_rejects_tampered_receipt():
    private_key, public_key = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    tampered = signed.model_copy(deep=True)
    tampered.receipt.exit_code = 1
    assert verify_receipt(tampered, public_key) is False


def test_verify_rejects_tampered_signature():
    private_key, public_key = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    tampered = signed.model_copy(deep=True)
    tampered.signature = "AAAA" * 16
    assert verify_receipt(tampered, public_key) is False


def test_verify_rejects_key_id_mismatch():
    private_key, _ = generate_keypair()
    _, other_public = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    forged = signed.model_copy(deep=True)
    forged.key_id = key_id_from_public(other_public)
    assert verify_receipt(forged, other_public) is False


def test_round_trip_is_deterministic():
    private_key, public_key = generate_keypair()
    first = sign_receipt(_make_receipt(), private_key)
    second = sign_receipt(_make_receipt(), private_key)
    assert first.signature == second.signature
    assert first.key_id == second.key_id


# ---------------------------------------------------------------------------
# Signing key management
# ---------------------------------------------------------------------------


def test_get_or_create_signing_key_persists(tmp_path):
    private_a, public_a, key_id_a = get_or_create_signing_key(str(tmp_path))
    private_b, public_b, key_id_b = get_or_create_signing_key(str(tmp_path))
    assert private_a == private_b
    assert public_a == public_b
    assert key_id_a == key_id_b


# ---------------------------------------------------------------------------
# JSONL store
# ---------------------------------------------------------------------------


def test_store_write_and_read_round_trip(tmp_path):
    private_key, _ = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    store = ReceiptStore(str(tmp_path))
    path = store.write(signed)
    assert path.endswith("/v1/receipt-1.jsonl")
    assert store.read("receipt-1") == signed
    assert store.read("missing-id") is None


def test_store_keeps_single_line_jsonl_per_receipt(tmp_path):
    private_key, _ = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    store = ReceiptStore(str(tmp_path))
    store.write(signed)
    path = store.path_for("receipt-1")
    with open(path, encoding="utf-8") as handle:
        lines = [line for line in handle if line.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["key_id"] == signed.key_id


def test_store_iter_all_oldest_first(tmp_path):
    private_key, _ = generate_keypair()
    store = ReceiptStore(str(tmp_path))
    store.write(sign_receipt(_make_receipt("aaa"), private_key))
    store.write(sign_receipt(_make_receipt("bbb"), private_key))
    store.write(sign_receipt(_make_receipt("ccc"), private_key))
    assert [s.receipt.id for s in store.iter_all()] == ["aaa", "bbb", "ccc"]


def test_store_accepts_appended_entries(tmp_path):
    private_key, _ = generate_keypair()
    store = ReceiptStore(str(tmp_path))
    store.write(sign_receipt(_make_receipt("aaa"), private_key))
    store.write(sign_receipt(_make_receipt("aaa", image="second"), private_key))
    assert len(list(store.iter_all())) == 2


# ---------------------------------------------------------------------------
# SBOM-style export
# ---------------------------------------------------------------------------


def test_receipt_to_sbom_structure(tmp_path):
    private_key, public_key = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    sbom = receipt_to_sbom(signed, signature_valid=verify_receipt(signed, public_key))
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"] == "urn:uuid:receipt-1"
    assert sbom["components"][0]["name"] == "echo hi"
    names = {prop["name"] for prop in sbom["properties"]}
    assert "sandboxctl:receipt_id" in names
    assert "sandboxctl:fully_enforced" in names
    assert "sandboxctl:signature_valid" in names
    assert next(
        p for p in sbom["properties"] if p["name"] == "sandboxctl:signature_valid"
    )["value"] == "true"
    check_props = {p["name"] for p in sbom["properties"]}
    assert "sandboxctl:check:resources" in check_props
    assert "sandboxctl:check:network" in check_props


def test_receipt_to_sbom_includes_mounts(tmp_path):
    private_key, _ = generate_keypair()
    signed = sign_receipt(
        _make_receipt(
            mounts=[
                {
                    "host_path": "/tmp/src",
                    "container_path": "/src",
                    "mode": "read-only",
                    "ok": True,
                    "detail": "",
                }
            ]
        ),
        private_key,
    )
    sbom = receipt_to_sbom(signed)
    file_components = [c for c in sbom["components"] if c["type"] == "file"]
    assert file_components and file_components[0]["bom-ref"] == "mount:/tmp/src"


# ---------------------------------------------------------------------------
# Model validation
# ---------------------------------------------------------------------------


def test_signed_receipt_round_trips_through_json():
    private_key, _ = generate_keypair()
    signed = sign_receipt(_make_receipt(), private_key)
    data = json.loads(signed.model_dump_json())
    data["surprise"] = 1
    reparsed = SignedReceipt.model_validate(data)
    assert reparsed == signed


def test_receipt_requires_mandatory_fields():
    with pytest.raises(Exception):
        Receipt.model_validate({})
