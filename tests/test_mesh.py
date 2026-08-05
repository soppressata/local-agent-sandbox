"""
Unit tests for Zero-Trust Mesh Networking & mTLS Certificate Negotiation (AC2).
"""

import pytest
from local_agent_sandbox.orchestrator import UniverseOrchestrator, UniverseStatus
from local_agent_sandbox.mesh import (
    CertificateAuthority,
    MeshNetworkManager,
    TrustPolicy,
    TrustRule,
    TrustAction,
    TrustDecision,
)


def test_certificate_authority_generation_and_verification():
    ca = CertificateAuthority(common_name="Test CA")
    key_pem, cert_pem = ca.generate_universe_certificate("uv-12345")

    assert b"BEGIN PRIVATE KEY" in key_pem
    assert b"BEGIN CERTIFICATE" in cert_pem

    assert ca.verify_certificate(cert_pem) is True


def test_trust_policy_evaluation():
    policy = TrustPolicy(default_decision=TrustDecision.DENY)
    policy.add_rule(
        TrustRule(
            rule_id="allow-rpc-between-uv1-uv2",
            source_selector="uv-00001",
            target_selector="uv-00002",
            allowed_actions={TrustAction.RPC_CALL, TrustAction.FILE_TRANSFER},
            decision=TrustDecision.ALLOW,
        )
    )

    assert policy.evaluate("uv-00001", "uv-00002", TrustAction.RPC_CALL) == TrustDecision.ALLOW
    assert policy.evaluate("uv-00001", "uv-00002", TrustAction.WASM_INVOKE) == TrustDecision.DENY
    assert policy.evaluate("uv-00001", "uv-00003", TrustAction.RPC_CALL) == TrustDecision.DENY


def test_mtls_mesh_channel_negotiation_and_encrypted_transmission():
    orchestrator = UniverseOrchestrator()
    mesh = MeshNetworkManager()

    u1 = orchestrator.create_universe(name="agent-alpha")
    u2 = orchestrator.create_universe(name="agent-beta")

    channel = mesh.negotiate_channel(u1, u2, action=TrustAction.RPC_CALL)
    assert channel is not None
    assert channel.is_active is True
    assert u1.status == UniverseStatus.MESHED
    assert u2.status == UniverseStatus.MESHED

    secret_message = "AGENT_DIRECTIVE: INITIATE_TASK_ALPHA"
    packet = mesh.transmit(u1, u2, secret_message)

    assert packet is not None
    assert packet.encrypted is True
    assert packet.payload_bytes == len(secret_message)
    assert u1.network.rx_bytes == len(secret_message)

    topo = mesh.get_mesh_topology()
    assert topo["node_count"] >= 2
    assert topo["link_count"] >= 1

    orchestrator.close()
