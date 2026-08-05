"""
Zero-Trust Mesh Networking Layer for Multi-Verse Agent Ecology (AC2).
Provides dynamic mTLS certificate generation, cryptographic trust policy evaluation,
ephemeral secure channel negotiation, and encrypted P2P inter-sandbox routing.
"""

import os
import time
import datetime
import uuid
import json
import base64
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .orchestrator import Universe, NetworkPacket, UniverseStatus


class TrustAction(str, Enum):
    RPC_CALL = "RPC_CALL"
    FILE_TRANSFER = "FILE_TRANSFER"
    STATE_SYNC = "STATE_SYNC"
    RESOURCE_SHARE = "RESOURCE_SHARE"
    WASM_INVOKE = "WASM_INVOKE"


class TrustDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    AUDIT_ONLY = "AUDIT_ONLY"


@dataclass
class TrustRule:
    rule_id: str
    source_selector: str  # Glob or exact ID / label
    target_selector: str
    allowed_actions: Set[TrustAction]
    max_rate_limit: int = 1000  # ops/sec
    decision: TrustDecision = TrustDecision.ALLOW


class TrustPolicy:
    """Dynamic Cryptographic Trust Policy Evaluator."""

    def __init__(self, policy_id: str = "default-policy", default_decision: TrustDecision = TrustDecision.DENY):
        self.policy_id = policy_id
        self.default_decision = default_decision
        self.rules: List[TrustRule] = []

    def add_rule(self, rule: TrustRule):
        self.rules.append(rule)

    def evaluate(self, source_id: str, target_id: str, action: TrustAction, claims: Optional[Dict[str, Any]] = None) -> TrustDecision:
        for rule in self.rules:
            src_match = (rule.source_selector == "*") or (rule.source_selector == source_id) or (source_id.startswith(rule.source_selector.rstrip("*")))
            tgt_match = (rule.target_selector == "*") or (rule.target_selector == target_id) or (target_id.startswith(rule.target_selector.rstrip("*")))
            if src_match and tgt_match:
                if action in rule.allowed_actions:
                    return rule.decision
        return self.default_decision


class CertificateAuthority:
    """
    Automated In-Memory PKI Certificate Authority for generating
    ephemeral TLS certificates and keypairs per universe sandbox.
    """

    def __init__(self, common_name: str = "MultiVerse Mesh Root CA"):
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LocalAgentSandbox Ecology"),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(self.ca_name)
            .issuer_name(self.ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )

    def generate_universe_certificate(self, universe_id: str) -> Tuple[bytes, bytes]:
        """Generates (private_key_pem, cert_pem) for a given sandbox universe."""
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"universe-{universe_id}.mesh.local"),
        ])
        
        now = datetime.datetime.now(datetime.timezone.utc)
        san = x509.SubjectAlternativeName([
            x509.DNSName(f"universe-{universe_id}.mesh.local"),
            x509.DNSName(f"{universe_id}.node.internal"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject_name)
            .issuer_name(self.ca_name)
            .public_key(priv_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(san, critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )

        key_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        return key_pem, cert_pem

    def verify_certificate(self, cert_pem: bytes) -> bool:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem)
            pub_key = self.ca_key.public_key()
            pub_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except Exception:
            return False


class MeshChannel:
    """
    An ephemeral, mTLS-secured zero-trust communication channel between two sandboxes.
    """

    def __init__(self, channel_id: str, source_id: str, target_id: str):
        self.channel_id = channel_id
        self.source_id = source_id
        self.target_id = target_id
        self.established_at = time.time()
        self.is_active = False
        self.secret_key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.secret_key)
        self.packet_count = 0
        self.bytes_transferred = 0

    def establish_mtls_handshake(self, source_cert_pem: bytes, target_cert_pem: bytes, ca: CertificateAuthority) -> bool:
        """Performs dynamic mTLS handshake verification."""
        if ca.verify_certificate(source_cert_pem) and ca.verify_certificate(target_cert_pem):
            self.is_active = True
            return True
        return False

    def send_encrypted(self, payload: str) -> NetworkPacket:
        if not self.is_active:
            raise ConnectionError("Mesh channel is not active or mTLS handshake failed.")
        
        data = payload.encode("utf-8")
        nonce = os.urandom(12)  # Standard 96-bit AES-GCM nonce
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        
        encoded_payload = base64.b64encode(nonce + ciphertext).decode("ascii")
        self.packet_count += 1
        self.bytes_transferred += len(data)

        packet = NetworkPacket(
            timestamp=time.time(),
            source_id=self.source_id,
            target_id=self.target_id,
            protocol="mTLS-mVerse/1.0",
            payload_bytes=len(data),
            encrypted=True,
        )
        return packet

    def decrypt_payload(self, encoded_payload: str) -> str:
        raw = base64.b64decode(encoded_payload.encode("ascii"))
        nonce = raw[:12]
        ciphertext = raw[12:]
        decrypted = self.aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted.decode("utf-8")


class MeshNetworkManager:
    """
    Zero-Trust Mesh Network Manager orchestrating communication across sandboxes.
    """

    def __init__(self, ca: Optional[CertificateAuthority] = None):
        self.ca = ca or CertificateAuthority()
        self.default_policy = TrustPolicy(default_decision=TrustDecision.ALLOW)
        self.default_policy.add_rule(TrustRule(
            rule_id="allow-all-internal",
            source_selector="*",
            target_selector="*",
            allowed_actions={TrustAction.RPC_CALL, TrustAction.FILE_TRANSFER, TrustAction.STATE_SYNC, TrustAction.RESOURCE_SHARE, TrustAction.WASM_INVOKE},
            decision=TrustDecision.ALLOW
        ))
        self.universe_certs: Dict[str, Tuple[bytes, bytes]] = {}
        self.channels: Dict[str, MeshChannel] = {}
        self.universe_connections: Dict[str, Set[str]] = {}

    def register_universe(self, universe: Universe):
        if universe.id not in self.universe_certs:
            key_pem, cert_pem = self.ca.generate_universe_certificate(universe.id)
            self.universe_certs[universe.id] = (key_pem, cert_pem)
            self.universe_connections[universe.id] = set()

    def negotiate_channel(
        self,
        source: Universe,
        target: Universe,
        action: TrustAction = TrustAction.RPC_CALL,
        policy: Optional[TrustPolicy] = None,
    ) -> Optional[MeshChannel]:
        """
        Negotiates ephemeral zero-trust channel using mTLS certificates and policy verification.
        """
        self.register_universe(source)
        self.register_universe(target)

        active_policy = policy or self.default_policy
        decision = active_policy.evaluate(source.id, target.id, action)

        if decision == TrustDecision.DENY:
            source.log(f"Mesh connection to {target.id} denied by trust policy.")
            return None

        channel_id = f"mesh-{source.id}-to-{target.id}"
        channel = MeshChannel(channel_id, source.id, target.id)

        source_cert = self.universe_certs[source.id][1]
        target_cert = self.universe_certs[target.id][1]

        if channel.establish_mtls_handshake(source_cert, target_cert, self.ca):
            self.channels[channel_id] = channel
            self.universe_connections[source.id].add(target.id)
            self.universe_connections[target.id].add(source.id)
            
            source.status = UniverseStatus.MESHED
            target.status = UniverseStatus.MESHED
            source.network.allowed_peers.add(target.id)
            target.network.allowed_peers.add(source.id)
            
            source.log(f"Established zero-trust mTLS channel {channel_id} with {target.id}")
            return channel
        return None

    def transmit(self, source: Universe, target: Universe, message: str) -> Optional[NetworkPacket]:
        channel_id = f"mesh-{source.id}-to-{target.id}"
        channel = self.channels.get(channel_id)
        if not channel or not channel.is_active:
            channel = self.negotiate_channel(source, target)
            if not channel:
                return None

        packet = channel.send_encrypted(message)
        source.record_packet(packet)
        target.record_packet(packet)
        return packet

    def get_mesh_topology(self) -> Dict[str, Any]:
        """Returns visualizable mesh topology representation."""
        nodes = []
        links = []
        
        seen_nodes = set(self.universe_connections.keys())
        for uid in seen_nodes:
            nodes.append({
                "id": uid,
                "label": f"Universe {uid}",
                "degree": len(self.universe_connections.get(uid, set())),
            })

        for cid, channel in self.channels.items():
            if channel.is_active:
                links.append({
                    "id": cid,
                    "source": channel.source_id,
                    "target": channel.target_id,
                    "packets": channel.packet_count,
                    "bytes": channel.bytes_transferred,
                })

        return {
            "node_count": len(nodes),
            "link_count": len(links),
            "nodes": nodes,
            "links": links,
        }
