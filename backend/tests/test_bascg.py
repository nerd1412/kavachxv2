"""
BASCG Test Suite
================
Unit tests for all BASCG Phase 1–3 modules.

Run with:
    cd backend
    pytest tests/test_bascg.py -v

No network access required — all tests use mock/local implementations.
"""
import asyncio
import base64
import hashlib
import json
import sys
import pytest

# ══════════════════════════════════════════════════════════════════════════════
#  P0 Stage 1 — MerkleTree
# ══════════════════════════════════════════════════════════════════════════════

def _hex_leaf(s: str) -> str:
    """Produce a valid 64-char hex string from a plain string (for MerkleTree inputs)."""
    return hashlib.sha256(s.encode()).hexdigest()


class TestMerkleTree:
    def _tree(self, plain_labels):
        """Build a MerkleTree from plain strings by converting to hex chain_hashes."""
        from app.services.sovereign_ledger_sync import MerkleTree
        return MerkleTree([_hex_leaf(l) for l in plain_labels])

    def test_single_leaf_root(self):
        # MerkleTree(chain_hashes) — leaf node = SHA256(bytes.fromhex(chain_hash))
        chain_hash = _hex_leaf("abc")
        from app.services.sovereign_ledger_sync import MerkleTree
        tree = MerkleTree([chain_hash])
        expected = hashlib.sha256(bytes.fromhex(chain_hash)).hexdigest()
        assert tree.root == expected

    def test_two_leaves_root(self):
        # Internal node = SHA256(bytes(left_leaf) || bytes(right_leaf))
        from app.services.sovereign_ledger_sync import MerkleTree
        ch_a = _hex_leaf("a")
        ch_b = _hex_leaf("b")
        tree = MerkleTree([ch_a, ch_b])
        ha = hashlib.sha256(bytes.fromhex(ch_a)).hexdigest()
        hb = hashlib.sha256(bytes.fromhex(ch_b)).hexdigest()
        # Concatenate raw bytes, not encoded strings
        combined = hashlib.sha256(bytes.fromhex(ha) + bytes.fromhex(hb)).hexdigest()
        assert tree.root == combined

    def test_odd_leaf_count_pads_last(self):
        tree = self._tree(["a", "b", "c"])
        assert tree.root is not None and len(tree.root) == 64

    def test_proof_verification_passes(self):
        from app.services.sovereign_ledger_sync import MerkleTree
        chain_hashes = [_hex_leaf(f"x{i}") for i in range(4)]
        tree = MerkleTree(chain_hashes)
        for i, ch in enumerate(chain_hashes):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(ch, proof, tree.root), \
                f"Proof failed for leaf index {i}"

    def test_tampered_leaf_fails_verification(self):
        from app.services.sovereign_ledger_sync import MerkleTree
        chain_hashes = [_hex_leaf(f"n{i}") for i in range(4)]
        tree = MerkleTree(chain_hashes)
        proof = tree.get_proof(0)
        tampered = _hex_leaf("tampered_value")
        assert not MerkleTree.verify_proof(tampered, proof, tree.root)

    def test_to_dict_contains_root_and_leaves(self):
        tree = self._tree(["p", "q"])
        d = tree.to_dict()
        assert d["root"] == tree.root
        assert d["leaf_count"] == 2
        assert "leaves" in d
        assert "levels" in d

    def test_empty_leaf_list_raises(self):
        from app.services.sovereign_ledger_sync import MerkleTree
        with pytest.raises(Exception):
            MerkleTree([])

    def test_large_batch_produces_consistent_root(self):
        chain_hashes = [_hex_leaf(f"log_{i:04d}") for i in range(100)]
        from app.services.sovereign_ledger_sync import MerkleTree
        tree  = MerkleTree(chain_hashes)
        tree2 = MerkleTree(chain_hashes)
        assert tree.root == tree2.root  # deterministic

    def test_single_leaf_proof_verifies(self):
        from app.services.sovereign_ledger_sync import MerkleTree
        ch = _hex_leaf("only_leaf")
        tree = MerkleTree([ch])
        proof = tree.get_proof(0)
        assert MerkleTree.verify_proof(ch, proof, tree.root)


# ══════════════════════════════════════════════════════════════════════════════
#  P0 Stage 1 — MockTSAClient
# ══════════════════════════════════════════════════════════════════════════════

class TestMockTSAClient:
    @pytest.fixture
    def client(self):
        from app.services.sovereign_ledger_sync import MockTSAClient
        return MockTSAClient(secret_key="test-secret-key")

    @pytest.mark.asyncio
    async def test_returns_receipt(self, client):
        receipt = await client.timestamp(b"test_data")
        assert receipt.provider == "mock-local-tsa"
        assert receipt.verified is True
        assert len(receipt.token_b64) > 0
        assert len(receipt.serial) > 0

    @pytest.mark.asyncio
    async def test_token_is_valid_base64(self, client):
        receipt = await client.timestamp(b"hello")
        decoded = base64.b64decode(receipt.token_b64)
        body = json.loads(decoded)
        assert "signature" in body
        assert "message_imprint" in body

    @pytest.mark.asyncio
    async def test_verify_token_round_trip(self, client):
        receipt = await client.timestamp(b"round_trip")
        assert client.verify_token(receipt.token_b64) is True

    @pytest.mark.asyncio
    async def test_tampered_token_fails_verify(self, client):
        receipt = await client.timestamp(b"data")
        raw = base64.b64decode(receipt.token_b64)
        body = json.loads(raw)
        body["merkle_root_hex"] = "deadbeef" * 8  # tamper
        tampered = base64.b64encode(json.dumps(body).encode()).decode()
        assert client.verify_token(tampered) is False

    @pytest.mark.asyncio
    async def test_different_data_different_receipt(self, client):
        r1 = await client.timestamp(b"data_one")
        r2 = await client.timestamp(b"data_two")
        assert r1.message_imprint_sha256 != r2.message_imprint_sha256

    @pytest.mark.asyncio
    async def test_issued_at_is_iso8601(self, client):
        from datetime import datetime
        receipt = await client.timestamp(b"ts_test")
        # Should parse without error
        datetime.fromisoformat(receipt.issued_at)


# ══════════════════════════════════════════════════════════════════════════════
#  P0 Stage 2 — CryptoService (Ed25519 signing)
# ══════════════════════════════════════════════════════════════════════════════

class TestCryptoService:
    @pytest.fixture(autouse=True)
    def init_crypto(self):
        from app.core.crypto import crypto_service
        crypto_service.initialize()
        self.cs = crypto_service

    def test_sign_and_verify_round_trip(self):
        payload = {"model_id": "m-001", "sector": "finance", "risk": "HIGH"}
        sig = self.cs.signer.sign(payload)
        assert self.cs.verifier.verify(payload, sig, self.cs.signer.issuer) is True

    def test_tampered_payload_fails_verify(self):
        payload = {"key": "value"}
        sig = self.cs.signer.sign(payload)
        tampered = {"key": "different_value"}
        assert self.cs.verifier.verify(tampered, sig, self.cs.signer.issuer) is False

    def test_signature_is_base64(self):
        sig = self.cs.signer.sign({"a": 1})
        decoded = base64.b64decode(sig)
        assert len(decoded) == 64  # Ed25519 signature is always 64 bytes

    def test_canonical_json_is_deterministic(self):
        from app.core.crypto import canonical_json
        d1 = {"z": 1, "a": 2, "m": 3}
        d2 = {"m": 3, "z": 1, "a": 2}
        assert canonical_json(d1) == canonical_json(d2)

    def test_unknown_issuer_fails_verify(self):
        payload = {"x": 1}
        sig = self.cs.signer.sign(payload)
        assert self.cs.verifier.verify(payload, sig, "unknown-issuer") is False

    def test_generate_seed_b64_is_32_bytes(self):
        from app.core.crypto import generate_seed_b64
        seed_b64 = generate_seed_b64()
        raw = base64.b64decode(seed_b64)
        assert len(raw) == 32


# ══════════════════════════════════════════════════════════════════════════════
#  P0 Stage 2 — PolicyBundleService
# ══════════════════════════════════════════════════════════════════════════════

class TestPolicyBundleService:
    @pytest.fixture(autouse=True)
    def init(self):
        from app.core.crypto import crypto_service
        crypto_service.initialize()
        from app.services.policy_bundle_service import policy_bundle_service
        self.svc = policy_bundle_service

    def test_sign_and_verify_db_policy(self):
        payload = {
            "id": "test-001",
            "name": "Test Policy",
            "description": "Unit test",
            "policy_type": "safety",
            "severity": "high",
            "jurisdiction": "IN",
            "rules": [{"field": "risk_score", "operator": "gt", "value": 0.8, "action": "BLOCK"}],
        }
        sig = self.svc.sign_db_policy_payload(payload)
        assert sig is not None and len(sig) > 0

    def test_verify_db_policy_valid(self):
        from types import SimpleNamespace
        payload = {
            "id": "v-001", "name": "V", "description": "",
            "policy_type": "safety", "severity": "medium",
            "jurisdiction": "IN", "rules": [],
        }
        from app.core.crypto import crypto_service
        sig = self.svc.sign_db_policy_payload(payload)
        issuer = crypto_service.signer.issuer

        policy_obj = SimpleNamespace(
            id="v-001", name="V", description="",
            policy_type="safety", severity="medium",
            jurisdiction="IN", rules=[],
            policy_signature=sig, signed_by=issuer,
        )
        assert self.svc.verify_db_policy(policy_obj) is True

    def test_unsigned_policy_rejected(self):
        from types import SimpleNamespace
        policy_obj = SimpleNamespace(
            id="u-001", name="Unsigned",
            policy_signature=None, signed_by=None,
        )
        assert self.svc.verify_db_policy(policy_obj) is False

    def test_builtin_bundle_has_policies(self):
        bundle = self.svc.get_builtin_bundle()
        assert bundle.signature is not None
        assert len(bundle.policies) > 0
        assert self.svc.verify_bundle(bundle) is True


# ══════════════════════════════════════════════════════════════════════════════
#  P1 — NAELService
# ══════════════════════════════════════════════════════════════════════════════

class TestNAELToken:
    def test_token_round_trip(self):
        from app.services.nael_service import NAELToken, NAEL_ISS
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        tok = NAELToken(
            nael_version="1.0",
            license_id="lic-001",
            model_id="mod-001",
            model_sha256="abc" * 21 + "d",
            sector_restrictions=["finance", "healthcare"],
            risk_classification="HIGH",
            licensed_tee_platforms=["mock", "aws-nitro"],
            issued_by="dev-local",
            issued_at=now.isoformat(),
            valid_from=now.isoformat(),
            valid_until=(now + timedelta(days=365)).isoformat(),
            iss=NAEL_ISS,
        )
        assert tok.allows_sector("finance") is True
        assert tok.allows_sector("education") is False
        assert tok.allows_tee("aws-nitro") is True
        assert tok.allows_tee("intel-sgx") is False
        assert tok.is_expired is False
        assert tok.is_active is True

    def test_expired_token(self):
        from app.services.nael_service import NAELToken, NAEL_ISS
        from datetime import datetime, timezone, timedelta

        past = datetime.now(timezone.utc) - timedelta(days=1)
        tok = NAELToken(
            nael_version="1.0",
            license_id="lic-expired",
            model_id="m", model_sha256=None,
            sector_restrictions=[], risk_classification="LOW",
            licensed_tee_platforms=[], issued_by="dev",
            issued_at=past.isoformat(),
            valid_from=past.isoformat(),
            valid_until=past.isoformat(),  # already in the past
            iss=NAEL_ISS,
        )
        assert tok.is_expired is True
        # is_active checks valid_from has passed — True even for expired tokens
        # The correct validity check is: is_active and not is_expired
        assert not (tok.is_active and not tok.is_expired)


# ══════════════════════════════════════════════════════════════════════════════
#  P1 — TEE Attestation (Mock)
# ══════════════════════════════════════════════════════════════════════════════

class TestMockTEEAttestation:
    @pytest.fixture(autouse=True)
    def init(self):
        from app.core.crypto import crypto_service
        crypto_service.initialize()
        from app.services.tee_attestation_service import tee_attestation_service, MockTEEClient
        self.svc = tee_attestation_service
        self.mock_client = MockTEEClient()

    def test_generate_mock_document(self):
        # generate_mock_document is synchronous — returns base64 string
        nonce = self.svc.generate_nonce()
        doc_b64 = self.svc.generate_mock_document(nonce=nonce)
        assert isinstance(doc_b64, str)
        # decode and check structure
        raw = base64.b64decode(doc_b64)
        body = json.loads(raw)
        assert body["platform"] == "mock"
        assert body["nonce"] == nonce
        assert "pcrs" in body

    def test_mock_client_parse_and_verify(self):
        # Use MockTEEClient directly for sync verification (no DB needed)
        nonce = self.svc.generate_nonce()
        raw = self.mock_client.generate_document(nonce=nonce)
        doc = self.mock_client.parse_and_verify(raw)
        assert doc.platform == "mock"
        assert doc.nonce == nonce
        assert doc.pcr0 is not None

    def test_wrong_nonce_detected_by_client(self):
        # MockTEEClient.parse_and_verify raises on bad HMAC (corrupted nonce = bad sig)
        import json, base64
        raw = self.mock_client.generate_document(nonce="nonce-a")
        body = json.loads(raw)
        body["nonce"] = "nonce-b"          # tamper
        body.pop("signature", None)        # strip signature
        tampered = json.dumps(body).encode()
        with pytest.raises(Exception):
            self.mock_client.parse_and_verify(tampered)

    def test_nonce_is_unique(self):
        n1 = self.svc.generate_nonce()
        n2 = self.svc.generate_nonce()
        assert n1 != n2

    def test_mock_pcr0_is_expected_hash(self):
        from app.services.tee_attestation_service import MOCK_PCR0
        expected = hashlib.sha256(b"kavachx-governance-engine-v2.0").hexdigest()
        assert MOCK_PCR0 == expected

    def test_pcr0_in_generated_document_matches_mock_pcr0(self):
        from app.services.tee_attestation_service import MOCK_PCR0
        nonce = self.svc.generate_nonce()
        raw = self.mock_client.generate_document(nonce=nonce)
        doc = self.mock_client.parse_and_verify(raw)
        assert doc.pcr0 == MOCK_PCR0


# ══════════════════════════════════════════════════════════════════════════════
#  P3 — Synthetic Media Shield
# ══════════════════════════════════════════════════════════════════════════════

class TestMockMediaDetector:
    @pytest.fixture
    def detector(self):
        from app.services.synthetic_media_service import MockMediaDetector
        return MockMediaDetector()

    @pytest.mark.asyncio
    async def test_synthetic_test_vector(self, detector):
        result = await detector.detect(b"SYNTHETIC_TEST")
        assert result.is_synthetic is True
        assert result.confidence == 0.95
        assert len(result.labels) > 0

    @pytest.mark.asyncio
    async def test_real_test_vector(self, detector):
        result = await detector.detect(b"REAL_TEST")
        assert result.is_synthetic is False
        assert result.confidence == 0.05

    @pytest.mark.asyncio
    async def test_confidence_in_bounds(self, detector):
        import secrets
        for _ in range(20):
            result = await detector.detect(secrets.token_bytes(64))
            assert 0.0 <= result.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_detector_name_is_mock(self, detector):
        result = await detector.detect(b"SYNTHETIC_TEST")
        assert result.detector == "mock"

    @pytest.mark.asyncio
    async def test_same_input_produces_same_output(self, detector):
        content = b"deterministic_content_xyz"
        r1 = await detector.detect(content)
        r2 = await detector.detect(content)
        assert r1.confidence == r2.confidence
        assert r1.is_synthetic == r2.is_synthetic


class TestSyntheticMediaShieldService:
    @pytest.fixture(autouse=True)
    def setup(self):
        from app.services.synthetic_media_service import SyntheticMediaShieldService
        self.svc = SyntheticMediaShieldService()

    @pytest.mark.asyncio
    async def test_synthetic_content_returns_alert(self):
        result = await self.svc.scan(b"SYNTHETIC_TEST")
        assert result.enforcement_action in ("ALERT", "BLOCK", "ESCALATE")
        assert result.detection.is_synthetic is True

    @pytest.mark.asyncio
    async def test_real_content_passes(self):
        result = await self.svc.scan(b"REAL_TEST")
        assert result.enforcement_action == "PASS"
        assert result.detection.is_synthetic is False

    @pytest.mark.asyncio
    async def test_evidence_hash_matches_bundle(self):
        from app.services.synthetic_media_service import _hash_evidence
        result = await self.svc.scan(b"SYNTHETIC_TEST")
        recomputed = _hash_evidence(result.evidence_bundle)
        assert recomputed == result.evidence_hash

    @pytest.mark.asyncio
    async def test_content_hash_is_sha256(self):
        content = b"some_media_bytes"
        result = await self.svc.scan(content)
        expected = hashlib.sha256(content).hexdigest()
        assert result.content_hash == expected

    @pytest.mark.asyncio
    async def test_election_mode_escalates_synthetic(self, monkeypatch):
        """
        Election escalation requires synthetic content WITHOUT hard-block labels.
        SYNTHETIC_TEST returns labels like 'face_swap' which triggers BLOCK first.
        Use content that yields high confidence but no block-list labels.

        We test by mocking the detector directly on the service instance.
        """
        from app.core import config
        from app.services.synthetic_media_service import MockMediaDetector, DetectionResult
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_ENABLED", True)
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_STATE", "MH")
        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_CONFIDENCE_THRESHOLD", 0.65)

        # Mock detector returns high confidence synthetic content but NO block-list labels
        class ElectionMockDetector(MockMediaDetector):
            async def detect(self, content, content_type=None):
                return DetectionResult(
                    detector="mock",
                    is_synthetic=True,
                    confidence=0.90,
                    labels=["diffusion_generated"],  # not in _BLOCK_LABELS
                    raw_response=None,
                )

        # Patch _get_detector on the service instance
        self.svc._get_detector = lambda: ElectionMockDetector()

        result = await self.svc.scan(b"any_content")
        assert result.election_context is True
        assert result.enforcement_action == "ESCALATE"
        assert result.escalated_to_eci is True

    @pytest.mark.asyncio
    async def test_election_mode_inactive_for_real_content(self, monkeypatch):
        from app.core import config
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_ENABLED", True)
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_STATE", "KA")

        result = await self.svc.scan(b"REAL_TEST")
        # Real content never escalates
        assert result.enforcement_action == "PASS"
        assert result.escalated_to_eci is False

    @pytest.mark.asyncio
    async def test_scan_id_is_hex_string(self):
        result = await self.svc.scan(b"test")
        assert len(result.scan_id) == 32
        int(result.scan_id, 16)  # must be valid hex


# ══════════════════════════════════════════════════════════════════════════════
#  P2b — BlockchainTSAClient (no network — logic tests only)
# ══════════════════════════════════════════════════════════════════════════════

class TestBlockchainTSAClientLogic:
    def test_calldata_has_magic_prefix(self):
        from app.services.sovereign_ledger_sync import BlockchainTSAClient
        client = BlockchainTSAClient(
            rpc_url="http://localhost:8545",
            from_address="0x" + "0" * 40,
        )
        data = bytes.fromhex("a" * 64)
        calldata = "0x" + client._MAGIC.hex() + data.hex().zfill(64)
        assert calldata.startswith("0xba5c9a00")

    def test_magic_bytes_are_4_bytes(self):
        from app.services.sovereign_ledger_sync import BlockchainTSAClient
        assert len(BlockchainTSAClient._MAGIC) == 4

    @pytest.mark.asyncio
    async def test_wait_for_receipt_times_out(self):
        from app.services.sovereign_ledger_sync import BlockchainTSAClient
        client = BlockchainTSAClient(
            rpc_url="http://localhost:8545",
            from_address="0x" + "0" * 40,
            poll_interval=0.01,
            max_polls=2,
        )
        # Override _rpc to always return None (simulating unmined tx)
        async def mock_rpc(method, params):
            return None

        client._rpc = mock_rpc
        with pytest.raises(TimeoutError):
            await client._wait_for_receipt("0xdeadbeef")

    @pytest.mark.asyncio
    async def test_reverted_tx_raises(self):
        from app.services.sovereign_ledger_sync import BlockchainTSAClient
        client = BlockchainTSAClient(
            rpc_url="http://localhost:8545",
            from_address="0x" + "0" * 40,
        )
        async def mock_rpc(method, params):
            return {"status": "0x0", "blockNumber": "0x1", "blockHash": "0xabc"}

        client._rpc = mock_rpc
        with pytest.raises(RuntimeError, match="reverted"):
            await client._wait_for_receipt("0xbadtx")


# ══════════════════════════════════════════════════════════════════════════════
#  P1 — NAEL + Sovereign Ledger factory routing
# ══════════════════════════════════════════════════════════════════════════════

class TestTSAClientFactory:
    def test_mock_mode_returns_mock_client(self, monkeypatch):
        from app.core import config
        monkeypatch.setattr(config.settings, "SOVEREIGN_LEDGER_MODE", "mock")
        from app.services.sovereign_ledger_sync import (
            sovereign_ledger_sync, MockTSAClient,
        )
        client = sovereign_ledger_sync._get_tsa_client()
        assert isinstance(client, MockTSAClient)

    def test_rfc3161_mode_returns_rfc3161_client(self, monkeypatch):
        from app.core import config
        monkeypatch.setattr(config.settings, "SOVEREIGN_LEDGER_MODE", "rfc3161")
        from app.services.sovereign_ledger_sync import (
            sovereign_ledger_sync, RFC3161TSAClient,
        )
        client = sovereign_ledger_sync._get_tsa_client()
        assert isinstance(client, RFC3161TSAClient)

    def test_blockchain_mode_returns_blockchain_client(self, monkeypatch):
        from app.core import config
        monkeypatch.setattr(config.settings, "SOVEREIGN_LEDGER_MODE", "blockchain")
        from app.services.sovereign_ledger_sync import (
            sovereign_ledger_sync, BlockchainTSAClient,
        )
        client = sovereign_ledger_sync._get_tsa_client()
        assert isinstance(client, BlockchainTSAClient)

    def test_unknown_mode_falls_back_to_mock(self, monkeypatch):
        from app.core import config
        monkeypatch.setattr(config.settings, "SOVEREIGN_LEDGER_MODE", "nonexistent")
        from app.services.sovereign_ledger_sync import (
            sovereign_ledger_sync, MockTSAClient,
        )
        client = sovereign_ledger_sync._get_tsa_client()
        assert isinstance(client, MockTSAClient)


# ══════════════════════════════════════════════════════════════════════════════
#  T1-A — TEE Attestation Clearance Gate
# ══════════════════════════════════════════════════════════════════════════════

class TestTEEClearanceGate:
    """
    Tests for check_inference_clearance() — the TEE gate wired into
    governance_service.evaluate_inference().

    Uses an in-memory SQLite async session so no live DB is needed.
    """

    @pytest.fixture(autouse=True)
    def init_crypto(self):
        from app.core.crypto import crypto_service
        crypto_service.initialize()

    @pytest.fixture
    async def db(self):
        """Provide a real async SQLite session backed by an in-memory DB."""
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from app.db.database import Base
        import app.models.orm_models  # ensure all ORM models are registered before create_all  # noqa: F401

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            yield session
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_auto_attest_dev_grants_clearance(self, db, monkeypatch):
        """In development mode with auto-attest on, clearance is granted automatically."""
        from app.core import config
        monkeypatch.setattr(config.settings, "TEE_AUTO_ATTEST_DEV", True)
        monkeypatch.setattr(config.settings, "ENVIRONMENT", "development")
        monkeypatch.setattr(config.settings, "TEE_ENFORCEMENT_ENABLED", False)

        from app.services.tee_attestation_service import tee_attestation_service
        result = await tee_attestation_service.check_inference_clearance(
            db=db, model_id="model-test-001"
        )
        assert result.valid is True
        assert result.action == "pass"
        assert result.platform == "mock"
        assert result.pcr0_match is True

    @pytest.mark.asyncio
    async def test_no_clearance_soft_enforcement_gives_alert(self, db, monkeypatch):
        """No clearance + TEE_ENFORCEMENT_ENABLED=False → alert, not block."""
        from app.core import config
        monkeypatch.setattr(config.settings, "TEE_AUTO_ATTEST_DEV", False)
        monkeypatch.setattr(config.settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(config.settings, "TEE_ENFORCEMENT_ENABLED", False)

        from app.services.tee_attestation_service import tee_attestation_service
        result = await tee_attestation_service.check_inference_clearance(
            db=db, model_id="model-no-clearance"
        )
        assert result.valid is False
        assert result.action == "alert"

    @pytest.mark.asyncio
    async def test_no_clearance_hard_enforcement_gives_block(self, db, monkeypatch):
        """No clearance + TEE_ENFORCEMENT_ENABLED=True → block."""
        from app.core import config
        monkeypatch.setattr(config.settings, "TEE_AUTO_ATTEST_DEV", False)
        monkeypatch.setattr(config.settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(config.settings, "TEE_ENFORCEMENT_ENABLED", True)

        from app.services.tee_attestation_service import tee_attestation_service
        result = await tee_attestation_service.check_inference_clearance(
            db=db, model_id="model-no-clearance"
        )
        assert result.valid is False
        assert result.action == "block"

    @pytest.mark.asyncio
    async def test_existing_valid_clearance_reused(self, db, monkeypatch):
        """A live AttestationReport with future clearance_valid_until is reused."""
        from app.core import config
        monkeypatch.setattr(config.settings, "TEE_AUTO_ATTEST_DEV", False)
        monkeypatch.setattr(config.settings, "ENVIRONMENT", "production")
        monkeypatch.setattr(config.settings, "TEE_ENFORCEMENT_ENABLED", True)

        from app.models.orm_models import AttestationReport
        from datetime import datetime, timezone, timedelta

        model_id = "model-pre-attested"
        report = AttestationReport(
            platform              = "mock",
            model_id              = model_id,
            verified              = True,
            pcr0_match            = True,
            nael_valid            = False,
            clearance_valid_until = datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add(report)
        await db.commit()

        from app.services.tee_attestation_service import tee_attestation_service
        result = await tee_attestation_service.check_inference_clearance(
            db=db, model_id=model_id
        )
        assert result.valid is True
        assert result.action == "pass"
        assert result.report_id == report.id

    @pytest.mark.asyncio
    async def test_expired_clearance_triggers_re_attest_in_dev(self, db, monkeypatch):
        """An expired clearance in dev mode triggers auto-re-attestation."""
        from app.core import config
        monkeypatch.setattr(config.settings, "TEE_AUTO_ATTEST_DEV", True)
        monkeypatch.setattr(config.settings, "ENVIRONMENT", "development")

        from app.models.orm_models import AttestationReport
        from datetime import datetime, timezone, timedelta

        model_id = "model-expired"
        expired = AttestationReport(
            platform              = "mock",
            model_id              = model_id,
            verified              = True,
            pcr0_match            = True,
            nael_valid            = False,
            # Clearance expired 1 hour ago
            clearance_valid_until = datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db.add(expired)
        await db.commit()

        from app.services.tee_attestation_service import tee_attestation_service
        result = await tee_attestation_service.check_inference_clearance(
            db=db, model_id=model_id
        )
        # Should auto-re-attest and return valid
        assert result.valid is True
        assert result.platform == "mock"
        assert result.pcr0_match is True

    @pytest.mark.asyncio
    async def test_clearance_result_fields(self, db, monkeypatch):
        """TEEClearanceResult has all expected fields."""
        from app.core import config
        monkeypatch.setattr(config.settings, "TEE_AUTO_ATTEST_DEV", True)
        monkeypatch.setattr(config.settings, "ENVIRONMENT", "development")

        from app.services.tee_attestation_service import tee_attestation_service, TEEClearanceResult
        result = await tee_attestation_service.check_inference_clearance(
            db=db, model_id="field-check-model"
        )
        assert isinstance(result, TEEClearanceResult)
        assert hasattr(result, "valid")
        assert hasattr(result, "action")
        assert hasattr(result, "reason")
        assert hasattr(result, "report_id")
        assert hasattr(result, "platform")
        assert hasattr(result, "pcr0_match")

    def test_tee_gate_present_in_governance_pipeline(self):
        """Confirm the TEE gate is wired into evaluate_inference."""
        import inspect
        from app.services.governance_service import GovernanceService
        src = inspect.getsource(GovernanceService.evaluate_inference)
        assert "check_inference_clearance" in src
        assert "tee-attestation-gate" in src
        assert "tee_result.action" in src
        assert "tee_blocked" in src

    def test_config_defaults_are_safe_for_local(self):
        """Default config allows local dev without manual attestation setup."""
        from app.core.config import settings
        # These defaults ensure zero-friction local dev
        assert settings.TEE_AUTO_ATTEST_DEV is True
        assert settings.TEE_ENFORCEMENT_ENABLED is False
        assert settings.TEE_CLEARANCE_TTL_MINUTES > 0

    def test_provider_factory_respects_config(self, monkeypatch):
        """_get_client() returns MockTEEClient in mock mode."""
        from app.core import config
        monkeypatch.setattr(config.settings, "TEE_ATTESTATION_MODE", "mock")
        from app.services.tee_attestation_service import (
            tee_attestation_service, MockTEEClient,
        )
        client = tee_attestation_service._get_client()
        assert isinstance(client, MockTEEClient)


# ══════════════════════════════════════════════════════════════════════════════
#  T1-B: Built-in Policy Sovereign Signing Fix
# ══════════════════════════════════════════════════════════════════════════════

class TestBuiltinPolicySovereignSigning:
    """
    T1-B: verify that BUILT_IN_POLICIES now travel through the same
    Ed25519 bundle-verification path as DB policies.
    """

    @pytest.fixture(autouse=True)
    def init_crypto(self):
        from app.core.crypto import crypto_service
        from app.services.policy_bundle_service import policy_bundle_service
        crypto_service.initialize()
        # Invalidate cached bundle so it's re-signed with the current key.
        # (In production the key is stable; in tests ephemeral keys rotate per class.)
        policy_bundle_service._builtin_bundle = None

    def test_builtin_bundle_is_signed(self):
        """get_builtin_bundle() returns a bundle with a non-empty signature."""
        from app.services.policy_bundle_service import policy_bundle_service
        bundle = policy_bundle_service.get_builtin_bundle()
        assert bundle.signature, "Built-in bundle must have a signature"

    def test_builtin_bundle_verifies(self):
        """verify_bundle() returns True for the freshly signed built-in bundle."""
        from app.services.policy_bundle_service import policy_bundle_service
        bundle = policy_bundle_service.get_builtin_bundle()
        assert policy_bundle_service.verify_bundle(bundle) is True

    def test_builtin_bundle_contains_all_builtin_policies(self):
        """bundle.policies must match BUILT_IN_POLICIES exactly."""
        from app.services.policy_bundle_service import policy_bundle_service
        from app.modules.policy_engine import BUILT_IN_POLICIES
        bundle = policy_bundle_service.get_builtin_bundle()
        bundle_ids = {p["id"] for p in bundle.policies}
        raw_ids    = {p["id"] for p in BUILT_IN_POLICIES}
        assert bundle_ids == raw_ids

    def test_tampered_builtin_bundle_fails_verify(self):
        """Mutating bundle.policies after signing causes verify_bundle() to fail."""
        import copy
        from app.services.policy_bundle_service import policy_bundle_service
        original = policy_bundle_service.get_builtin_bundle()
        # Deep-copy so we don't corrupt the singleton
        tampered = copy.deepcopy(original)
        tampered.policies[0]["severity"] = "low"   # mutate a field
        assert policy_bundle_service.verify_bundle(tampered) is False

    def test_load_federated_uses_verified_bundle(self):
        """_load_federated_policies uses bundle.policies, not raw BUILT_IN_POLICIES."""
        import inspect
        from app.services.governance_service import GovernanceService
        src = inspect.getsource(GovernanceService._load_federated_policies)
        # Must call get_builtin_bundle and verify_bundle
        assert "get_builtin_bundle" in src
        assert "verify_bundle" in src
        # Raw BUILT_IN_POLICIES must only appear as a fallback, not the primary return
        assert "builtin_policies" in src
        assert "builtin_bundle.policies" in src

    def test_bundle_version_is_builtin(self):
        """Built-in bundle has the expected version tag."""
        from app.services.policy_bundle_service import policy_bundle_service
        bundle = policy_bundle_service.get_builtin_bundle()
        assert bundle.bundle_version == "builtin-1.0"

    def test_bundle_is_not_expired(self):
        """Built-in bundle valid_until is far in the future (10-year window)."""
        from app.services.policy_bundle_service import policy_bundle_service
        from datetime import datetime, timezone, timedelta
        bundle = policy_bundle_service.get_builtin_bundle()
        assert not bundle.is_expired
        valid_until = datetime.fromisoformat(bundle.valid_until)
        assert valid_until > datetime.now(timezone.utc) + timedelta(days=365)


# ══════════════════════════════════════════════════════════════════════════════
#  T1-C: NAEL Pre-flight Provisioner Script
# ══════════════════════════════════════════════════════════════════════════════

class TestNAELProvisionScript:
    """
    T1-C: nael_provision_all_models.py core logic tests.
    Uses an in-memory SQLite DB to avoid touching the live database.
    """

    @pytest.fixture(autouse=True)
    def init_crypto(self):
        from app.core.crypto import crypto_service
        crypto_service.initialize()

    @pytest.fixture
    async def db(self):
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from app.db.database import Base
        import app.models.orm_models  # noqa: F401

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            yield session
        await engine.dispose()

    async def _create_model(self, db, name="test-model", risk="MEDIUM", sector=None):
        """Helper: insert a minimal AIModel row and return it."""
        from app.models.orm_models import AIModel
        import uuid
        model = AIModel(
            id                  = str(uuid.uuid4()),
            name                = name,
            version             = "v1.0.0",
            model_type          = "classification",
            owner               = "test@example.com",
            risk_category = risk,
            sector              = sector,
        )
        db.add(model)
        await db.commit()
        await db.refresh(model)
        return model

    @pytest.mark.asyncio
    async def test_unlicensed_model_gets_issued(self, db):
        """A model with no license → status ISSUED."""
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from scripts.nael_provision_all_models import _provision_model

        model = await self._create_model(db, name="credit-v1")
        result = await _provision_model(
            db, model,
            risk_class_override=None, valid_days=365,
            dry_run=False, force=False,
        )
        from scripts.nael_provision_all_models import ProvisionResult
        assert result.status == ProvisionResult.STATUS_ISSUED
        assert result.license_id is not None

    @pytest.mark.asyncio
    async def test_already_licensed_model_skipped(self, db):
        """A model that already has a valid license → status SKIPPED."""
        from scripts.nael_provision_all_models import _provision_model, ProvisionResult
        from app.services.nael_service import nael_service

        model = await self._create_model(db, name="already-licensed")
        await nael_service.issue_license(db, model.id)

        result = await _provision_model(
            db, model,
            risk_class_override=None, valid_days=365,
            dry_run=False, force=False,
        )
        assert result.status == ProvisionResult.STATUS_SKIPPED
        assert result.license_id is not None

    @pytest.mark.asyncio
    async def test_force_reissues_even_if_licensed(self, db):
        """--force re-issues a license even when a valid one already exists."""
        from scripts.nael_provision_all_models import _provision_model, ProvisionResult
        from app.services.nael_service import nael_service

        model  = await self._create_model(db, name="force-reissue")
        first  = await nael_service.issue_license(db, model.id)

        result = await _provision_model(
            db, model,
            risk_class_override=None, valid_days=365,
            dry_run=False, force=True,
        )
        assert result.status == ProvisionResult.STATUS_ISSUED
        # New license ID differs from the original
        assert result.license_id != first.id

    @pytest.mark.asyncio
    async def test_dry_run_does_not_write(self, db):
        """--dry-run returns DRY_RUN status and writes nothing to the DB."""
        from sqlalchemy import select
        from scripts.nael_provision_all_models import _provision_model, ProvisionResult
        from app.models.orm_models import NAELLicense

        model = await self._create_model(db, name="dry-run-model")
        result = await _provision_model(
            db, model,
            risk_class_override=None, valid_days=365,
            dry_run=True, force=False,
        )
        assert result.status == ProvisionResult.STATUS_DRY_RUN
        assert result.license_id is None

        # Confirm nothing was written
        res = await db.execute(
            select(NAELLicense).where(NAELLicense.model_id == model.id)
        )
        assert res.scalars().first() is None

    @pytest.mark.asyncio
    async def test_risk_class_override_applied(self, db):
        """--risk-class override supersedes the model's own risk_classification."""
        from app.services.nael_service import nael_service
        from scripts.nael_provision_all_models import _provision_model, ProvisionResult

        model = await self._create_model(db, name="low-risk-model", risk="LOW")
        result = await _provision_model(
            db, model,
            risk_class_override="HIGH", valid_days=365,
            dry_run=False, force=False,
        )
        assert result.status == ProvisionResult.STATUS_ISSUED
        # Fetch the issued license and verify the override was applied
        issued = await nael_service.get_license_for_model(db, model.id)
        assert issued.risk_classification == "HIGH"

    @pytest.mark.asyncio
    async def test_sector_derived_from_model(self, db):
        """Model.sector is propagated to NAELLicense.sector_restrictions."""
        from app.services.nael_service import nael_service
        from scripts.nael_provision_all_models import _provision_model, ProvisionResult

        model = await self._create_model(db, name="finance-model", sector="finance")
        result = await _provision_model(
            db, model,
            risk_class_override=None, valid_days=365,
            dry_run=False, force=False,
        )
        assert result.status == ProvisionResult.STATUS_ISSUED
        issued = await nael_service.get_license_for_model(db, model.id)
        assert "finance" in (issued.sector_restrictions or [])

    @pytest.mark.asyncio
    async def test_valid_days_applied(self, db):
        """--valid-days is reflected in the license's valid_until date."""
        from datetime import datetime, timezone, timedelta
        from app.services.nael_service import nael_service
        from scripts.nael_provision_all_models import _provision_model, ProvisionResult

        model = await self._create_model(db, name="long-validity")
        await _provision_model(
            db, model,
            risk_class_override=None, valid_days=730,
            dry_run=False, force=False,
        )
        issued = await nael_service.get_license_for_model(db, model.id)
        expected_min = datetime.now(timezone.utc) + timedelta(days=729)
        # valid_until should be ~730 days from now (within 1 day tolerance)
        assert issued.valid_until.replace(tzinfo=timezone.utc) > expected_min

    @pytest.mark.asyncio
    async def test_error_on_nonexistent_model_id(self, db):
        """_provision_model returns ERROR status when model_id is not in DB."""
        from app.models.orm_models import AIModel
        from scripts.nael_provision_all_models import _provision_model, ProvisionResult
        import uuid

        # Construct a fake model object (not saved to DB)
        ghost = AIModel(
            id          = str(uuid.uuid4()),
            name        = "ghost-model",
            version     = "v0.0.1",
            model_type  = "classification",
            owner       = "nobody@example.com",
            risk_category = "MEDIUM",
        )
        result = await _provision_model(
            db, ghost,
            risk_class_override=None, valid_days=365,
            dry_run=False, force=False,
        )
        assert result.status == ProvisionResult.STATUS_ERROR
        assert result.error is not None

    def test_script_file_exists(self):
        """The script exists at the expected path."""
        import os
        script = os.path.join(
            os.path.dirname(__file__), "..", "scripts", "nael_provision_all_models.py"
        )
        assert os.path.isfile(os.path.abspath(script))

    def test_exit_codes_are_documented(self):
        """Script docstring defines exit codes 0, 1, 2."""
        import importlib.util, os, sys
        path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "scripts", "nael_provision_all_models.py")
        )
        spec   = importlib.util.spec_from_file_location("nael_provision_all_models", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert "exit code" in module.__doc__.lower()
        assert "0" in module.__doc__
        assert "1" in module.__doc__
        assert "2" in module.__doc__


# ══════════════════════════════════════════════════════════════════════════════
#  T2-A: Registry Service + Federation Stub
# ══════════════════════════════════════════════════════════════════════════════

class TestRegistryService:
    """
    T2-A: RegistryService core operations and federation stub.
    """

    @pytest.fixture(autouse=True)
    def init_crypto(self):
        from app.core.crypto import crypto_service
        crypto_service.initialize()

    @pytest.fixture
    async def db(self):
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from app.db.database import Base
        import app.models.orm_models  # noqa: F401

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            yield session
        await engine.dispose()

    async def _create_model(self, db, name="test-model", risk="MEDIUM",
                             status="PENDING", sector=None):
        from app.models.orm_models import AIModel
        import uuid
        m = AIModel(
            id              = str(uuid.uuid4()),
            name            = name,
            version         = "v1.0",
            model_type      = "classification",
            owner           = "test@example.com",
            risk_category   = risk,
            registry_status = status,
            sector          = sector,
        )
        db.add(m)
        await db.commit()
        await db.refresh(m)
        return m

    # ── Core reads ───────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_get_model_found(self, db):
        from app.services.registry_service import registry_service
        m = await self._create_model(db)
        result = await registry_service.get_model(db, m.id)
        assert result is not None
        assert result.id == m.id

    @pytest.mark.asyncio
    async def test_get_model_not_found_returns_none(self, db):
        from app.services.registry_service import registry_service
        result = await registry_service.get_model(db, "does-not-exist")
        assert result is None

    @pytest.mark.asyncio
    async def test_list_models_filter_by_risk(self, db):
        from app.services.registry_service import registry_service
        await self._create_model(db, name="high-1",  risk="HIGH")
        await self._create_model(db, name="low-1",   risk="LOW")
        await self._create_model(db, name="high-2",  risk="HIGH")
        results = await registry_service.list_models(db, risk_category="HIGH")
        assert all(m.risk_category == "HIGH" for m in results)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_list_models_filter_by_sector(self, db):
        from app.services.registry_service import registry_service
        await self._create_model(db, name="fin-1", sector="finance")
        await self._create_model(db, name="med-1", sector="healthcare")
        results = await registry_service.list_models(db, sector="finance")
        assert len(results) == 1
        assert results[0].sector == "finance"

    @pytest.mark.asyncio
    async def test_get_stats_counts_correctly(self, db):
        from app.services.registry_service import registry_service
        await self._create_model(db, risk="HIGH",   status="ACTIVE")
        await self._create_model(db, risk="MEDIUM", status="ACTIVE")
        stats = await registry_service.get_stats(db)
        assert stats["total_registered_models"] == 2
        assert stats["risk_distribution"]["HIGH"] == 1
        assert stats["registry_status"]["ACTIVE"] == 2

    # ── Core writes ──────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_submit_hash_promotes_to_active(self, db):
        from app.services.registry_service import registry_service
        m = await self._create_model(db, status="PENDING")
        updated = await registry_service.submit_model_hash(
            db, m.id, sha256="a" * 64
        )
        assert updated.model_sha256 == "a" * 64
        assert updated.registry_status == "ACTIVE"
        assert updated.nair_registered_at is not None

    @pytest.mark.asyncio
    async def test_submit_hash_nonexistent_raises(self, db):
        from app.services.registry_service import registry_service
        with pytest.raises(ValueError, match="not found"):
            await registry_service.submit_model_hash(db, "ghost", sha256="x" * 64)

    @pytest.mark.asyncio
    async def test_update_risk_category(self, db):
        from app.services.registry_service import registry_service
        m = await self._create_model(db, risk="LOW")
        updated = await registry_service.update_risk_category(db, m.id, "HIGH")
        assert updated.risk_category == "HIGH"

    @pytest.mark.asyncio
    async def test_prohibited_suspends_model(self, db):
        from app.services.registry_service import registry_service
        m = await self._create_model(db, risk="HIGH", status="ACTIVE")
        updated = await registry_service.update_risk_category(db, m.id, "PROHIBITED")
        assert updated.registry_status == "SUSPENDED"

    @pytest.mark.asyncio
    async def test_invalid_risk_raises(self, db):
        from app.services.registry_service import registry_service
        m = await self._create_model(db)
        with pytest.raises(ValueError, match="Invalid risk_category"):
            await registry_service.update_risk_category(db, m.id, "BANANA")

    @pytest.mark.asyncio
    async def test_update_registry_status(self, db):
        from app.services.registry_service import registry_service
        m = await self._create_model(db, status="ACTIVE")
        updated = await registry_service.update_registry_status(db, m.id, "SUSPENDED")
        assert updated.registry_status == "SUSPENDED"

    @pytest.mark.asyncio
    async def test_invalid_status_raises(self, db):
        from app.services.registry_service import registry_service
        m = await self._create_model(db)
        with pytest.raises(ValueError, match="Invalid registry_status"):
            await registry_service.update_registry_status(db, m.id, "BANANA")

    @pytest.mark.asyncio
    async def test_patch_metadata_updates_sector(self, db):
        from app.services.registry_service import registry_service
        m = await self._create_model(db)
        updated = await registry_service.patch_metadata(db, m.id, sector="Finance")
        assert updated.sector == "finance"   # lowercased

    # ── model_to_entry serialiser ─────────────────────────────────────────────

    def test_model_to_entry_basic_fields(self):
        from app.services.registry_service import model_to_entry
        from app.models.orm_models import AIModel
        import uuid
        m = AIModel(
            id="x", name="n", version="v1", model_type="cls",
            owner="o@x.com", risk_category="LOW", registry_status="ACTIVE",
        )
        e = model_to_entry(m)
        assert e["id"] == "x"
        assert e["risk_category"] == "LOW"
        # Full details not included by default
        assert "description" not in e

    def test_model_to_entry_full_includes_description(self):
        from app.services.registry_service import model_to_entry
        from app.models.orm_models import AIModel
        m = AIModel(
            id="y", name="n2", version="v2", model_type="llm",
            owner="o@x.com", risk_category="HIGH", registry_status="ACTIVE",
            description="Test model",
        )
        e = model_to_entry(m, full=True)
        assert "description" in e
        assert e["description"] == "Test model"

    # ── Federation: local/stub mode ───────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_local_mode_sync_skipped(self, db, monkeypatch):
        """BASCG_PROVIDER_MODE=local → sync skipped, no HTTP call."""
        from app.core import config
        from app.services.registry_service import registry_service
        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE",    "local")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL", "")
        m      = await self._create_model(db, status="ACTIVE")
        result = await registry_service.sync_to_national_node(db, m.id)
        assert result.skipped is True
        assert result.synced  is False
        assert result.error   is None

    @pytest.mark.asyncio
    async def test_empty_node_url_skips_without_http(self, db, monkeypatch):
        """No BASCG_NATIONAL_NODE_URL configured → always skip."""
        from app.core import config
        from app.services.registry_service import registry_service
        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE",    "production")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL", "")
        m      = await self._create_model(db, status="ACTIVE")
        result = await registry_service.sync_to_national_node(db, m.id)
        assert result.skipped is True

    @pytest.mark.asyncio
    async def test_sync_nonexistent_model_returns_error(self, db, monkeypatch):
        """sync_to_national_node with unknown model_id → error result, not exception."""
        from app.core import config
        from app.services.registry_service import registry_service
        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE",    "production")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL",
                            "https://bascg.example.gov.in")
        result = await registry_service.sync_to_national_node(db, "ghost-model-id")
        assert result.synced is False
        assert result.error  is not None

    @pytest.mark.asyncio
    async def test_sync_http_failure_returns_error_result(self, db, monkeypatch):
        """HTTP error during sync → FederationSyncResult.synced=False, not exception."""
        import httpx
        from app.core import config
        from app.services.registry_service import registry_service

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE",    "production")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL",
                            "https://bascg.example.gov.in")
        monkeypatch.setattr(config.settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 5)

        # Patch httpx to raise a connection error
        async def _fake_post(*args, **kwargs):
            raise httpx.ConnectError("connection refused")

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            post = _fake_post

        monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: _FakeClient())

        m      = await self._create_model(db, status="ACTIVE")
        result = await registry_service.sync_to_national_node(db, m.id)
        assert result.synced is False
        assert result.error  is not None

    @pytest.mark.asyncio
    async def test_push_all_active_returns_one_result_per_model(self, db, monkeypatch):
        """push_all_active_to_national_node returns one result per ACTIVE model."""
        from app.core import config
        from app.services.registry_service import registry_service
        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE",    "local")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL", "")

        await self._create_model(db, name="a", status="ACTIVE")
        await self._create_model(db, name="b", status="ACTIVE")
        await self._create_model(db, name="c", status="PENDING")  # not ACTIVE — excluded

        results = await registry_service.push_all_active_to_national_node(db)
        assert len(results) == 2
        assert all(r.skipped for r in results)

    # ── Config & wiring ───────────────────────────────────────────────────────

    def test_config_has_national_node_url(self):
        from app.core.config import settings
        assert hasattr(settings, "BASCG_NATIONAL_NODE_URL")
        assert hasattr(settings, "BASCG_FEDERATION_TIMEOUT_SECONDS")

    def test_federation_sync_result_fields(self):
        from app.services.registry_service import FederationSyncResult
        r = FederationSyncResult(
            model_id="m1", node_url="http://x", synced=True, status_code=200
        )
        assert r.synced is True
        assert r.skipped is False

    def test_registry_api_has_sync_endpoints(self):
        """API router exposes /sync and /sync-all."""
        import inspect
        from app.api import registry
        src = inspect.getsource(registry)
        assert "sync_model_to_national_node" in src
        assert "sync_all_to_national_node"   in src
        assert "federated-sync"              in src


# ══════════════════════════════════════════════════════════════════════════════
#  T1-D: Production Signing Key Startup Guard
# ══════════════════════════════════════════════════════════════════════════════

class TestStartupChecks:
    """
    T1-D: run_production_checks() must fail fast in production when
    critical secrets are missing, and must NOT block development startups.
    """

    def _run(self, monkeypatch, *, env, seed_b64, secret_key,
             mock_tsa_secret=None, ledger_mode="mock"):
        """Helper: patch settings and call run_production_checks()."""
        from app.core import config, startup_checks
        monkeypatch.setattr(config.settings, "ENVIRONMENT",              env)
        monkeypatch.setattr(config.settings, "BASCG_SIGNING_KEY_SEED_B64", seed_b64)
        monkeypatch.setattr(config.settings, "SECRET_KEY",               secret_key)
        monkeypatch.setattr(config.settings, "SOVEREIGN_LEDGER_MODE",    ledger_mode)
        if mock_tsa_secret is not None:
            monkeypatch.setattr(config.settings, "MOCK_TSA_SECRET", mock_tsa_secret)
        startup_checks.run_production_checks()

    # ── Production failures ───────────────────────────────────────────────────

    def test_production_no_seed_raises(self, monkeypatch):
        """Production + empty seed → RuntimeError."""
        import pytest
        from app.core.startup_checks import run_production_checks
        with pytest.raises(RuntimeError, match="BASCG_SIGNING_KEY_SEED_B64"):
            self._run(monkeypatch, env="production", seed_b64="",
                      secret_key="a" * 64)

    def test_production_placeholder_secret_key_raises(self, monkeypatch):
        """Production + placeholder SECRET_KEY → RuntimeError."""
        import pytest, base64, secrets
        valid_seed = base64.b64encode(secrets.token_bytes(32)).decode()
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            self._run(monkeypatch, env="production", seed_b64=valid_seed,
                      secret_key="CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32")

    def test_production_invalid_base64_seed_raises(self, monkeypatch):
        """Production + malformed base64 seed → RuntimeError."""
        import pytest
        with pytest.raises(RuntimeError, match="base64"):
            self._run(monkeypatch, env="production", seed_b64="not-valid-base64!!!",
                      secret_key="a" * 64)

    def test_production_wrong_seed_length_raises(self, monkeypatch):
        """Production + 16-byte seed (not 32 bytes) → RuntimeError."""
        import pytest, base64, secrets
        short_seed = base64.b64encode(secrets.token_bytes(16)).decode()
        with pytest.raises(RuntimeError, match="16 bytes"):
            self._run(monkeypatch, env="production", seed_b64=short_seed,
                      secret_key="a" * 64)

    def test_production_both_missing_raises(self, monkeypatch):
        """Production + both secrets missing → RuntimeError listing both."""
        import pytest
        with pytest.raises(RuntimeError) as exc_info:
            self._run(monkeypatch, env="production", seed_b64="",
                      secret_key="CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32")
        msg = str(exc_info.value)
        assert "BASCG_SIGNING_KEY_SEED_B64" in msg
        assert "SECRET_KEY" in msg

    # ── Production success ────────────────────────────────────────────────────

    def test_production_valid_config_passes(self, monkeypatch):
        """Production + valid seed + valid secret_key → no exception."""
        import base64, secrets
        valid_seed = base64.b64encode(secrets.token_bytes(32)).decode()
        self._run(monkeypatch, env="production", seed_b64=valid_seed,
                  secret_key="a" * 64)  # any non-placeholder value

    # ── Development leniency ─────────────────────────────────────────────────

    def test_development_no_seed_does_not_raise(self, monkeypatch):
        """Development + empty seed → warning only, no exception."""
        self._run(monkeypatch, env="development", seed_b64="",
                  secret_key="CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32")

    def test_development_placeholder_secret_does_not_raise(self, monkeypatch):
        """Development + placeholder SECRET_KEY → warning only, no exception."""
        self._run(monkeypatch, env="development", seed_b64="",
                  secret_key="CHANGE_ME_IN_PRODUCTION_use_openssl_rand_hex_32")

    # ── Mock TSA warning (non-blocking) ──────────────────────────────────────

    def test_mock_tsa_placeholder_emits_warning_not_error(self, monkeypatch, caplog):
        """Placeholder MOCK_TSA_SECRET in mock mode → warning, not RuntimeError."""
        import base64, secrets, logging
        valid_seed = base64.b64encode(secrets.token_bytes(32)).decode()
        with caplog.at_level(logging.WARNING, logger="kavachx.startup"):
            self._run(monkeypatch, env="production", seed_b64=valid_seed,
                      secret_key="a" * 64,
                      mock_tsa_secret="CHANGE_ME_MOCK_TSA_SECRET_32CHARS",
                      ledger_mode="mock")
        assert any("MOCK_TSA_SECRET" in r.message for r in caplog.records)

    # ── Wiring check ─────────────────────────────────────────────────────────

    def test_run_production_checks_called_in_lifespan(self):
        """main.py lifespan must call run_production_checks() before crypto init."""
        import inspect
        from app import main
        src = inspect.getsource(main.lifespan)
        # Guard must come before crypto_service.initialize()
        guard_pos  = src.find("run_production_checks")
        crypto_pos = src.find("crypto_service.initialize")
        assert guard_pos != -1, "run_production_checks not found in lifespan"
        assert crypto_pos != -1, "crypto_service.initialize not found in lifespan"
        assert guard_pos < crypto_pos, (
            "run_production_checks must be called BEFORE crypto_service.initialize()"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  T2-B: Regulator Key Import API
# ══════════════════════════════════════════════════════════════════════════════

class TestRegulatorKeyImport:
    """
    T2-B: runtime import, removal, and listing of regulator Ed25519 keys.
    Tests cover BASCGVerifier, CryptoService, config sidecar, and API wiring.
    """

    @pytest.fixture(autouse=True)
    def fresh_crypto(self, monkeypatch):
        """Re-initialise crypto with a fresh ephemeral key before each test."""
        from app.core import crypto as crypto_mod
        crypto_mod.crypto_service.initialize()
        # Reset settings trusted-keys JSON to empty so tests start clean
        from app.core import config
        monkeypatch.setattr(config.settings, "BASCG_TRUSTED_PUBLIC_KEYS_JSON", "{}")

    def _gen_key_b64(self) -> str:
        """Generate a fresh random Ed25519 public key (base64)."""
        import secrets, base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        priv = Ed25519PrivateKey.from_private_bytes(secrets.token_bytes(32))
        raw  = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    # ── BASCGVerifier.add_trusted_key ─────────────────────────────────────────

    def test_add_trusted_key_accepted(self):
        from app.core.crypto import crypto_service
        pub_b64 = self._gen_key_b64()
        crypto_service.verifier.add_trusted_key("TestIssuer-v1", pub_b64)
        assert "TestIssuer-v1" in crypto_service.verifier.trusted_issuers

    def test_add_trusted_key_invalid_base64_raises(self):
        from app.core.crypto import crypto_service
        with pytest.raises(ValueError, match="base64"):
            crypto_service.verifier.add_trusted_key("Bad-Issuer", "!!!not-base64!!!")

    def test_add_trusted_key_wrong_length_raises(self):
        import base64
        from app.core.crypto import crypto_service
        short = base64.b64encode(b"tooshort").decode()
        with pytest.raises(ValueError, match="32 bytes"):
            crypto_service.verifier.add_trusted_key("Short-Issuer", short)

    def test_remove_trusted_key(self):
        from app.core.crypto import crypto_service
        pub_b64 = self._gen_key_b64()
        crypto_service.verifier.add_trusted_key("Removable-v1", pub_b64)
        assert "Removable-v1" in crypto_service.verifier.trusted_issuers
        removed = crypto_service.verifier.remove_trusted_key("Removable-v1")
        assert removed is True
        assert "Removable-v1" not in crypto_service.verifier.trusted_issuers

    def test_remove_dev_local_is_protected(self):
        from app.core.crypto import crypto_service, DEV_ISSUER
        removed = crypto_service.verifier.remove_trusted_key(DEV_ISSUER)
        assert removed is False
        assert DEV_ISSUER in crypto_service.verifier.trusted_issuers

    # ── CryptoService.import_regulator_key ────────────────────────────────────

    def test_import_regulator_key_appears_in_trusted(self):
        from app.core.crypto import crypto_service
        pub_b64 = self._gen_key_b64()
        crypto_service.import_regulator_key("MeitY-BASCG-v1", pub_b64)
        assert "MeitY-BASCG-v1" in crypto_service.verifier.trusted_issuers

    def test_import_updates_settings_json(self):
        import json
        from app.core.crypto import crypto_service
        from app.core import config
        pub_b64 = self._gen_key_b64()
        crypto_service.import_regulator_key("RBI-AI-Gov", pub_b64)
        stored = json.loads(config.settings.BASCG_TRUSTED_PUBLIC_KEYS_JSON)
        assert "RBI-AI-Gov" in stored
        assert stored["RBI-AI-Gov"] == pub_b64

    def test_import_dev_local_issuer_raises(self):
        from app.core.crypto import crypto_service, DEV_ISSUER
        pub_b64 = self._gen_key_b64()
        with pytest.raises(ValueError, match="reserved"):
            crypto_service.import_regulator_key(DEV_ISSUER, pub_b64)

    def test_import_empty_issuer_raises(self):
        from app.core.crypto import crypto_service
        pub_b64 = self._gen_key_b64()
        with pytest.raises(ValueError, match="empty"):
            crypto_service.import_regulator_key("", pub_b64)

    def test_import_bad_key_raises(self):
        from app.core.crypto import crypto_service
        with pytest.raises(ValueError):
            crypto_service.import_regulator_key("AnyIssuer", "not-valid-base64!!!")

    def test_remove_regulator_key(self):
        from app.core.crypto import crypto_service
        pub_b64 = self._gen_key_b64()
        crypto_service.import_regulator_key("SEBI-AI-Gov", pub_b64)
        removed = crypto_service.remove_regulator_key("SEBI-AI-Gov")
        assert removed is True
        assert "SEBI-AI-Gov" not in crypto_service.verifier.trusted_issuers

    def test_list_trusted_keys_includes_dev_local(self):
        from app.core.crypto import crypto_service, DEV_ISSUER
        keys = crypto_service.list_trusted_keys()
        assert DEV_ISSUER in keys

    def test_list_trusted_keys_includes_imported(self):
        from app.core.crypto import crypto_service
        pub_b64 = self._gen_key_b64()
        crypto_service.import_regulator_key("IRDAI-AI-Gov", pub_b64)
        keys = crypto_service.list_trusted_keys()
        assert "IRDAI-AI-Gov" in keys
        assert keys["IRDAI-AI-Gov"] == pub_b64

    # ── Config sidecar ────────────────────────────────────────────────────────

    def test_save_and_load_regulator_keys(self, tmp_path, monkeypatch):
        """save_regulator_keys writes a file; load_regulator_keys merges it."""
        import json
        from app.core import config

        # Point sidecar to a temp path
        monkeypatch.setattr(config, "_REGULATOR_KEYS_FILE",
                            str(tmp_path / "test_regulator_keys.json"))
        monkeypatch.setattr(config.settings, "BASCG_TRUSTED_PUBLIC_KEYS_JSON", "{}")

        pub_b64 = self._gen_key_b64()
        config.save_regulator_keys({"TestReg-v1": pub_b64})

        # Reset in-memory state and reload from file
        monkeypatch.setattr(config.settings, "BASCG_TRUSTED_PUBLIC_KEYS_JSON", "{}")
        config.load_regulator_keys()

        stored = json.loads(config.settings.BASCG_TRUSTED_PUBLIC_KEYS_JSON)
        assert "TestReg-v1" in stored
        assert stored["TestReg-v1"] == pub_b64

    def test_env_var_takes_precedence_over_sidecar(self, tmp_path, monkeypatch):
        """Env-var value wins when both sidecar and BASCG_TRUSTED_PUBLIC_KEYS_JSON set same issuer."""
        import json
        from app.core import config

        monkeypatch.setattr(config, "_REGULATOR_KEYS_FILE",
                            str(tmp_path / "test_override.json"))

        env_pub    = self._gen_key_b64()
        sidecar_pub = self._gen_key_b64()

        monkeypatch.setattr(
            config.settings, "BASCG_TRUSTED_PUBLIC_KEYS_JSON",
            json.dumps({"Reg-A": env_pub})
        )
        config.save_regulator_keys({"Reg-A": sidecar_pub, "Reg-B": self._gen_key_b64()})

        stored = json.loads(config.settings.BASCG_TRUSTED_PUBLIC_KEYS_JSON)
        # env-var value for Reg-A must NOT be overwritten by sidecar
        assert stored["Reg-A"] == env_pub
        # Reg-B (sidecar-only) is merged in
        assert "Reg-B" in stored

    # ── API wiring ────────────────────────────────────────────────────────────

    def test_api_endpoints_present_in_bascg_module(self):
        import inspect
        from app.api import bascg
        src = inspect.getsource(bascg)
        assert "import_regulator_key"    in src
        assert "remove_regulator_key"    in src
        assert "list_trusted_keys"       in src
        assert "admin/import-regulator-key" in src
        assert "admin/regulator-keys"    in src
        assert "admin/trusted-keys"      in src

    def test_import_key_endpoint_requires_policy_write(self):
        """Endpoint uses require_permission('policies:write')."""
        import inspect
        from app.api import bascg
        src = inspect.getsource(bascg.import_regulator_key)
        assert "policies:write" in src


# ══════════════════════════════════════════════════════════════════════════════
#  T2-C: ONNX Local Media Detector
# ══════════════════════════════════════════════════════════════════════════════

class TestLocalModelMediaDetector:
    """Unit tests for LocalModelMediaDetector."""

    # ── Instantiation ─────────────────────────────────────────────────────────

    def test_empty_model_path_raises_value_error(self):
        from app.services.synthetic_media_service import LocalModelMediaDetector
        with pytest.raises(ValueError, match="SYNTHETIC_MEDIA_ONNX_MODEL_PATH"):
            LocalModelMediaDetector(model_path="")

    def test_valid_path_stores_attributes(self):
        from app.services.synthetic_media_service import LocalModelMediaDetector
        det = LocalModelMediaDetector(model_path="/tmp/model.onnx",
                                      input_name="images",
                                      input_size=128)
        assert det._model_path == "/tmp/model.onnx"
        assert det._input_name == "images"
        assert det._input_size == 128
        assert det._session is None   # lazy — not loaded yet

    def test_default_input_name_and_size(self):
        from app.services.synthetic_media_service import LocalModelMediaDetector
        det = LocalModelMediaDetector(model_path="/tmp/model.onnx")
        assert det._input_name == "input"
        assert det._input_size == 224

    # ── _load_session error paths ─────────────────────────────────────────────

    def test_load_session_raises_when_onnxruntime_missing(self, monkeypatch):
        """Simulate onnxruntime not installed → clear RuntimeError."""
        import builtins
        import importlib
        from app.services.synthetic_media_service import LocalModelMediaDetector

        det = LocalModelMediaDetector(model_path="/tmp/model.onnx")

        real_import = builtins.__import__

        def _block_ort(name, *args, **kwargs):
            if name == "onnxruntime":
                raise ImportError("No module named 'onnxruntime'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _block_ort)
        with pytest.raises(RuntimeError, match="onnxruntime is not installed"):
            det._load_session()

    def test_load_session_raises_when_model_file_missing(self, monkeypatch, tmp_path):
        """onnxruntime present but model file not found → clear RuntimeError."""
        from app.services.synthetic_media_service import LocalModelMediaDetector

        # Stub onnxruntime so the import succeeds
        fake_ort = type(sys)("onnxruntime")
        fake_ort.SessionOptions = lambda: None
        fake_ort.InferenceSession = lambda *a, **kw: None
        monkeypatch.setitem(sys.modules, "onnxruntime", fake_ort)

        det = LocalModelMediaDetector(model_path=str(tmp_path / "nonexistent.onnx"))
        with pytest.raises(RuntimeError, match="ONNX model not found"):
            det._load_session()

    # ── _preprocess ───────────────────────────────────────────────────────────

    def test_preprocess_without_pil_produces_correct_shape(self, monkeypatch):
        """When PIL is absent the fallback path produces [1,3,H,W] float32."""
        import builtins
        from app.services.synthetic_media_service import LocalModelMediaDetector
        import numpy as np

        real_import = builtins.__import__

        def _block_pil(name, *args, **kwargs):
            if name == "PIL" or name.startswith("PIL."):
                raise ImportError("No module named 'PIL'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _block_pil)

        det = LocalModelMediaDetector(model_path="/tmp/model.onnx", input_size=32)
        content = b"fake image bytes padded to make it long enough"
        arr = det._preprocess(content)

        assert arr.shape == (1, 3, 32, 32)
        assert arr.dtype == np.float32

    def test_preprocess_values_in_valid_float_range(self, monkeypatch):
        """Fallback tensor values must be in [0, 1] before normalisation."""
        import builtins
        from app.services.synthetic_media_service import LocalModelMediaDetector
        import numpy as np

        real_import = builtins.__import__

        def _block_pil(name, *args, **kwargs):
            if name == "PIL" or name.startswith("PIL."):
                raise ImportError("No module named 'PIL'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _block_pil)

        det = LocalModelMediaDetector(model_path="/tmp/model.onnx", input_size=8)
        arr = det._preprocess(b"\xff" * 200)
        # /255 → all 1.0
        assert float(arr.min()) >= 0.0
        assert float(arr.max()) <= 1.0

    # ── _parse_output ─────────────────────────────────────────────────────────

    def test_parse_output_logits_two_class(self):
        """[1,2] logit output → softmax over synthetic score."""
        import numpy as np
        from app.services.synthetic_media_service import LocalModelMediaDetector

        det = LocalModelMediaDetector(model_path="/tmp/model.onnx")
        # High synthetic logit
        out = np.array([[0.1, 5.0]], dtype=np.float32)
        confidence, is_synthetic = det._parse_output(out)
        assert is_synthetic is True
        assert confidence > 0.9

    def test_parse_output_logits_real_wins(self):
        """[1,2] logit output where real logit dominates → not synthetic."""
        import numpy as np
        from app.services.synthetic_media_service import LocalModelMediaDetector

        det = LocalModelMediaDetector(model_path="/tmp/model.onnx")
        out = np.array([[5.0, 0.1]], dtype=np.float32)
        confidence, is_synthetic = det._parse_output(out)
        assert is_synthetic is False
        assert confidence < 0.1

    def test_parse_output_sigmoid_scalar(self):
        """[1,1] sigmoid output → probability of synthetic directly."""
        import numpy as np
        from app.services.synthetic_media_service import LocalModelMediaDetector

        det = LocalModelMediaDetector(model_path="/tmp/model.onnx")
        out = np.array([[0.85]], dtype=np.float32)
        confidence, is_synthetic = det._parse_output(out)
        assert is_synthetic is True
        assert abs(confidence - 0.85) < 0.01

    def test_parse_output_clamped_to_unit_interval(self):
        """Confidence is always within [0, 1] regardless of raw output."""
        import numpy as np
        from app.services.synthetic_media_service import LocalModelMediaDetector

        det = LocalModelMediaDetector(model_path="/tmp/model.onnx")
        # Scalar that exceeds 1 after processing
        out = np.array([[1e10]], dtype=np.float32)
        confidence, _ = det._parse_output(out)
        assert 0.0 <= confidence <= 1.0

    # ── detect() end-to-end with mocked onnxruntime ──────────────────────────

    @pytest.mark.asyncio
    async def test_detect_end_to_end_synthetic(self, monkeypatch, tmp_path):
        """detect() with mocked ONNX session returns synthetic DetectionResult."""
        import numpy as np
        from app.services.synthetic_media_service import LocalModelMediaDetector

        # Create a dummy model file so the file-exists check passes
        model_file = tmp_path / "deepfake.onnx"
        model_file.write_bytes(b"fake onnx binary")

        # Stub onnxruntime session
        class _FakeSession:
            def run(self, output_names, inputs):
                # Return logits heavily favouring synthetic class
                return [np.array([[0.0, 10.0]], dtype=np.float32)]

        class _FakeOrt:
            class SessionOptions:
                log_severity_level = 3

            @staticmethod
            def InferenceSession(path, sess_options=None, providers=None):
                return _FakeSession()

        monkeypatch.setitem(sys.modules, "onnxruntime", _FakeOrt)

        det = LocalModelMediaDetector(model_path=str(model_file))
        result = await det.detect(b"fake image content")

        assert result.is_synthetic is True
        assert result.confidence > 0.9
        assert f"onnx:{str(model_file)}" == result.detector
        assert result.raw_response["engine"] == "onnxruntime"
        assert len(result.labels) > 0   # should have a label for high confidence

    @pytest.mark.asyncio
    async def test_detect_end_to_end_real(self, monkeypatch, tmp_path):
        """detect() returns not-synthetic when model says real content."""
        import numpy as np
        from app.services.synthetic_media_service import LocalModelMediaDetector

        model_file = tmp_path / "deepfake.onnx"
        model_file.write_bytes(b"fake onnx binary")

        class _FakeSession:
            def run(self, output_names, inputs):
                return [np.array([[10.0, 0.0]], dtype=np.float32)]

        class _FakeOrt:
            class SessionOptions:
                log_severity_level = 3

            @staticmethod
            def InferenceSession(path, sess_options=None, providers=None):
                return _FakeSession()

        monkeypatch.setitem(sys.modules, "onnxruntime", _FakeOrt)

        det = LocalModelMediaDetector(model_path=str(model_file))
        result = await det.detect(b"real image content")

        assert result.is_synthetic is False
        assert result.confidence < 0.1
        assert result.labels == []

    @pytest.mark.asyncio
    async def test_detect_label_buckets(self, monkeypatch, tmp_path):
        """Labels use confidence buckets: >=0.9 → high_confidence_synthetic etc."""
        import numpy as np
        from app.services.synthetic_media_service import LocalModelMediaDetector

        model_file = tmp_path / "m.onnx"
        model_file.write_bytes(b"x")

        # Produce confidence ~0.75 → "likely_synthetic"
        class _FakeSession:
            def run(self, output_names, inputs):
                # sigmoid = 0.75 → [1,1] output
                return [np.array([[0.75]], dtype=np.float32)]

        class _FakeOrt:
            class SessionOptions:
                log_severity_level = 3

            @staticmethod
            def InferenceSession(*a, **kw):
                return _FakeSession()

        monkeypatch.setitem(sys.modules, "onnxruntime", _FakeOrt)

        det = LocalModelMediaDetector(model_path=str(model_file))
        result = await det.detect(b"content")
        assert "likely_synthetic" in result.labels


class TestONNXDetectorFactory:
    """Tests for _get_detector() onnx branch in SyntheticMediaShieldService."""

    def test_get_detector_returns_local_model_when_onnx_mode(self, monkeypatch):
        from app.services import synthetic_media_service as svc
        from app.services.synthetic_media_service import (
            LocalModelMediaDetector,
            SyntheticMediaShieldService,
        )

        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_MODE", "onnx")
        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "/tmp/m.onnx")
        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_ONNX_INPUT_NAME", "input")
        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_ONNX_INPUT_SIZE", 224)

        service = SyntheticMediaShieldService()
        detector = service._get_detector()
        assert isinstance(detector, LocalModelMediaDetector)
        assert detector._model_path == "/tmp/m.onnx"

    def test_get_detector_raises_when_onnx_mode_no_path(self, monkeypatch):
        from app.services import synthetic_media_service as svc
        from app.services.synthetic_media_service import SyntheticMediaShieldService

        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_MODE", "onnx")
        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "")

        service = SyntheticMediaShieldService()
        with pytest.raises(ValueError, match="SYNTHETIC_MEDIA_ONNX_MODEL_PATH"):
            service._get_detector()

    def test_get_detector_returns_mock_by_default(self, monkeypatch):
        from app.services import synthetic_media_service as svc
        from app.services.synthetic_media_service import (
            MockMediaDetector,
            SyntheticMediaShieldService,
        )

        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_MODE", "mock")
        service = SyntheticMediaShieldService()
        assert isinstance(service._get_detector(), MockMediaDetector)

    def test_get_detector_onnx_uses_config_input_name_and_size(self, monkeypatch):
        from app.services import synthetic_media_service as svc
        from app.services.synthetic_media_service import (
            LocalModelMediaDetector,
            SyntheticMediaShieldService,
        )

        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_MODE", "onnx")
        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "/x/y.onnx")
        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_ONNX_INPUT_NAME", "frames")
        monkeypatch.setattr(svc.settings, "SYNTHETIC_MEDIA_ONNX_INPUT_SIZE", 112)

        det = SyntheticMediaShieldService()._get_detector()
        assert isinstance(det, LocalModelMediaDetector)
        assert det._input_name == "frames"
        assert det._input_size == 112


class TestONNXConfigFields:
    """Config settings exist and have correct defaults."""

    def test_onnx_model_path_default_empty(self):
        from app.core.config import Settings
        s = Settings()
        assert s.SYNTHETIC_MEDIA_ONNX_MODEL_PATH == ""

    def test_onnx_input_name_default(self):
        from app.core.config import Settings
        s = Settings()
        assert s.SYNTHETIC_MEDIA_ONNX_INPUT_NAME == "input"

    def test_onnx_input_size_default(self):
        from app.core.config import Settings
        s = Settings()
        assert s.SYNTHETIC_MEDIA_ONNX_INPUT_SIZE == 224


class TestBASCGStatusONNX:
    """bascg_status_service reports ONNX mode correctly in pillar 4."""

    def test_onnx_mode_with_path_is_local_and_prod_ready(self, monkeypatch):
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_MODE", "onnx")
        monkeypatch.setattr(config.settings,
                            "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "/opt/models/df.onnx")

        svc = BASCGStatusService()
        p = svc._pillar_synthetic_media()
        assert p.local_ready is True
        assert p.production_ready is True
        assert p.provider_mode == "local"    # onnx is still considered local

    def test_onnx_mode_no_path_not_ready(self, monkeypatch):
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_MODE", "onnx")
        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "")

        svc = BASCGStatusService()
        p = svc._pillar_synthetic_media()
        assert p.local_ready is False
        assert p.production_ready is False

    def test_onnx_path_in_config_keys(self, monkeypatch):
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_MODE", "onnx")
        monkeypatch.setattr(config.settings,
                            "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "/opt/models/df.onnx")

        svc = BASCGStatusService()
        p = svc._pillar_synthetic_media()
        assert "SYNTHETIC_MEDIA_ONNX_MODEL_PATH" in p.config_keys
        assert p.config_keys["SYNTHETIC_MEDIA_ONNX_MODEL_PATH"] == "/opt/models/df.onnx"

    def test_mock_mode_still_works(self, monkeypatch):
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_MODE", "mock")
        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "")

        svc = BASCGStatusService()
        p = svc._pillar_synthetic_media()
        assert p.local_ready is True
        assert p.production_ready is False  # mock is never prod-ready
        assert p.operational is True

    def test_onnx_prod_steps_when_path_missing(self, monkeypatch):
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_MODE", "onnx")
        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "")

        svc = BASCGStatusService()
        p = svc._pillar_synthetic_media()
        # Should suggest setting the path
        assert any("SYNTHETIC_MEDIA_ONNX_MODEL_PATH" in step
                   for step in p.production_steps)


# ══════════════════════════════════════════════════════════════════════════════
#  T2-D: ECI Election Integrity Webhook
# ══════════════════════════════════════════════════════════════════════════════

class TestECIWebhookService:
    """Unit tests for ECIWebhookService."""

    # ── Stub mode (default) ───────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_stub_mode_returns_sent_false_stub_true(self, monkeypatch):
        from app.core import config
        from app.services.eci_webhook_service import ECIWebhookService

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "stub")
        svc = ECIWebhookService()
        result = await svc.escalate("scan1", "MH", 0.9, ["likely_synthetic"],
                                    "abc123", "mock")
        assert result.stub is True
        assert result.sent is False
        assert result.scan_id == "scan1"

    @pytest.mark.asyncio
    async def test_non_http_mode_also_stubs(self, monkeypatch):
        """Any mode that isn't 'http' → stub behaviour."""
        from app.core import config
        from app.services.eci_webhook_service import ECIWebhookService

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "local")
        svc = ECIWebhookService()
        result = await svc.escalate("scanX", "GJ", 0.8, [], "hash", "mock")
        assert result.stub is True
        assert result.sent is False

    # ── http mode — URL not configured ────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_http_mode_no_url_returns_error(self, monkeypatch):
        from app.core import config
        from app.services.eci_webhook_service import ECIWebhookService

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "http")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_URL", "")
        svc = ECIWebhookService()
        result = await svc.escalate("scan2", "MH", 0.9, [], "hash", "mock")
        assert result.sent is False
        assert result.stub is False
        assert result.error is not None
        assert "ECI_WEBHOOK_URL" in result.error

    # ── http mode — successful POST ───────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_http_mode_successful_post(self, monkeypatch):
        from app.core import config
        from app.services import eci_webhook_service as svc_module

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "http")
        monkeypatch.setattr(config.settings,
                            "ECI_WEBHOOK_URL", "https://eci.example.gov.in/escalate")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_API_KEY", "test-token")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_TIMEOUT_SECONDS", 5)

        # Stub httpx
        class _FakeResponse:
            status_code = 200
            is_success = True
            text = '{"status": "accepted"}'
            def json(self): return {"status": "accepted"}

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def post(self, url, content, headers): return _FakeResponse()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        svc = svc_module.ECIWebhookService()
        result = await svc.escalate("scan3", "MH", 0.95,
                                    ["high_confidence_synthetic"], "deadbeef", "mock")
        assert result.sent is True
        assert result.stub is False
        assert result.status_code == 200
        assert result.response_body == {"status": "accepted"}

    @pytest.mark.asyncio
    async def test_http_mode_non_2xx_returns_error(self, monkeypatch):
        from app.core import config
        from app.services import eci_webhook_service as svc_module

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "http")
        monkeypatch.setattr(config.settings,
                            "ECI_WEBHOOK_URL", "https://eci.example.gov.in/escalate")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_API_KEY", "")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_TIMEOUT_SECONDS", 5)

        class _FakeResponse:
            status_code = 503
            is_success = False
            text = "Service Unavailable"

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def post(self, url, content, headers): return _FakeResponse()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        svc = svc_module.ECIWebhookService()
        result = await svc.escalate("scan4", "MH", 0.9, [], "hash", "mock")
        assert result.sent is False
        assert result.status_code == 503
        assert "503" in result.error

    @pytest.mark.asyncio
    async def test_http_mode_network_error(self, monkeypatch):
        from app.core import config
        from app.services import eci_webhook_service as svc_module

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "http")
        monkeypatch.setattr(config.settings,
                            "ECI_WEBHOOK_URL", "https://eci.example.gov.in/escalate")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_API_KEY", "")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_TIMEOUT_SECONDS", 5)

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def post(self, url, content, headers):
                raise ConnectionError("network unreachable")

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        svc = svc_module.ECIWebhookService()
        result = await svc.escalate("scan5", "MH", 0.9, [], "hash", "mock")
        assert result.sent is False
        assert result.error is not None
        assert "unreachable" in result.error.lower()

    # ── Payload structure ─────────────────────────────────────────────────────

    def test_build_payload_fields(self):
        from app.services.eci_webhook_service import ECIWebhookService
        svc = ECIWebhookService()
        p = svc._build_payload("scanABC", "MH", 0.87,
                               ["likely_synthetic"], "deadbeef", "mock:test")
        assert p["scan_id"]       == "scanABC"
        assert p["state"]         == "MH"
        assert p["confidence"]    == 0.87
        assert p["labels"]        == ["likely_synthetic"]
        assert p["evidence_hash"] == "deadbeef"
        assert p["detector"]      == "mock:test"
        assert p["bascg_version"] == "3.0"
        assert "issued_at"  in p
        assert "nonce"      in p

    def test_build_payload_labels_sorted(self):
        from app.services.eci_webhook_service import ECIWebhookService
        svc = ECIWebhookService()
        p = svc._build_payload("s", "MH", 0.9,
                               ["z_label", "a_label", "m_label"], "h", "mock")
        assert p["labels"] == ["a_label", "m_label", "z_label"]

    def test_build_payload_nonce_unique(self):
        from app.services.eci_webhook_service import ECIWebhookService
        svc = ECIWebhookService()
        p1 = svc._build_payload("s", "MH", 0.9, [], "h", "mock")
        p2 = svc._build_payload("s", "MH", 0.9, [], "h", "mock")
        assert p1["nonce"] != p2["nonce"]

    # ── Signed_by populated in http mode ─────────────────────────────────────

    @pytest.mark.asyncio
    async def test_successful_post_has_signed_by(self, monkeypatch):
        from app.core import config
        from app.services import eci_webhook_service as svc_module

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "http")
        monkeypatch.setattr(config.settings,
                            "ECI_WEBHOOK_URL", "https://eci.example.gov.in/escalate")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_API_KEY", "")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_TIMEOUT_SECONDS", 5)

        class _FakeResponse:
            status_code = 201
            is_success = True
            text = "{}"
            def json(self): return {}

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def post(self, url, content, headers): return _FakeResponse()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        svc = svc_module.ECIWebhookService()
        result = await svc.escalate("scanSB", "MH", 0.9, [], "hash", "mock")
        assert result.signed_by is not None


class TestECIWebhookScanIntegration:
    """scan() ESCALATE path calls eci_webhook_service and sets escalated_to_eci."""

    @pytest.mark.asyncio
    async def test_escalate_path_sets_escalated_flag(self, monkeypatch):
        """When enforcement=ESCALATE, escalated_to_eci reflects the stub result."""
        from app.core import config
        from app.services import synthetic_media_service as svc_module
        from app.services.synthetic_media_service import SyntheticMediaShieldService

        # Enable EPM
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_ENABLED", True)
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_STATE", "MH")
        monkeypatch.setattr(config.settings,
                            "SYNTHETIC_MEDIA_CONFIDENCE_THRESHOLD", 0.60)
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "stub")

        # Force mock detector to return high-confidence synthetic result
        from app.services.synthetic_media_service import DetectionResult

        class _HighConfidenceMock:
            async def detect(self, content, content_type=None):
                return DetectionResult(
                    detector     = "mock",
                    is_synthetic = True,
                    confidence   = 0.95,
                    labels       = ["likely_synthetic"],
                    raw_response = {},
                )

        service = SyntheticMediaShieldService()
        monkeypatch.setattr(service, "_get_detector", lambda: _HighConfidenceMock())

        result = await service.scan(b"fake content")
        assert result.enforcement_action == "ESCALATE"
        # stub mode: sent=False but stub=True → escalated_to_eci=True
        assert result.escalated_to_eci is True

    @pytest.mark.asyncio
    async def test_non_election_context_no_escalation(self, monkeypatch):
        """Without EPM enabled, even synthetic content is ALERT not ESCALATE."""
        from app.core import config
        from app.services.synthetic_media_service import (
            SyntheticMediaShieldService,
            DetectionResult,
        )

        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_ENABLED", False)
        monkeypatch.setattr(config.settings,
                            "SYNTHETIC_MEDIA_CONFIDENCE_THRESHOLD", 0.60)

        class _HighConfidenceMock:
            async def detect(self, content, content_type=None):
                return DetectionResult(
                    detector="mock", is_synthetic=True, confidence=0.95,
                    labels=["likely_synthetic"], raw_response={},
                )

        service = SyntheticMediaShieldService()
        monkeypatch.setattr(service, "_get_detector", lambda: _HighConfidenceMock())

        result = await service.scan(b"content")
        assert result.enforcement_action == "ALERT"
        assert result.escalated_to_eci is False


class TestECIWebhookConfig:
    """Config fields for ECI webhook exist with correct defaults."""

    def test_eci_webhook_mode_default_stub(self):
        from app.core.config import Settings
        assert Settings().ECI_WEBHOOK_MODE == "stub"

    def test_eci_webhook_url_default_empty(self):
        from app.core.config import Settings
        assert Settings().ECI_WEBHOOK_URL == ""

    def test_eci_webhook_api_key_default_empty(self):
        from app.core.config import Settings
        assert Settings().ECI_WEBHOOK_API_KEY == ""

    def test_eci_webhook_timeout_default(self):
        from app.core.config import Settings
        assert Settings().ECI_WEBHOOK_TIMEOUT_SECONDS == 10


class TestBASCGStatusECIWebhook:
    """Status service correctly surfaces ECI webhook mode in P4 pillar."""

    def test_eci_stub_mode_in_config_keys(self, monkeypatch):
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "stub")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_URL", "")
        p = BASCGStatusService()._pillar_synthetic_media()
        assert p.config_keys["ECI_WEBHOOK_MODE"] == "stub"
        assert p.config_keys["ECI_WEBHOOK_URL"] == "(not set)"

    def test_eci_live_url_in_config_keys(self, monkeypatch):
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "http")
        monkeypatch.setattr(config.settings,
                            "ECI_WEBHOOK_URL", "https://eci.gov.in/bus")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_API_KEY", "secret")
        p = BASCGStatusService()._pillar_synthetic_media()
        assert p.config_keys["ECI_WEBHOOK_MODE"] == "http"
        assert p.config_keys["ECI_WEBHOOK_URL"] == "https://eci.gov.in/bus"
        assert p.config_keys["ECI_WEBHOOK_API_KEY"] == "***"

    def test_epm_on_stub_mode_shows_prod_step(self, monkeypatch):
        """When EPM is enabled but ECI webhook is stub → production step added."""
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_MODE", "mock")
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_ENABLED", True)
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_STATE", "MH")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "stub")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_URL", "")
        p = BASCGStatusService()._pillar_synthetic_media()
        assert any("ECI_WEBHOOK_MODE" in step for step in p.production_steps)

    def test_epm_on_http_no_url_shows_prod_step(self, monkeypatch):
        """http mode but URL missing → production step to set the URL."""
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_MODE", "mock")
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_ENABLED", True)
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_STATE", "MH")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "http")
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_URL", "")
        p = BASCGStatusService()._pillar_synthetic_media()
        assert any("ECI_WEBHOOK_URL" in step for step in p.production_steps)

    def test_epm_off_eci_off_no_step(self, monkeypatch):
        """When EPM disabled, no ECI-related production step."""
        from app.core import config
        from app.services.bascg_status_service import BASCGStatusService

        monkeypatch.setattr(config.settings, "SYNTHETIC_MEDIA_MODE", "mock")
        monkeypatch.setattr(config.settings, "ELECTION_PROTECTION_ENABLED", False)
        monkeypatch.setattr(config.settings, "ECI_WEBHOOK_MODE", "stub")
        p = BASCGStatusService()._pillar_synthetic_media()
        # No ECI steps when EPM is off
        assert not any("ECI_WEBHOOK_MODE" in step for step in p.production_steps)


# ══════════════════════════════════════════════════════════════════════════════
#  T3-A: NAIR-I Bidirectional Sync
# ══════════════════════════════════════════════════════════════════════════════

class TestNAIRSyncService:
    """Unit + integration tests for NAIRSyncService."""

    @pytest.fixture(autouse=True)
    def init_crypto(self):
        from app.core.crypto import crypto_service
        crypto_service.initialize()

    @pytest.fixture
    async def db(self):
        """In-memory async SQLite session with all ORM tables."""
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from app.db.database import Base
        import app.models.orm_models  # noqa: F401

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            yield session
        await engine.dispose()

    # ── Local / stub mode: pull returns immediately ───────────────────────────

    @pytest.mark.asyncio
    async def test_pull_local_mode_skips(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "local")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL", "")

        result = await NAIRSyncService().pull_from_national_node(db)
        assert result.pulled_count == 0
        assert result.created      == 0
        assert result.node_url     == "local"

    @pytest.mark.asyncio
    async def test_pull_no_url_skips(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "production")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL", "")

        result = await NAIRSyncService().pull_from_national_node(db)
        assert result.pulled_count == 0

    # ── Pull: creates new stub for unknown model ──────────────────────────────

    @pytest.mark.asyncio
    async def test_pull_creates_new_model(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService
        from app.services.registry_service import registry_service

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "production")
        monkeypatch.setattr(config.settings,
                            "BASCG_NATIONAL_NODE_URL", "https://nair.example.gov.in")
        monkeypatch.setattr(config.settings, "NAIR_PULL_VERIFY_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 5)
        monkeypatch.setattr(config.settings, "NAIR_PULL_PAGE_SIZE", 100)

        national_entry = {
            "id":             "national-model-001",
            "name":           "CreditScoreV2",
            "version":        "2.0",
            "risk_category":  "HIGH",
            "registry_status": "ACTIVE",
            "sector":         "finance",
            "owner":          "HDFC Bank",
        }

        class _FakeResp:
            status_code = 200
            is_success  = True
            def json(self): return [national_entry]

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url): return _FakeResp()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        svc = NAIRSyncService()
        result = await svc.pull_from_national_node(db)

        assert result.created == 1
        assert result.pulled_count == 1

        m = await registry_service.get_model(db, "national-model-001")
        assert m is not None
        assert m.name == "CreditScoreV2"
        assert m.nair_source == "national"
        assert m.nair_pulled_at is not None

    # ── Pull: updates authority-owned fields on existing model ────────────────

    @pytest.mark.asyncio
    async def test_pull_updates_existing_model(self, db, monkeypatch):
        from app.core import config
        from app.models.orm_models import AIModel
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "production")
        monkeypatch.setattr(config.settings,
                            "BASCG_NATIONAL_NODE_URL", "https://nair.example.gov.in")
        monkeypatch.setattr(config.settings, "NAIR_PULL_VERIFY_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 5)
        monkeypatch.setattr(config.settings, "NAIR_PULL_PAGE_SIZE", 100)

        # Seed a local model with outdated risk category
        local_model = AIModel(
            id="existing-001", name="FraudDetect", version="1.0",
            risk_category="LOW", registry_status="ACTIVE",
        )
        db.add(local_model)
        await db.commit()

        national_entry = {
            "id":             "existing-001",
            "name":           "FraudDetect",
            "version":        "1.0",
            "risk_category":  "HIGH",   # national says HIGH
            "registry_status": "ACTIVE",
        }

        class _FakeResp:
            status_code = 200
            is_success  = True
            def json(self): return [national_entry]

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url): return _FakeResp()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        svc = NAIRSyncService()
        result = await svc.pull_from_national_node(db)

        assert result.updated == 1
        assert result.created == 0

        await db.refresh(local_model)
        assert local_model.risk_category == "HIGH"
        assert local_model.nair_pulled_at is not None

    # ── Pull: skips entry with no id ──────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_pull_skips_entry_with_no_id(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "production")
        monkeypatch.setattr(config.settings,
                            "BASCG_NATIONAL_NODE_URL", "https://nair.example.gov.in")
        monkeypatch.setattr(config.settings, "NAIR_PULL_VERIFY_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 5)
        monkeypatch.setattr(config.settings, "NAIR_PULL_PAGE_SIZE", 100)

        class _FakeResp:
            status_code = 200
            is_success  = True
            def json(self): return [{"name": "NoId"}]   # missing "id"

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url): return _FakeResp()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        result = await NAIRSyncService().pull_from_national_node(db)
        assert result.skipped == 1
        assert result.created == 0

    # ── Pull: signature verification rejects tampered entry ──────────────────

    @pytest.mark.asyncio
    async def test_pull_rejects_invalid_signature(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "production")
        monkeypatch.setattr(config.settings,
                            "BASCG_NATIONAL_NODE_URL", "https://nair.example.gov.in")
        monkeypatch.setattr(config.settings, "NAIR_PULL_VERIFY_SIGNATURES", True)
        monkeypatch.setattr(config.settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 5)
        monkeypatch.setattr(config.settings, "NAIR_PULL_PAGE_SIZE", 100)

        # Entry with a bogus signature
        wrapped = {
            "entry":     {"id": "bad-sig-001", "name": "Tampered", "version": "1"},
            "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "signed_by": "dev-local",
        }

        class _FakeResp:
            status_code = 200
            is_success  = True
            def json(self): return [wrapped]

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url): return _FakeResp()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        result = await NAIRSyncService().pull_from_national_node(db)
        assert result.skipped == 1
        assert result.created == 0
        assert any("signature" in e for e in result.errors)

    # ── Pull: valid signature accepted ────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_pull_accepts_valid_signature(self, db, monkeypatch):
        from app.core import config
        from app.core.crypto import crypto_service
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "production")
        monkeypatch.setattr(config.settings,
                            "BASCG_NATIONAL_NODE_URL", "https://nair.example.gov.in")
        monkeypatch.setattr(config.settings, "NAIR_PULL_VERIFY_SIGNATURES", True)
        monkeypatch.setattr(config.settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 5)
        monkeypatch.setattr(config.settings, "NAIR_PULL_PAGE_SIZE", 100)

        entry   = {"id": "valid-sig-001", "name": "SignedModel", "version": "1",
                   "risk_category": "LOW", "registry_status": "ACTIVE"}
        sig     = crypto_service.signer.sign(entry)
        issuer  = crypto_service.signer.issuer
        wrapped = {"entry": entry, "signature": sig, "signed_by": issuer}

        class _FakeResp:
            status_code = 200
            is_success  = True
            def json(self): return [wrapped]

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url): return _FakeResp()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        result = await NAIRSyncService().pull_from_national_node(db)
        assert result.created == 1
        assert result.skipped == 0

    # ── Pull: HTTP error returns failed result ────────────────────────────────

    @pytest.mark.asyncio
    async def test_pull_network_error_returns_failed(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "production")
        monkeypatch.setattr(config.settings,
                            "BASCG_NATIONAL_NODE_URL", "https://nair.example.gov.in")
        monkeypatch.setattr(config.settings, "NAIR_PULL_VERIFY_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 5)

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url): raise ConnectionError("timeout")

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        result = await NAIRSyncService().pull_from_national_node(db)
        assert result.failed > 0
        assert any("timeout" in e or "Network error" in e for e in result.errors)

    # ── Pull: pagination fetches multiple pages ───────────────────────────────

    @pytest.mark.asyncio
    async def test_pull_paginates_multiple_pages(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "production")
        monkeypatch.setattr(config.settings,
                            "BASCG_NATIONAL_NODE_URL", "https://nair.example.gov.in")
        monkeypatch.setattr(config.settings, "NAIR_PULL_VERIFY_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "BASCG_FEDERATION_TIMEOUT_SECONDS", 5)
        monkeypatch.setattr(config.settings, "NAIR_PULL_PAGE_SIZE", 2)  # small page

        pages = [
            [{"id": "m1", "name": "M1", "version": "1"},
             {"id": "m2", "name": "M2", "version": "1"}],
            [{"id": "m3", "name": "M3", "version": "1"}],   # last page (< page_size)
        ]
        call_count = [0]

        class _FakeResp:
            def __init__(self, data):
                self.status_code = 200
                self.is_success  = True
                self._data = data
            def json(self): return self._data

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url):
                idx = call_count[0]
                call_count[0] += 1
                return _FakeResp(pages[idx] if idx < len(pages) else [])

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        result = await NAIRSyncService().pull_from_national_node(db)
        assert result.pulled_count == 3
        assert result.created      == 3
        assert call_count[0]       == 2   # exactly 2 GET calls

    # ── Bidirectional sync ────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_bidirectional_sync_local_mode_all_skipped(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "local")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL", "")

        result = await NAIRSyncService().bidirectional_sync(db)
        assert result.push_ok      == 0
        assert result.pull.created == 0
        assert result.node_url     == "local"

    @pytest.mark.asyncio
    async def test_bidirectional_result_has_all_fields(self, db, monkeypatch):
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncService, BidirectionalSyncResult

        monkeypatch.setattr(config.settings, "BASCG_PROVIDER_MODE", "local")
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL", "")

        result = await NAIRSyncService().bidirectional_sync(db)
        assert isinstance(result, BidirectionalSyncResult)
        assert result.completed_at != ""


class TestNAIRSyncWorker:
    """Background worker lifecycle tests."""

    def test_worker_start_disabled_by_default(self, monkeypatch):
        """Worker does not create a task when NAIR_SYNC_ENABLED=False."""
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncWorker

        monkeypatch.setattr(config.settings, "NAIR_SYNC_ENABLED", False)
        w = NAIRSyncWorker()
        w.start_background_worker()
        assert w._task is None

    def test_worker_start_no_url_skips(self, monkeypatch):
        """Worker does not start when NAIR_SYNC_ENABLED=True but URL is empty."""
        from app.core import config
        from app.services.nair_sync_service import NAIRSyncWorker

        monkeypatch.setattr(config.settings, "NAIR_SYNC_ENABLED", True)
        monkeypatch.setattr(config.settings, "BASCG_NATIONAL_NODE_URL", "")
        w = NAIRSyncWorker()
        w.start_background_worker()
        assert w._task is None

    def test_stop_no_task_is_safe(self):
        """stop() is safe to call even if no task was started."""
        from app.services.nair_sync_service import NAIRSyncWorker
        w = NAIRSyncWorker()
        w.stop()   # must not raise

    def test_main_lifespan_imports_worker(self):
        """main.py imports nair_sync_worker."""
        import inspect
        from app import main
        src = inspect.getsource(main)
        assert "nair_sync_worker" in src
        assert "start_background_worker" in src


class TestNAIRSyncConfig:
    """Config fields for NAIR bidirectional sync have correct defaults."""

    def test_nair_sync_enabled_default_false(self):
        from app.core.config import Settings
        assert Settings().NAIR_SYNC_ENABLED is False

    def test_nair_sync_interval_default(self):
        from app.core.config import Settings
        assert Settings().NAIR_SYNC_INTERVAL_MINUTES == 30

    def test_nair_pull_page_size_default(self):
        from app.core.config import Settings
        assert Settings().NAIR_PULL_PAGE_SIZE == 100

    def test_nair_pull_verify_signatures_default(self):
        from app.core.config import Settings
        assert Settings().NAIR_PULL_VERIFY_SIGNATURES is True


class TestNAIROrmColumns:
    """ORM model has the T3-A columns."""

    def test_aimodel_has_nair_source_column(self):
        from app.models.orm_models import AIModel
        assert hasattr(AIModel, "nair_source")

    def test_aimodel_has_nair_pulled_at_column(self):
        from app.models.orm_models import AIModel
        assert hasattr(AIModel, "nair_pulled_at")


class TestNAIRAPIEndpoints:
    """Registry API has the T3-A endpoints."""

    def test_sync_pull_endpoint_present(self):
        import inspect
        from app.api import registry
        src = inspect.getsource(registry)
        assert "sync-pull"        in src
        assert "sync_pull"        in src or "sync-pull" in src

    def test_sync_bidirectional_endpoint_present(self):
        import inspect
        from app.api import registry
        src = inspect.getsource(registry)
        assert "sync-bidirectional" in src
        assert "bidirectional_sync"  in src

    def test_endpoints_require_policies_write(self):
        import inspect
        from app.api import registry
        src = inspect.getsource(registry.sync_pull_from_national_node)
        assert "policies:write" in src
        src2 = inspect.getsource(registry.sync_bidirectional)
        assert "policies:write" in src2


# ══════════════════════════════════════════════════════════════════════════════
#  T3-B: Multi-node Policy Consensus
# ══════════════════════════════════════════════════════════════════════════════

class TestConsensusService:
    """Unit + integration tests for ConsensusService."""

    @pytest.fixture(autouse=True)
    def init_crypto(self):
        from app.core.crypto import crypto_service
        crypto_service.initialize()

    @pytest.fixture
    async def db(self):
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from app.db.database import Base
        import app.models.orm_models  # noqa: F401

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            yield session
        await engine.dispose()

    # ── propose ───────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_propose_creates_pending_proposal(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_NODE_ID", "node-test-01")
        monkeypatch.setattr(config.settings, "CONSENSUS_PROPOSAL_TTL_HOURS", 24)

        svc = ConsensusService()
        p = await svc.propose(
            db            = db,
            proposal_type = "create_policy",
            title         = "Add AML Policy",
            payload       = {"name": "AML Block", "rules": [{"rule_id": "x"}]},
        )
        assert p.status        == "pending"
        assert p.proposal_type == "create_policy"
        assert p.proposed_by   == "node-test-01"
        assert p.proposal_signature is not None
        assert p.expires_at is not None

    @pytest.mark.asyncio
    async def test_propose_invalid_type_raises(self, db):
        from app.services.consensus_service import ConsensusService
        with pytest.raises(ValueError, match="Invalid proposal_type"):
            await ConsensusService().propose(
                db=db, proposal_type="fly_to_moon",
                title="T", payload={}
            )

    @pytest.mark.asyncio
    async def test_propose_invalid_payload_raises(self, db):
        from app.services.consensus_service import ConsensusService
        with pytest.raises(ValueError, match="must include 'name'"):
            await ConsensusService().propose(
                db=db, proposal_type="create_policy",
                title="T", payload={"rules": []}   # missing name
            )

    @pytest.mark.asyncio
    async def test_propose_update_threshold_bad_key_raises(self, db):
        from app.services.consensus_service import ConsensusService
        with pytest.raises(ValueError, match="threshold_key"):
            await ConsensusService().propose(
                db=db, proposal_type="update_threshold",
                title="T", payload={"threshold_key": "UNKNOWN_KEY", "value": 0.5}
            )

    @pytest.mark.asyncio
    async def test_propose_is_signed(self, db):
        from app.services.consensus_service import ConsensusService
        svc = ConsensusService()
        p = await svc.propose(
            db=db, proposal_type="create_policy",
            title="Signed Prop",
            payload={"name": "P", "rules": []}
        )
        assert p.proposal_signature is not None
        assert p.signed_by is not None

    # ── cast_vote ─────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_cast_vote_accept(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})
        v   = await svc.cast_vote(db=db, proposal_id=p.id,
                                   node_id="node-A", vote="accept")
        assert v.vote    == "accept"
        assert v.node_id == "node-A"

    @pytest.mark.asyncio
    async def test_cast_vote_reject(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})
        v   = await svc.cast_vote(db=db, proposal_id=p.id,
                                   node_id="node-B", vote="reject")
        assert v.vote == "reject"

    @pytest.mark.asyncio
    async def test_duplicate_vote_raises(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="node-A", vote="accept")
        with pytest.raises(ValueError, match="already voted"):
            await svc.cast_vote(db=db, proposal_id=p.id, node_id="node-A", vote="reject")

    @pytest.mark.asyncio
    async def test_vote_on_nonexistent_proposal_raises(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        with pytest.raises(ValueError, match="not found"):
            await ConsensusService().cast_vote(
                db=db, proposal_id="does-not-exist",
                node_id="N", vote="accept"
            )

    @pytest.mark.asyncio
    async def test_vote_bad_value_raises(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})
        with pytest.raises(ValueError, match="accept.*reject"):
            await svc.cast_vote(db=db, proposal_id=p.id,
                                 node_id="N", vote="maybe")

    @pytest.mark.asyncio
    async def test_vote_invalid_signature_raises(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", True)
        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})
        with pytest.raises(ValueError, match="signature verification failed"):
            await svc.cast_vote(
                db=db, proposal_id=p.id, node_id="node-X", vote="accept",
                signature="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                signed_by="dev-local",
            )

    @pytest.mark.asyncio
    async def test_vote_valid_signature_accepted(self, db, monkeypatch):
        from app.core import config
        from app.core.crypto import crypto_service
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", True)
        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})

        # Build and sign the vote payload: {proposal_id, node_id, vote} only
        # (voted_at is server-assigned; not included in canonical signature payload)
        vote_payload = {
            "proposal_id": p.id,
            "node_id":     "node-signed",
            "vote":        "accept",
        }
        sig    = crypto_service.signer.sign(vote_payload)
        issuer = crypto_service.signer.issuer

        v = await svc.cast_vote(
            db=db, proposal_id=p.id, node_id="node-signed", vote="accept",
            signature=sig, signed_by=issuer,
        )
        assert v.vote == "accept"

    # ── tally ─────────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_tally_pending_when_not_enough_votes(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "CONSENSUS_MIN_VOTES", 3)
        monkeypatch.setattr(config.settings, "CONSENSUS_QUORUM_THRESHOLD", 0.67)

        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="A", vote="accept")
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="B", vote="accept")

        result = await svc.tally(db, p.id)
        assert result.status    == "pending"
        assert result.quorum_met is False

    @pytest.mark.asyncio
    async def test_tally_accepted_applies_policy(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "CONSENSUS_MIN_VOTES", 2)
        monkeypatch.setattr(config.settings, "CONSENSUS_QUORUM_THRESHOLD", 0.67)

        svc = ConsensusService()
        p   = await svc.propose(
            db=db, proposal_type="create_policy",
            title="New Safety Policy",
            payload={"name": "Safety-Consensus", "rules": [{"rule_id": "cs-001"}],
                     "policy_type": "safety"},
        )
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="A", vote="accept")
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="B", vote="accept")

        result = await svc.tally(db, p.id)
        assert result.status         == "accepted"
        assert result.quorum_met     is True
        assert result.applied        is True
        assert result.applied_policy_id is not None

        # Verify the policy was actually persisted
        from sqlalchemy import select
        from app.models.orm_models import GovernancePolicy
        pol_q = await db.execute(
            select(GovernancePolicy).where(GovernancePolicy.id == result.applied_policy_id)
        )
        pol = pol_q.scalars().first()
        assert pol is not None
        assert pol.name == "Safety-Consensus"

    @pytest.mark.asyncio
    async def test_tally_rejected_when_majority_rejects(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "CONSENSUS_MIN_VOTES", 2)
        monkeypatch.setattr(config.settings, "CONSENSUS_QUORUM_THRESHOLD", 0.67)

        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="A", vote="accept")
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="B", vote="reject")
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="C", vote="reject")
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="D", vote="reject")

        result = await svc.tally(db, p.id)
        assert result.status    == "rejected"
        assert result.applied   is False

    @pytest.mark.asyncio
    async def test_tally_update_threshold(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "CONSENSUS_MIN_VOTES", 2)
        monkeypatch.setattr(config.settings, "CONSENSUS_QUORUM_THRESHOLD", 0.5)
        monkeypatch.setattr(config.settings, "RISK_SCORE_HIGH_THRESHOLD", 0.60)

        svc = ConsensusService()
        p   = await svc.propose(
            db=db, proposal_type="update_threshold",
            title="Lower risk threshold",
            payload={"threshold_key": "RISK_SCORE_HIGH_THRESHOLD", "value": 0.50},
        )
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="A", vote="accept")
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="B", vote="accept")

        result = await svc.tally(db, p.id)
        assert result.status  == "accepted"
        assert result.applied is True        # threshold changes return applied=True only if no error
        assert float(config.settings.RISK_SCORE_HIGH_THRESHOLD) == pytest.approx(0.50)

    @pytest.mark.asyncio
    async def test_tally_disable_policy(self, db, monkeypatch):
        from app.core import config
        from app.models.orm_models import GovernancePolicy
        from app.services.consensus_service import ConsensusService
        from sqlalchemy import select

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "CONSENSUS_MIN_VOTES", 2)
        monkeypatch.setattr(config.settings, "CONSENSUS_QUORUM_THRESHOLD", 0.5)

        # Seed an existing policy
        pol = GovernancePolicy(name="ToDisable", enabled=True,
                               policy_type="safety", rules=[])
        db.add(pol)
        await db.commit()
        await db.refresh(pol)

        svc = ConsensusService()
        p   = await svc.propose(
            db=db, proposal_type="disable_policy",
            title="Disable ToDisable",
            payload={"policy_id": pol.id},
        )
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="A", vote="accept")
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="B", vote="accept")
        result = await svc.tally(db, p.id)

        assert result.status == "accepted"
        await db.refresh(pol)
        assert pol.enabled is False

    @pytest.mark.asyncio
    async def test_tally_update_policy_fields(self, db, monkeypatch):
        from app.core import config
        from app.models.orm_models import GovernancePolicy
        from app.services.consensus_service import ConsensusService
        from sqlalchemy import select

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "CONSENSUS_MIN_VOTES", 2)
        monkeypatch.setattr(config.settings, "CONSENSUS_QUORUM_THRESHOLD", 0.5)

        pol = GovernancePolicy(name="Original", severity="low",
                               policy_type="safety", rules=[])
        db.add(pol)
        await db.commit()
        await db.refresh(pol)

        svc = ConsensusService()
        p   = await svc.propose(
            db=db, proposal_type="update_policy",
            title="Escalate severity",
            payload={"policy_id": pol.id, "fields": {"severity": "critical"}},
        )
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="A", vote="accept")
        await svc.cast_vote(db=db, proposal_id=p.id, node_id="B", vote="accept")
        await svc.tally(db, p.id)

        await db.refresh(pol)
        assert pol.severity == "critical"

    # ── expiry ────────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_expired_proposal_cannot_receive_votes(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService
        from datetime import datetime, timezone, timedelta

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        monkeypatch.setattr(config.settings, "CONSENSUS_PROPOSAL_TTL_HOURS", 1)

        svc = ConsensusService()
        p   = await svc.propose(db=db, proposal_type="create_policy",
                                title="T", payload={"name": "P", "rules": []})

        # Fast-forward expiry
        p.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
        await db.commit()

        with pytest.raises(ValueError, match="expired"):
            await svc.cast_vote(db=db, proposal_id=p.id, node_id="A", vote="accept")

    @pytest.mark.asyncio
    async def test_expire_stale_proposals(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService
        from datetime import datetime, timezone, timedelta

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        svc = ConsensusService()

        # Two proposals — one past TTL, one not
        p_old = await svc.propose(db=db, proposal_type="create_policy",
                                  title="Old", payload={"name": "O", "rules": []})
        p_new = await svc.propose(db=db, proposal_type="create_policy",
                                  title="New", payload={"name": "N", "rules": []})

        p_old.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        await db.commit()

        count = await svc.expire_stale_proposals(db)
        assert count == 1

        await db.refresh(p_old)
        await db.refresh(p_new)
        assert p_old.status == "expired"
        assert p_new.status == "pending"

    # ── list / get ────────────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_list_proposals_filter_by_status(self, db, monkeypatch):
        from app.core import config
        from app.services.consensus_service import ConsensusService
        from datetime import datetime, timezone, timedelta

        monkeypatch.setattr(config.settings, "CONSENSUS_VERIFY_VOTE_SIGNATURES", False)
        svc = ConsensusService()

        p1 = await svc.propose(db=db, proposal_type="create_policy",
                               title="P1", payload={"name": "A", "rules": []})
        p2 = await svc.propose(db=db, proposal_type="create_policy",
                               title="P2", payload={"name": "B", "rules": []})
        p1.status = "accepted"
        await db.commit()

        pending = await svc.list_proposals(db, status="pending")
        accepted = await svc.list_proposals(db, status="accepted")

        assert any(p.id == p2.id for p in pending)
        assert any(p.id == p1.id for p in accepted)


class TestConsensusORM:
    """PolicyProposal and PolicyVote ORM tables exist."""

    def test_policy_proposal_table(self):
        from app.models.orm_models import PolicyProposal
        assert PolicyProposal.__tablename__ == "policy_proposals"
        assert hasattr(PolicyProposal, "proposal_type")
        assert hasattr(PolicyProposal, "status")
        assert hasattr(PolicyProposal, "expires_at")
        assert hasattr(PolicyProposal, "proposal_signature")

    def test_policy_vote_table(self):
        from app.models.orm_models import PolicyVote
        assert PolicyVote.__tablename__ == "policy_votes"
        assert hasattr(PolicyVote, "vote")
        assert hasattr(PolicyVote, "node_id")
        assert hasattr(PolicyVote, "signature")

    def test_proposal_vote_relationship(self):
        from app.models.orm_models import PolicyProposal
        assert hasattr(PolicyProposal, "votes")


class TestConsensusConfig:
    """Consensus config fields have correct defaults."""

    def test_consensus_enabled_default_false(self):
        from app.core.config import Settings
        assert Settings().CONSENSUS_ENABLED is False

    def test_quorum_threshold_default(self):
        from app.core.config import Settings
        assert Settings().CONSENSUS_QUORUM_THRESHOLD == pytest.approx(0.67)

    def test_min_votes_default(self):
        from app.core.config import Settings
        assert Settings().CONSENSUS_MIN_VOTES == 2

    def test_ttl_hours_default(self):
        from app.core.config import Settings
        assert Settings().CONSENSUS_PROPOSAL_TTL_HOURS == 72

    def test_verify_signatures_default_true(self):
        from app.core.config import Settings
        assert Settings().CONSENSUS_VERIFY_VOTE_SIGNATURES is True

    def test_node_id_default(self):
        from app.core.config import Settings
        assert Settings().CONSENSUS_NODE_ID == "local-node"


class TestConsensusAPI:
    """Consensus API router endpoints are wired and have correct permissions."""

    def test_router_mounted_in_main(self):
        import inspect
        from app import main
        src = inspect.getsource(main)
        assert "consensus_api" in src
        assert "/api/v1/consensus" in src

    def test_create_proposal_requires_policy_write(self):
        import inspect
        from app.api import consensus
        src = inspect.getsource(consensus.create_proposal)
        assert "policies:write" in src

    def test_cast_vote_requires_policy_write(self):
        import inspect
        from app.api import consensus
        src = inspect.getsource(consensus.cast_vote)
        assert "policies:write" in src

    def test_tally_requires_policy_write(self):
        import inspect
        from app.api import consensus
        src = inspect.getsource(consensus.tally_proposal)
        assert "policies:write" in src

    def test_list_proposals_requires_policy_read(self):
        import inspect
        from app.api import consensus
        src = inspect.getsource(consensus.list_proposals)
        assert "policies:read" in src

    def test_status_endpoint_present(self):
        import inspect
        from app.api import consensus
        src = inspect.getsource(consensus)
        assert "consensus_status" in src
        assert "/status" in src

    def test_disabled_by_default_raises_503(self, monkeypatch):
        from app.core import config
        from app.api.consensus import _check_enabled
        monkeypatch.setattr(config.settings, "CONSENSUS_ENABLED", False)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _check_enabled()
        assert exc_info.value.status_code == 503

    def test_enabled_flag_allows_access(self, monkeypatch):
        from app.core import config
        from app.api.consensus import _check_enabled
        monkeypatch.setattr(config.settings, "CONSENSUS_ENABLED", True)
        _check_enabled()   # must not raise


# ══════════════════════════════════════════════════════════════════════════════
#  T3-C: Distributed TEE Attestation
# ══════════════════════════════════════════════════════════════════════════════

class TestDistributedTEEORM:
    """RemoteNodeAttestation ORM model has required columns."""

    def test_remote_node_attestation_columns_exist(self):
        from app.models.orm_models import RemoteNodeAttestation
        cols = {c.key for c in RemoteNodeAttestation.__table__.columns}
        for expected in (
            "id", "node_id", "node_url", "platform", "pcr0", "pcr0_match",
            "verified", "failure_reason", "clearance_valid_until",
            "raw_document_b64", "nonce", "attested_at",
        ):
            assert expected in cols, f"Missing column: {expected}"

    def test_remote_node_attestation_verified_column_default(self):
        from app.models.orm_models import RemoteNodeAttestation
        col = RemoteNodeAttestation.__table__.c["verified"]
        # Column-level default should be False (not null)
        assert col.default is not None
        assert col.default.arg is False


class TestDistributedTEEConfig:
    """Config settings exist and have correct defaults."""

    def test_distributed_enabled_default_false(self):
        from app.core.config import Settings
        assert Settings().TEE_DISTRIBUTED_ENABLED is False

    def test_peer_nodes_default_empty(self):
        from app.core.config import Settings
        assert Settings().TEE_PEER_NODES == ""

    def test_challenge_timeout_default(self):
        from app.core.config import Settings
        assert Settings().TEE_DISTRIBUTED_CHALLENGE_TIMEOUT_SECONDS == 10

    def test_auto_challenge_interval_default(self):
        from app.core.config import Settings
        assert Settings().TEE_AUTO_CHALLENGE_INTERVAL_MINUTES == 60


class TestDistributedTEEService:
    """Unit tests for DistributedTEEService logic."""

    @pytest.fixture
    async def db(self):
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from app.db.database import Base
        import app.models.orm_models  # noqa: F401

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            yield session
        await engine.dispose()

    # ── disabled mode returns skipped ────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_challenge_skips_when_disabled(self, db, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEService
        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", False)
        svc = DistributedTEEService()
        result = await svc.challenge_peer(db, "http://peer", "peer-1")
        assert result.skipped is True
        assert result.success is False

    @pytest.mark.asyncio
    async def test_push_skips_when_disabled(self, db, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEService
        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", False)
        svc = DistributedTEEService()
        result = await svc.push_local_attestation(db, "http://peer")
        assert result.skipped is True
        assert result.sent is False

    # ── respond_to_challenge generates document ───────────────────────────────

    def test_respond_returns_raw_document_b64(self, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEService
        monkeypatch.setattr(config.settings, "TEE_ATTESTATION_MODE", "mock")
        monkeypatch.setattr(config.settings, "CONSENSUS_NODE_ID", "test-node")
        svc = DistributedTEEService()
        result = svc.respond_to_challenge(nonce="abc123")
        assert "raw_document_b64" in result
        assert result["raw_document_b64"]
        assert result["node_id"] == "test-node"
        assert result["platform"] == "mock"

    def test_respond_includes_expected_pcr0_for_mock(self, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEService
        from app.services.tee_attestation_service import MOCK_PCR0
        monkeypatch.setattr(config.settings, "TEE_ATTESTATION_MODE", "mock")
        svc = DistributedTEEService()
        result = svc.respond_to_challenge(nonce="nonce-xyz")
        assert result["expected_pcr0"] == MOCK_PCR0

    # ── receive_peer_attestation persists record ──────────────────────────────

    @pytest.mark.asyncio
    async def test_receive_persists_unverified_record(self, db):
        from app.services.distributed_tee_service import DistributedTEEService
        svc = DistributedTEEService()
        record = await svc.receive_peer_attestation(
            db                    = db,
            node_id               = "remote-node-1",
            node_url              = "http://remote:8000",
            platform              = "mock",
            pcr0                  = "aabbcc",
            pcr0_match            = True,
            clearance_valid_until = None,
        )
        assert record.id is not None
        assert record.node_id  == "remote-node-1"
        assert record.verified is False   # pushed attestations are unverified

    @pytest.mark.asyncio
    async def test_receive_parses_iso_clearance_date(self, db):
        from app.services.distributed_tee_service import DistributedTEEService
        from datetime import datetime, timezone, timedelta
        svc = DistributedTEEService()
        ts  = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        record = await svc.receive_peer_attestation(
            db                    = db,
            node_id               = "remote-node-2",
            node_url              = "http://remote:8000",
            platform              = "mock",
            pcr0                  = None,
            pcr0_match            = False,
            clearance_valid_until = ts,
        )
        assert record.clearance_valid_until is not None

    # ── list_peers deduplicates by node_id ────────────────────────────────────

    @pytest.mark.asyncio
    async def test_list_peers_returns_latest_per_node(self, db):
        from app.services.distributed_tee_service import DistributedTEEService
        from app.models.orm_models import RemoteNodeAttestation
        import time

        # Insert two records for the same node_id
        for i in range(2):
            r = RemoteNodeAttestation(
                node_id  = "dup-node",
                node_url = "http://dup:8000",
                platform = "mock",
                verified = False,
            )
            db.add(r)
            await db.commit()

        # And one record for a different node
        r2 = RemoteNodeAttestation(
            node_id  = "other-node",
            node_url = "http://other:8000",
            platform = "mock",
            verified = False,
        )
        db.add(r2)
        await db.commit()

        svc    = DistributedTEEService()
        peers  = await svc.list_peers(db)
        # Should have exactly two unique nodes
        ids = [p.node_id for p in peers]
        assert len(ids) == 2
        assert "dup-node"   in ids
        assert "other-node" in ids

    # ── get_peer_status ───────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_get_peer_status_returns_none_for_unknown(self, db):
        from app.services.distributed_tee_service import DistributedTEEService
        svc = DistributedTEEService()
        result = await svc.get_peer_status(db, "ghost-node")
        assert result is None

    @pytest.mark.asyncio
    async def test_get_peer_status_returns_record(self, db):
        from app.services.distributed_tee_service import DistributedTEEService
        svc = DistributedTEEService()
        await svc.receive_peer_attestation(
            db=db, node_id="found-node", node_url="http://found:8000",
            platform="mock", pcr0=None, pcr0_match=False,
            clearance_valid_until=None,
        )
        result = await svc.get_peer_status(db, "found-node")
        assert result is not None
        assert result.node_id == "found-node"

    # ── challenge_peer: network error is captured, not raised ─────────────────

    @pytest.mark.asyncio
    async def test_challenge_captures_network_error(self, db, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEService

        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", True)

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url): raise ConnectionError("refused")

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        svc    = DistributedTEEService()
        result = await svc.challenge_peer(db, "http://dead-peer:9000", "dead-node")
        assert result.success  is False
        assert result.verified is False
        assert "refused" in (result.error or "")

    # ── challenge_peer: successful mock round-trip ────────────────────────────

    @pytest.mark.asyncio
    async def test_challenge_peer_success_mock(self, db, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEService
        from app.services.tee_attestation_service import tee_attestation_service, MOCK_PCR0

        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", True)
        monkeypatch.setattr(config.settings, "TEE_ATTESTATION_MODE", "mock")

        # Generate a real nonce + mock document so local verification passes
        nonce   = tee_attestation_service.generate_nonce()
        doc_b64 = tee_attestation_service.generate_mock_document(nonce=nonce)

        class _FakeGetResponse:
            is_success = True
            def json(self): return {"nonce": nonce}

        class _FakePostResponse:
            is_success = True
            def json(self):
                return {
                    "raw_document_b64": doc_b64,
                    "platform":         "mock",
                    "node_id":          "mock-peer",
                    "expected_pcr0":    MOCK_PCR0,
                }

        class _FakeClient:
            async def __aenter__(self): return self
            async def __aexit__(self, *_): pass
            async def get(self, url):  return _FakeGetResponse()
            async def post(self, url, json=None): return _FakePostResponse()

        import httpx as _httpx
        monkeypatch.setattr(_httpx, "AsyncClient", lambda **kw: _FakeClient())

        svc    = DistributedTEEService()
        result = await svc.challenge_peer(db, "http://mock-peer:8000", "mock-peer")
        assert result.success  is True
        assert result.verified is True
        assert result.pcr0_match is True

    # ── challenge_all_peers: empty config returns empty list ──────────────────

    @pytest.mark.asyncio
    async def test_challenge_all_peers_empty(self, db, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEService
        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", True)
        monkeypatch.setattr(config.settings, "TEE_PEER_NODES", "")
        svc    = DistributedTEEService()
        result = await svc.challenge_all_peers(db)
        assert result == []


class TestDistributedTEEWorker:
    """DistributedTEEWorker lifecycle tests."""

    def test_worker_does_not_start_when_disabled(self, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEWorker
        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", False)
        monkeypatch.setattr(config.settings, "TEE_PEER_NODES", "")
        w = DistributedTEEWorker()
        w.start_background_worker()
        assert w._task is None

    def test_worker_does_not_start_without_peers(self, monkeypatch):
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEWorker
        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", True)
        monkeypatch.setattr(config.settings, "TEE_PEER_NODES", "")
        w = DistributedTEEWorker()
        w.start_background_worker()
        assert w._task is None

    def test_stop_is_safe_when_not_started(self):
        from app.services.distributed_tee_service import DistributedTEEWorker
        w = DistributedTEEWorker()
        w.stop()   # must not raise

    @pytest.mark.asyncio
    async def test_worker_starts_and_stops_in_event_loop(self, monkeypatch):
        import asyncio
        from app.core import config
        from app.services.distributed_tee_service import DistributedTEEWorker
        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", True)
        monkeypatch.setattr(config.settings, "TEE_PEER_NODES", "http://peer-x:8000")
        monkeypatch.setattr(config.settings, "TEE_AUTO_CHALLENGE_INTERVAL_MINUTES", 9999)
        w = DistributedTEEWorker()
        w.start_background_worker()
        assert w._task is not None
        assert not w._task.done()
        w.stop()
        # Give the event loop a tick to process the cancellation
        await asyncio.sleep(0)
        assert w._task.cancelled() or w._task.done() or w._task.cancelling() > 0


class TestDistributedTEEAPI:
    """API shape and guard tests for /api/v1/attestation/distributed/*."""

    def test_distributed_tee_router_imported_in_main(self):
        import inspect
        import app.main as main_module
        src = inspect.getsource(main_module)
        assert "distributed_tee" in src

    def test_distributed_tee_router_mounted(self):
        import inspect
        import app.main as main_module
        src = inspect.getsource(main_module)
        assert "/api/v1/attestation" in src
        assert "distributed_tee_api" in src

    def test_challenge_endpoint_present(self):
        import inspect
        from app.api import distributed_tee
        src = inspect.getsource(distributed_tee)
        assert "challenge_peer" in src
        assert "/distributed/challenge" in src

    def test_respond_endpoint_present(self):
        import inspect
        from app.api import distributed_tee
        src = inspect.getsource(distributed_tee)
        assert "respond_to_challenge" in src
        assert "/distributed/respond" in src

    def test_receive_endpoint_present(self):
        import inspect
        from app.api import distributed_tee
        src = inspect.getsource(distributed_tee)
        assert "receive_peer_attestation" in src
        assert "/distributed/receive" in src

    def test_push_endpoint_present(self):
        import inspect
        from app.api import distributed_tee
        src = inspect.getsource(distributed_tee)
        assert "push_attestation" in src
        assert "/distributed/push" in src

    def test_peers_endpoint_present(self):
        import inspect
        from app.api import distributed_tee
        src = inspect.getsource(distributed_tee)
        assert "list_peers" in src
        assert "/distributed/peers" in src

    def test_disabled_raises_503(self, monkeypatch):
        from app.core import config
        from app.api.distributed_tee import _check_enabled
        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", False)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _check_enabled()
        assert exc_info.value.status_code == 503

    def test_enabled_does_not_raise(self, monkeypatch):
        from app.core import config
        from app.api.distributed_tee import _check_enabled
        monkeypatch.setattr(config.settings, "TEE_DISTRIBUTED_ENABLED", True)
        _check_enabled()   # must not raise


# ══════════════════════════════════════════════════════════════════════════════
#  T3-D: Legal Bundle Export
# ══════════════════════════════════════════════════════════════════════════════

class TestLegalExportORM:
    """LegalExportRecord ORM model has required columns and correct defaults."""

    def test_legal_export_record_columns_exist(self):
        from app.models.orm_models import LegalExportRecord
        cols = {c.key for c in LegalExportRecord.__table__.columns}
        for expected in (
            "id", "bundle_type", "subject_id", "model_id_filter",
            "window_since", "window_until",
            "inference_count", "audit_log_count", "proof_count",
            "policy_count", "nael_count", "tee_count",
            "bundle_sha256", "artifacts_sha256", "signature", "signed_by",
            "exported_by", "bascg_node_id", "created_at",
        ):
            assert expected in cols, f"Missing column: {expected}"

    def test_legal_export_record_bundle_sha256_not_nullable(self):
        from app.models.orm_models import LegalExportRecord
        col = LegalExportRecord.__table__.c["bundle_sha256"]
        assert col.nullable is False

    def test_legal_export_record_count_defaults(self):
        from app.models.orm_models import LegalExportRecord
        for col_name in ("inference_count", "audit_log_count", "proof_count",
                         "policy_count", "nael_count", "tee_count"):
            col = LegalExportRecord.__table__.c[col_name]
            assert col.default is not None
            assert col.default.arg == 0


class TestLegalExportConfig:
    """Config settings exist and have correct defaults."""

    def test_legal_export_enabled_default_true(self):
        from app.core.config import Settings
        assert Settings().LEGAL_EXPORT_ENABLED is True

    def test_legal_export_sign_bundles_default_true(self):
        from app.core.config import Settings
        assert Settings().LEGAL_EXPORT_SIGN_BUNDLES is True

    def test_legal_export_include_raw_documents_default_false(self):
        from app.core.config import Settings
        assert Settings().LEGAL_EXPORT_INCLUDE_RAW_DOCUMENTS is False

    def test_legal_export_max_audit_logs_default(self):
        from app.core.config import Settings
        assert Settings().LEGAL_EXPORT_MAX_AUDIT_LOGS == 1000


class TestLegalBundleService:
    """Unit tests for LegalBundleService logic."""

    @pytest.fixture
    async def db(self):
        from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
        from sqlalchemy.orm import sessionmaker
        from app.db.database import Base
        import app.models.orm_models  # noqa: F401

        engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with Session() as session:
            yield session
        await engine.dispose()

    async def _seed_inference(self, db, model_id="m1"):
        from app.models.orm_models import InferenceEvent
        import uuid
        ev = InferenceEvent(
            id                   = str(uuid.uuid4()),
            model_id             = model_id,
            confidence           = 0.9,
            risk_score           = 0.75,
            enforcement_decision = "BLOCK",
            fairness_flags       = [],
            policy_violations    = [{"policy_id": "p1", "severity": "HIGH"}],
            context_metadata     = {},
        )
        db.add(ev)
        await db.commit()
        await db.refresh(ev)
        return ev

    async def _seed_audit_log(self, db, entity_id):
        from app.models.orm_models import AuditLog
        import uuid
        log = AuditLog(
            id          = str(uuid.uuid4()),
            event_type  = "inference_evaluated",
            entity_id   = entity_id,
            entity_type = "inference",
            actor       = "test",
            action      = "evaluate",
            risk_level  = "HIGH",
        )
        db.add(log)
        await db.commit()
        await db.refresh(log)
        return log

    # ── inference bundle: not found raises ValueError ─────────────────────────

    @pytest.mark.asyncio
    async def test_export_inference_not_found_raises(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        svc = LegalBundleService()
        with pytest.raises(ValueError, match="not found"):
            await svc.export_inference_bundle(db, "does-not-exist")

    # ── inference bundle: required top-level keys ─────────────────────────────

    @pytest.mark.asyncio
    async def test_export_inference_bundle_has_required_keys(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        ev  = await self._seed_inference(db)
        svc = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        d = bundle.to_dict()
        for key in ("bundle_id", "bundle_version", "bundle_type", "generated_at",
                    "generated_by", "bascg_standard", "legal_basis",
                    "subject", "artifacts", "integrity"):
            assert key in d, f"Missing key: {key}"

    @pytest.mark.asyncio
    async def test_export_inference_bundle_type_is_inference(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        assert bundle.bundle_type == "inference"

    # ── inference bundle: subject fields ─────────────────────────────────────

    @pytest.mark.asyncio
    async def test_export_inference_subject_contains_inference_id(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        assert bundle.subject["inference_id"] == ev.id
        assert bundle.subject["type"] == "inference_decision"
        assert bundle.subject["enforcement_decision"] == "BLOCK"

    # ── inference bundle: artifacts structure ─────────────────────────────────

    @pytest.mark.asyncio
    async def test_export_inference_artifacts_contain_event(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        events = bundle.artifacts["inference_events"]
        assert len(events) == 1
        assert events[0]["id"] == ev.id

    @pytest.mark.asyncio
    async def test_export_inference_collects_audit_logs(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        ev  = await self._seed_inference(db)
        await self._seed_audit_log(db, ev.id)
        await self._seed_audit_log(db, ev.id)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        assert len(bundle.artifacts["audit_logs"]) == 2

    # ── inference bundle: integrity hash ─────────────────────────────────────

    @pytest.mark.asyncio
    async def test_export_inference_integrity_hash_present(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        assert bundle.integrity.get("artifacts_sha256")
        assert len(bundle.integrity["artifacts_sha256"]) == 64  # SHA-256 hex

    @pytest.mark.asyncio
    async def test_integrity_hash_matches_artifacts(self, db):
        import hashlib, json
        from app.services.legal_bundle_service import LegalBundleService
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        expected = hashlib.sha256(
            json.dumps(bundle.artifacts, sort_keys=True, default=str).encode()
        ).hexdigest()
        assert bundle.integrity["artifacts_sha256"] == expected

    # ── inference bundle: signature ────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_export_inference_bundle_is_signed(self, db, monkeypatch):
        from app.core import config
        from app.services.legal_bundle_service import LegalBundleService
        monkeypatch.setattr(config.settings, "LEGAL_EXPORT_SIGN_BUNDLES", True)
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        assert bundle.signature is not None
        assert bundle.signed_by is not None

    @pytest.mark.asyncio
    async def test_export_inference_signature_skipped_when_disabled(self, db, monkeypatch):
        from app.core import config
        from app.services.legal_bundle_service import LegalBundleService
        monkeypatch.setattr(config.settings, "LEGAL_EXPORT_SIGN_BUNDLES", False)
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        assert bundle.signature is None

    # ── inference bundle: export record persisted ─────────────────────────────

    @pytest.mark.asyncio
    async def test_export_inference_persists_export_record(self, db):
        from sqlalchemy import select
        from app.models.orm_models import LegalExportRecord
        from app.services.legal_bundle_service import LegalBundleService
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id, actor="tester")
        res    = await db.execute(select(LegalExportRecord))
        records = list(res.scalars().all())
        assert len(records) == 1
        r = records[0]
        assert r.bundle_type  == "inference"
        assert r.subject_id   == ev.id
        assert r.bundle_sha256 is not None
        assert r.exported_by  == "tester"

    # ── legal_basis contains IT Act reference ────────────────────────────────

    @pytest.mark.asyncio
    async def test_legal_basis_contains_it_act(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        bundle = await svc.export_inference_bundle(db, ev.id)
        assert "65B" in bundle.legal_basis["act"]
        assert bundle.legal_basis["jurisdiction"] == "India"

    # ── time_window bundle ────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_export_time_window_returns_bundle(self, db):
        from datetime import datetime, timedelta, timezone
        from app.services.legal_bundle_service import LegalBundleService
        now   = datetime.now(timezone.utc)
        svc   = LegalBundleService()
        bundle = await svc.export_time_window_bundle(
            db=db,
            since=now - timedelta(hours=1),
            until=now,
        )
        assert bundle.bundle_type == "time_window"
        assert "inference_events" in bundle.artifacts
        assert "audit_logs"       in bundle.artifacts
        assert "merkle_proofs"    in bundle.artifacts

    @pytest.mark.asyncio
    async def test_export_time_window_empty_succeeds(self, db):
        from datetime import datetime, timedelta, timezone
        from app.services.legal_bundle_service import LegalBundleService
        # Far-past window — no data
        epoch = datetime(2000, 1, 1, tzinfo=timezone.utc)
        svc   = LegalBundleService()
        bundle = await svc.export_time_window_bundle(
            db=db,
            since=epoch,
            until=epoch + timedelta(seconds=1),
        )
        assert bundle.bundle_type == "time_window"
        assert bundle.artifacts["inference_events"] == []

    @pytest.mark.asyncio
    async def test_export_time_window_collects_seeded_events(self, db):
        from datetime import datetime, timedelta, timezone
        from app.services.legal_bundle_service import LegalBundleService
        await self._seed_inference(db, model_id="model-tw")
        now   = datetime.now(timezone.utc)
        svc   = LegalBundleService()
        bundle = await svc.export_time_window_bundle(
            db=db,
            since=now - timedelta(minutes=5),
            until=now + timedelta(minutes=1),
        )
        assert len(bundle.artifacts["inference_events"]) >= 1

    # ── list / get export records ─────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_list_export_records_returns_records(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        ev     = await self._seed_inference(db)
        svc    = LegalBundleService()
        await svc.export_inference_bundle(db, ev.id)
        records = await svc.list_export_records(db)
        assert len(records) == 1

    @pytest.mark.asyncio
    async def test_get_export_record_returns_none_for_unknown(self, db):
        from app.services.legal_bundle_service import LegalBundleService
        svc = LegalBundleService()
        assert await svc.get_export_record(db, "ghost") is None

    @pytest.mark.asyncio
    async def test_list_export_records_filter_by_type(self, db):
        from datetime import datetime, timedelta, timezone
        from app.services.legal_bundle_service import LegalBundleService
        ev  = await self._seed_inference(db)
        svc = LegalBundleService()
        await svc.export_inference_bundle(db, ev.id)
        now = datetime.now(timezone.utc)
        await svc.export_time_window_bundle(
            db=db, since=now - timedelta(hours=1), until=now
        )
        inf_records = await svc.list_export_records(db, bundle_type="inference")
        tw_records  = await svc.list_export_records(db, bundle_type="time_window")
        assert all(r.bundle_type == "inference"   for r in inf_records)
        assert all(r.bundle_type == "time_window" for r in tw_records)

    # ── helper functions ──────────────────────────────────────────────────────

    def test_extract_policy_ids_from_violations(self):
        from app.services.legal_bundle_service import _extract_policy_ids
        violations = [
            {"policy_id": "pol-1", "severity": "HIGH"},
            {"policy_id": "pol-2", "severity": "MEDIUM"},
            {"policy_id": "pol-1"},  # duplicate
        ]
        ids = _extract_policy_ids(violations)
        assert set(ids) == {"pol-1", "pol-2"}

    def test_extract_policy_ids_handles_none(self):
        from app.services.legal_bundle_service import _extract_policy_ids
        assert _extract_policy_ids(None) == []
        assert _extract_policy_ids([])   == []

    def test_extract_scan_id_from_context(self):
        from app.services.legal_bundle_service import _extract_scan_id
        ctx = {"synthetic_media_scan_id": "scan-abc"}
        assert _extract_scan_id(ctx) == "scan-abc"

    def test_extract_scan_id_returns_none_when_missing(self):
        from app.services.legal_bundle_service import _extract_scan_id
        assert _extract_scan_id({}) is None
        assert _extract_scan_id(None) is None

    def test_sha256_json_is_deterministic(self):
        from app.services.legal_bundle_service import _sha256_json
        obj = {"b": 2, "a": 1}
        assert _sha256_json(obj) == _sha256_json(obj)
        assert len(_sha256_json(obj)) == 64


class TestLegalExportAPI:
    """API shape and guard tests for /api/v1/legal-export/*."""

    def test_legal_export_router_mounted_in_main(self):
        import inspect
        import app.main as main_module
        src = inspect.getsource(main_module)
        assert "legal_export" in src
        assert "/api/v1/legal-export" in src

    def test_inference_endpoint_present(self):
        import inspect
        from app.api import legal_export
        src = inspect.getsource(legal_export)
        assert "export_inference_bundle" in src
        assert "/inference/{inference_id}" in src

    def test_time_window_endpoint_present(self):
        import inspect
        from app.api import legal_export
        src = inspect.getsource(legal_export)
        assert "export_time_window_bundle" in src
        assert "/time-window" in src

    def test_records_endpoint_present(self):
        import inspect
        from app.api import legal_export
        src = inspect.getsource(legal_export)
        assert "list_export_records" in src
        assert "/records" in src

    def test_status_endpoint_present(self):
        import inspect
        from app.api import legal_export
        src = inspect.getsource(legal_export)
        assert "legal_export_status" in src
        assert "/status" in src

    def test_disabled_raises_503(self, monkeypatch):
        from app.core import config
        from app.api.legal_export import _check_enabled
        monkeypatch.setattr(config.settings, "LEGAL_EXPORT_ENABLED", False)
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            _check_enabled()
        assert exc_info.value.status_code == 503

    def test_enabled_by_default_does_not_raise(self, monkeypatch):
        from app.core import config
        from app.api.legal_export import _check_enabled
        monkeypatch.setattr(config.settings, "LEGAL_EXPORT_ENABLED", True)
        _check_enabled()   # must not raise

    def test_status_response_contains_legal_basis(self):
        import inspect
        from app.api import legal_export
        src = inspect.getsource(legal_export)
        assert "65B" in src
        assert "jurisdiction" in src
