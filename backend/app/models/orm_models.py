"""ORM Models for KavachX database."""
from sqlalchemy import Column, String, Float, DateTime, Text, Boolean, JSON, Integer, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from app.db.database import Base


# ──────────────────────────────────────────────────────────────────────────────
# NOTE: LedgerAnchor is defined BEFORE AuditLog so the FK string reference
# resolves cleanly at mapper configuration time.
# ──────────────────────────────────────────────────────────────────────────────


def gen_uuid():
    return str(uuid.uuid4())


class LedgerAnchor(Base):
    """
    BASCG Phase 1 — Forensic Integrity Layer (IT Act S.65B / DPDP 2023 S.8/S.10).

    Each row represents one batch of AuditLog entries whose chain_hashes have
    been combined into a binary Merkle tree, with the Merkle root timestamped
    by an external Timestamp Authority (TSA).

    Legal significance:
      - The TSA token is an independent, third-party witness that the Merkle root
        existed at a specific point in time.
      - Because the Merkle root commits to every chain_hash in the batch, any
        tampering with an AuditLog entry is detectable via Merkle proof verification.
      - This satisfies the "reasonable security" requirement (IT Act S.43A) and
        creates court-admissible electronic records (IT Act S.65B).

    Verification (production RFC 3161 mode):
        echo <tsa_token_b64> | base64 -d > response.tsr
        printf '%s' '<merkle_root_hex>' | xxd -r -p > root.bin
        openssl ts -verify -data root.bin -in response.tsr -CAfile tsa_ca.pem
    """
    __tablename__ = "ledger_anchors"

    id                 = Column(String,   primary_key=True, default=gen_uuid)

    # ── Batch metadata ────────────────────────────────────────────────────────
    batch_start_log_id = Column(String,   nullable=True)   # first AuditLog.id in batch
    batch_end_log_id   = Column(String,   nullable=True)   # last AuditLog.id in batch
    log_count          = Column(Integer,  default=0)       # number of logs anchored

    # ── Merkle tree ───────────────────────────────────────────────────────────
    # merkle_root: hex SHA-256 root committing to all chain_hashes in the batch.
    # merkle_tree_json: full tree (leaves + levels) stored for on-demand proof
    #   generation without recomputation; keyed as {"root","leaf_count","leaves","levels"}.
    merkle_root        = Column(String,   nullable=False)
    merkle_tree_json   = Column(JSON,     nullable=True)

    # ── TSA timestamp token ───────────────────────────────────────────────────
    # tsa_provider: "mock-local-tsa" | TSA HTTP URL (freetsa / digicert / sectigo)
    # tsa_token_b64: base64-encoded raw TSA response — opaque blob for external
    #   openssl verification (RFC 3161) or HMAC verification (mock mode).
    tsa_provider   = Column(String,   nullable=True)
    tsa_token_b64  = Column(Text,     nullable=True)
    tsa_timestamp  = Column(DateTime, nullable=True)       # parsed UTC timestamp from TSA
    tsa_serial     = Column(String,   nullable=True)       # TSA serial number

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    anchor_status  = Column(String,   default="pending")   # pending | anchored | failed
    error_message  = Column(Text,     nullable=True)
    created_at     = Column(DateTime, default=lambda: datetime.utcnow())
    anchored_at    = Column(DateTime, nullable=True)

    audit_logs = relationship("AuditLog", back_populates="ledger_anchor", lazy="noload")


class AIModel(Base):
    __tablename__ = "ai_models"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    model_type = Column(String)  # classification, regression, llm, etc.
    owner = Column(String)
    description = Column(Text)
    status = Column(String, default="active")  # active, suspended, archived
    registered_at = Column(DateTime, default=lambda: datetime.utcnow())
    metadata_ = Column("metadata", JSON, default=dict)
    inferences = relationship("InferenceEvent", back_populates="model")

    # ── BASCG P2: National AI Registry (NAIR-I) ───────────────────────────────
    # Cryptographic model identity (prevents weight substitution attacks)
    model_sha256          = Column(String,   nullable=True)   # SHA-256 of model weights
    training_data_hash    = Column(String,   nullable=True)   # Merkle root of training manifest

    # NAIR-I classification
    # risk_category: dynamic — updated by PolicyEngine based on inference history
    risk_category         = Column(String,   default="UNKNOWN")  # LOW|MEDIUM|HIGH|PROHIBITED|UNKNOWN
    # registry_status: lifecycle of the model in the national registry
    registry_status       = Column(String,   default="PENDING")  # PENDING|ACTIVE|SUSPENDED|DEREGISTERED
    sector                = Column(String,   nullable=True)   # finance|healthcare|education|government|…

    # Provenance and compliance artefacts
    model_card_url             = Column(String, nullable=True)
    compliance_certifications  = Column(JSON,   default=list)  # ["ISO-42001","RBI-AI-2024",…]
    framework                  = Column(String, nullable=True)  # pytorch|tensorflow|jax|onnx
    parameter_count            = Column(String, nullable=True)  # "7B", "175B", etc.

    # Registry timestamps
    nair_registered_at    = Column(DateTime, nullable=True)    # when accepted into NAIR-I
    last_audited_at       = Column(DateTime, nullable=True)

    # ── BASCG T3-A: Bidirectional NAIR-I Sync ────────────────────────────────
    nair_source     = Column(String,   default="local")   # "local" | "national"
    nair_pulled_at  = Column(DateTime, nullable=True)     # last pull from national node


class GovernancePolicy(Base):
    __tablename__ = "governance_policies"
    id = Column(String, primary_key=True, default=gen_uuid)
    name = Column(String, nullable=False)
    description = Column(Text)
    policy_type = Column(String)  # fairness, safety, compliance, performance
    rules = Column(JSON)  # structured rule definitions
    severity = Column(String, default="medium")  # low, medium, high, critical
    enabled = Column(Boolean, default=True)
    jurisdiction = Column(String, default="IN")
    created_at = Column(DateTime, default=lambda: datetime.utcnow())
    updated_at = Column(DateTime, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.now(timezone.utc))
    # ── BASCG Phase 1: Signed Policy Bundle (P0) ─────────────────────────────
    # Unsigned policies are REJECTED by GovernanceService._load_federated_policies.
    # Sign with: policy_bundle_service.sign_db_policy_payload(policy_dict)
    policy_signature   = Column(String, nullable=True)   # Ed25519 sig (base64)
    signed_by          = Column(String, nullable=True)   # issuer key name
    bundle_version     = Column(String, nullable=True)   # semantic version tag
    bundle_valid_until = Column(DateTime, nullable=True) # expiry for this policy


class InferenceEvent(Base):
    __tablename__ = "inference_events"
    id = Column(String, primary_key=True, default=gen_uuid)
    model_id = Column(String, ForeignKey("ai_models.id"))
    model = relationship("AIModel", back_populates="inferences")
    input_data = Column(JSON)
    prediction = Column(JSON)
    confidence = Column(Float)
    risk_score = Column(Float)
    enforcement_decision = Column(String)  # PASS, ALERT, BLOCK, HUMAN_REVIEW
    fairness_flags = Column(JSON, default=list)
    policy_violations = Column(JSON, default=list)
    explanation = Column(JSON)
    timestamp = Column(DateTime, default=datetime.utcnow)
    context_metadata = Column(JSON, default=dict)
    session_id = Column(String, index=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(String, primary_key=True, default=gen_uuid)
    event_type = Column(String)   # inference_evaluated, policy_violated, model_blocked, …
    entity_id = Column(String)
    entity_type = Column(String)
    actor = Column(String)
    action = Column(String)
    details = Column(JSON)
    risk_level = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # Cryptographic integrity chain (SHA-256 of prev_hash + this payload)
    prev_hash  = Column(String,  nullable=True)
    chain_hash = Column(String,  nullable=True, index=True)

    # ── BASCG Phase 1: Merkle anchoring (Stage 3 — Legal Admissibility) ──────
    # Set by SovereignLedgerSyncService after the batch containing this log
    # has been anchored.  NULL means not yet anchored.
    #
    # To generate a Merkle proof:
    #   GET /api/v1/ledger/anchors/{merkle_anchor_id}/proof/{merkle_leaf_index}
    merkle_anchor_id   = Column(String,  ForeignKey("ledger_anchors.id"), nullable=True, index=True)
    merkle_leaf_index  = Column(Integer, nullable=True)  # 0-based position in Merkle batch

    ledger_anchor = relationship("LedgerAnchor", back_populates="audit_logs")


class FairnessMetric(Base):
    __tablename__ = "fairness_metrics"
    id = Column(String, primary_key=True, default=gen_uuid)
    model_id = Column(String, ForeignKey("ai_models.id"))
    metric_name = Column(String)  # demographic_parity, equalized_odds, etc.
    group_a = Column(String)
    group_b = Column(String)
    value_a = Column(Float)
    value_b = Column(Float)
    disparity = Column(Float)
    passed = Column(Boolean)
    timestamp = Column(DateTime, default=datetime.utcnow)


class ConsentRecord(Base):
    """India DPDP 2023: Track data principal consent for specific processing purposes."""
    __tablename__ = "consent_records"
    id = Column(String, primary_key=True, default=gen_uuid)
    data_principal_id = Column(String, index=True)  # e.g., user_123, citizen_aadhaar_hash
    purpose = Column(String, nullable=False)        # e.g., credit_scoring, medical_diagnosis
    consent_given = Column(Boolean, default=False)
    collected_at = Column(DateTime, default=lambda: datetime.utcnow())
    expires_at = Column(DateTime, nullable=True)
    metadata_ = Column("metadata", JSON, default=dict)
    integrity_hash = Column(String)  # tamper-evident link


# ── BASCG Phase 1 — P1: National AI Execution Licensing (NAEL) ───────────────

class NAELLicense(Base):
    """
    National AI Execution License — the "Digital DNA" of a licensed AI system.

    A signed token that a BASCG-certified compute node must verify before
    decrypting model weights and running inference.  Sector restrictions and
    risk classification are cryptographically bound to the model identity hash.

    Enforcement (NAEL_ENFORCEMENT_ENABLED=True):
      - Missing license   → ALERT (model still runs, incident logged)
      - Expired license   → BLOCK
      - Sector mismatch   → BLOCK
      - Revoked license   → BLOCK
      - Invalid signature → BLOCK
    """
    __tablename__ = "nael_licenses"

    id                    = Column(String,   primary_key=True, default=gen_uuid)
    model_id              = Column(String,   ForeignKey("ai_models.id"), nullable=False, index=True)
    model_sha256          = Column(String,   nullable=True)   # SHA-256 of model weights
    license_token         = Column(Text,     nullable=False)  # full signed token JSON
    sector_restrictions   = Column(JSON,     default=list)    # ["finance","healthcare",...]
    risk_classification   = Column(String,   default="MEDIUM") # LOW|MEDIUM|HIGH|PROHIBITED
    licensed_tee_platforms = Column(JSON,    default=list)    # ["aws-nitro","intel-sgx-dcap"]
    issued_by             = Column(String,   nullable=True)
    issued_at             = Column(DateTime, nullable=True)
    valid_from            = Column(DateTime, nullable=True)
    valid_until           = Column(DateTime, nullable=True)
    revoked               = Column(Boolean,  default=False)
    revocation_reason     = Column(Text,     nullable=True)
    created_at            = Column(DateTime, default=lambda: datetime.utcnow())

    model = relationship("AIModel")


# ── BASCG Phase 1 — P1: TEE Attestation Reports ──────────────────────────────

class AttestationReport(Base):
    """
    Records a TEE attestation verification event.

    Each time a compute node presents an attestation document (AWS Nitro,
    Intel SGX DCAP, or mock), the result is stored here.  Successful
    attestations are referenced by inference events to prove the execution
    environment was verified before running the model.

    PCR0 (Platform Configuration Register 0) contains the hash of the
    enclave image — verifying it matches the registered policy engine hash
    closes the hardware root-of-trust chain.
    """
    __tablename__ = "attestation_reports"

    id                  = Column(String,   primary_key=True, default=gen_uuid)
    platform            = Column(String,   nullable=False)  # "mock"|"aws-nitro"|"intel-sgx-dcap"
    model_id            = Column(String,   ForeignKey("ai_models.id"), nullable=True)
    nael_license_id     = Column(String,   ForeignKey("nael_licenses.id"), nullable=True)

    # PCR values (base64-encoded bytes from the TEE)
    pcr0                = Column(String,   nullable=True)   # enclave image hash
    pcr1                = Column(String,   nullable=True)   # kernel / OS hash
    pcr2                = Column(String,   nullable=True)   # application hash

    # Attestation document (raw, for external re-verification)
    raw_document_b64    = Column(Text,     nullable=True)   # base64-encoded attestation doc
    user_data_b64       = Column(String,   nullable=True)   # data embedded by enclave
    nonce               = Column(String,   nullable=True)   # anti-replay nonce

    # Verification result
    verified            = Column(Boolean,  default=False)
    pcr0_match          = Column(Boolean,  default=False)   # PCR0 == registered engine hash
    nael_valid          = Column(Boolean,  default=False)   # NAEL token in user_data valid
    failure_reason      = Column(Text,     nullable=True)

    # Clearance (time-limited once verified)
    clearance_valid_until = Column(DateTime, nullable=True)

    created_at          = Column(DateTime, default=lambda: datetime.utcnow())


# ── BASCG Phase 3 — P3: Synthetic Media Shield ───────────────────────────────

class SyntheticMediaScanRecord(Base):
    """
    BASCG Phase 3 — Synthetic Media Shield.

    Records each deepfake / AI-generated content scan result.

    Legal basis:
      DPDP 2023 S.4  — Lawful processing of personal data (biometric deepfakes)
      IT Act S.66E   — Privacy violation by capturing / publishing private images
      IT Act S.67A/B — Obscene electronic material (election deepfakes)
      Election Commission of India Model Code of Conduct — synthetic political media

    During Election Protection Mode the scan is mandatory and results are
    forwarded to the BASCG Election Integrity Bus (async audit channel).
    """
    __tablename__ = "synthetic_media_scans"

    id              = Column(String,   primary_key=True, default=gen_uuid)

    # Content identity
    content_hash    = Column(String,   nullable=False, index=True)  # SHA-256 of raw bytes
    content_type    = Column(String,   nullable=True)   # "image/jpeg" | "video/mp4" | "audio/wav"
    file_size_bytes = Column(Integer,  nullable=True)
    filename        = Column(String,   nullable=True)   # original upload filename (sanitised)

    # Detection result
    detector        = Column(String,   nullable=False)  # "mock" | "api:<provider>"
    is_synthetic    = Column(Boolean,  nullable=False, default=False)
    confidence      = Column(Float,    nullable=True)   # 0.0–1.0; higher = more likely synthetic
    detection_labels = Column(JSON,   default=list)    # ["GAN_face", "audio_clone", …]
    raw_response    = Column(JSON,     nullable=True)   # full detector API response

    # BASCG enforcement
    enforcement_action = Column(String, default="PASS")  # PASS | ALERT | BLOCK | ESCALATE
    policy_violations  = Column(JSON,  default=list)

    # Election Protection Mode
    election_context   = Column(Boolean, default=False)  # True if scan was triggered in EPM
    election_state     = Column(String,  nullable=True)  # e.g. "MH" for Maharashtra
    escalated_to_eci   = Column(Boolean, default=False)  # forwarded to Election Integrity Bus

    # Evidence package (for court admissibility)
    evidence_hash      = Column(String,  nullable=True)  # SHA-256 of JSON evidence bundle
    evidence_bundle    = Column(JSON,    nullable=True)  # {content_hash, scan_id, labels, ts, sig}

    # Actor context
    submitted_by    = Column(String,   nullable=True)   # username / API key
    source_ip       = Column(String,   nullable=True)

    created_at      = Column(DateTime, default=lambda: datetime.utcnow())


# ══════════════════════════════════════════════════════════════════════════════
#  T3-B: Multi-node Policy Consensus
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
#  T3-C: Distributed TEE Attestation — peer-node trust registry
# ══════════════════════════════════════════════════════════════════════════════

class RemoteNodeAttestation(Base):
    """
    Tracks the TEE attestation status of a **peer** BASCG node.

    Each row represents the outcome of a challenge-response cycle where
    *this* node challenged a remote node and verified its attestation document.

    A peer is considered trusted for inference routing when:
      verified=True AND clearance_valid_until > now AND pcr0_match=True
    """
    __tablename__ = "remote_node_attestations"

    id                   = Column(String,  primary_key=True, default=gen_uuid)
    node_id              = Column(String,  nullable=False, index=True)  # peer's CONSENSUS_NODE_ID
    node_url             = Column(String,  nullable=False)              # peer's base URL

    platform             = Column(String,  nullable=True)   # "mock" | "aws-nitro" | "intel-sgx-dcap"
    pcr0                 = Column(String,  nullable=True)   # enclave image hash from peer
    pcr0_match           = Column(Boolean, default=False)   # matches expected value for this peer
    verified             = Column(Boolean, default=False)
    failure_reason       = Column(Text,    nullable=True)

    clearance_valid_until = Column(DateTime, nullable=True)  # when peer's clearance expires

    raw_document_b64     = Column(Text,    nullable=True)   # peer's attestation document (for audit)
    nonce                = Column(String,  nullable=True)   # challenge nonce we issued

    attested_at          = Column(DateTime, default=lambda: datetime.utcnow())


class PolicyProposal(Base):
    """
    A proposed governance policy change submitted to the BASCG consensus ring.

    Lifecycle: pending → accepted (quorum met) | rejected | expired (TTL passed)
    Proposal types:
      create_policy    — add a new GovernancePolicy
      update_policy    — update fields on an existing GovernancePolicy
      disable_policy   — set GovernancePolicy.enabled = False
      update_threshold — change a governance threshold in settings
    """
    __tablename__ = "policy_proposals"

    id              = Column(String,   primary_key=True, default=gen_uuid)
    proposal_type   = Column(String,   nullable=False)  # create_policy | update_policy | disable_policy | update_threshold
    title           = Column(String,   nullable=False)
    description     = Column(Text,     nullable=True)
    payload         = Column(JSON,     nullable=False)   # the full proposed change (policy dict, threshold dict, …)
    proposed_by     = Column(String,   nullable=False)   # node_id of the proposing node
    status          = Column(String,   default="pending")  # pending | accepted | rejected | expired

    expires_at      = Column(DateTime, nullable=False)   # proposal is void after this time
    created_at      = Column(DateTime, default=lambda: datetime.utcnow())
    resolved_at     = Column(DateTime, nullable=True)    # when tally reached quorum

    # Set on acceptance — the GovernancePolicy id that was created/updated
    applied_policy_id = Column(String, nullable=True)

    # Cryptographic integrity — proposal signed by the proposing node's Ed25519 key
    proposal_signature = Column(String, nullable=True)   # Ed25519 sig over canonical JSON
    signed_by          = Column(String, nullable=True)   # issuer key name

    votes = relationship("PolicyVote", back_populates="proposal",
                         cascade="all, delete-orphan")


class PolicyVote(Base):
    """
    A signed vote cast by a node on a PolicyProposal.

    The vote payload that is signed: {proposal_id, node_id, vote, voted_at}
    Unknown issuers are rejected when CONSENSUS_VERIFY_VOTE_SIGNATURES=True.
    """
    __tablename__ = "policy_votes"

    id          = Column(String,   primary_key=True, default=gen_uuid)
    proposal_id = Column(String,   ForeignKey("policy_proposals.id"), nullable=False, index=True)
    node_id     = Column(String,   nullable=False)   # voting node's identifier
    vote        = Column(String,   nullable=False)   # "accept" | "reject"
    reason      = Column(Text,     nullable=True)

    # Cryptographic integrity — vote signed by the voting node's Ed25519 key
    signature   = Column(String,   nullable=True)    # Ed25519 sig over vote payload
    signed_by   = Column(String,   nullable=True)    # issuer key name

    voted_at    = Column(DateTime, default=lambda: datetime.utcnow())

    proposal = relationship("PolicyProposal", back_populates="votes")


# ══════════════════════════════════════════════════════════════════════════════
#  T3-D: Legal Bundle Export — court-admissible evidence records
# ══════════════════════════════════════════════════════════════════════════════

class LegalExportRecord(Base):
    """
    Audit record for every legal bundle export.

    The full bundle JSON is returned in the API response only — storing the
    SHA-256 hash here keeps the DB lean while providing tamper-detection.

    Legal basis: IT Act S.65B, DPDP 2023 S.8/10, MeitY AI Governance Framework.
    Each exported bundle is Ed25519-signed by the issuing BASCG node.
    """
    __tablename__ = "legal_export_records"

    id               = Column(String,   primary_key=True, default=gen_uuid)

    # What was exported
    bundle_type      = Column(String,   nullable=False)    # "inference" | "time_window"
    subject_id       = Column(String,   nullable=True)     # inference_id (for type=inference)
    model_id_filter  = Column(String,   nullable=True)     # model filter for time_window

    # Time window (populated for bundle_type=time_window)
    window_since     = Column(DateTime, nullable=True)
    window_until     = Column(DateTime, nullable=True)

    # Counts of collected artifacts
    inference_count  = Column(Integer,  default=0)
    audit_log_count  = Column(Integer,  default=0)
    proof_count      = Column(Integer,  default=0)
    policy_count     = Column(Integer,  default=0)
    nael_count       = Column(Integer,  default=0)
    tee_count        = Column(Integer,  default=0)

    # Integrity
    bundle_sha256    = Column(String,   nullable=False)    # SHA-256 of full bundle JSON
    artifacts_sha256 = Column(String,   nullable=True)     # SHA-256 of artifacts sub-section only
    signature        = Column(Text,     nullable=True)     # Ed25519 sig over bundle
    signed_by        = Column(String,   nullable=True)     # issuer key name

    # Actor
    exported_by      = Column(String,   nullable=True)     # username / system actor
    bascg_node_id    = Column(String,   nullable=True)     # CONSENSUS_NODE_ID at export time

    created_at       = Column(DateTime, default=lambda: datetime.utcnow())


class User(Base):
    """
    KavachX platform user with RBAC role assignment.
    Passwords are bcrypt-hashed.  Plain-text passwords are NEVER stored.
    """
    __tablename__ = "users"

    id              = Column(String,   primary_key=True, default=gen_uuid)
    email           = Column(String,   unique=True, nullable=False, index=True)
    name            = Column(String,   nullable=False)
    hashed_password = Column(String,   nullable=False)
    role            = Column(String,   nullable=False)   # super_admin | ml_engineer | compliance_officer | executive | auditor
    is_active       = Column(Boolean,  default=True)
    created_at      = Column(DateTime, default=lambda: datetime.utcnow())
    last_login_at   = Column(DateTime, nullable=True)
    created_by      = Column(String,   nullable=True)    # user id who created this account (null = bootstrap)


class BootstrapToken(Base):
    """
    One-time token for first-run superadmin registration.
    Only the SHA-256 hash is stored — the plaintext is shown once in server logs.
    """
    __tablename__ = "bootstrap_tokens"

    id             = Column(String,   primary_key=True, default=gen_uuid)
    token_hash     = Column(String,   nullable=False, unique=True)  # SHA-256 hex
    used           = Column(Boolean,  default=False)
    expires_at     = Column(DateTime, nullable=False)
    created_at     = Column(DateTime, default=lambda: datetime.utcnow())
    used_at        = Column(DateTime, nullable=True)
    used_by_email  = Column(String,   nullable=True)   # audit trail
