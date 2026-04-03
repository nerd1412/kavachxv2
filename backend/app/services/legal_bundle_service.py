"""
BASCG T3-D — Legal Bundle Export Service
=========================================

Assembles court-admissible evidence bundles from BASCG governance artefacts.

Legal basis
-----------
  IT Act 2000 S.65B     — Electronic records admissible as evidence in Indian courts
  DPDP 2023 S.8 / S.10  — Data protection obligations for AI processors
  MeitY AI Governance Framework 2024 — Mandatory audit trail for high-risk AI

Bundle types
------------
  "inference"   — All evidence for a single AI inference decision (deep dive)
  "time_window" — All evidence within a calendar window (compliance audit)

Each bundle is:
  1. Assembled from live DB state (no network calls needed)
  2. Integrity-hashed (SHA-256 over the artifacts section)
  3. Ed25519-signed by this node's BASCG key (non-repudiation)
  4. Persisted as a LegalExportRecord (hash + metadata, not full JSON)

Both local (dev/mock) and production modes are supported:
  Local      → mock TSA tokens, dev Ed25519 key, mock TEE documents
  Production → RFC 3161 TSA tokens already stored in DB; HSM-backed Ed25519 key

Config
------
  LEGAL_EXPORT_ENABLED             — globally enable/disable (default True)
  LEGAL_EXPORT_INCLUDE_RAW_DOCUMENTS — include raw TEE docs in bundle (default False)
  LEGAL_EXPORT_MAX_AUDIT_LOGS      — per-bundle hard cap (default 1000)
  LEGAL_EXPORT_SIGN_BUNDLES        — Ed25519-sign every bundle (default True)
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.orm_models import (
    AuditLog,
    AttestationReport,
    GovernancePolicy,
    InferenceEvent,
    LedgerAnchor,
    LegalExportRecord,
    NAELLicense,
    RemoteNodeAttestation,
    SyntheticMediaScanRecord,
)

logger = logging.getLogger("bascg.legal_bundle")

# ── Legal basis metadata (static, references Indian law) ─────────────────────

_LEGAL_BASIS = {
    "act": "Information Technology Act 2000 (India), Section 65B",
    "supplementary": [
        "Digital Personal Data Protection Act 2023 (DPDP), S.8 / S.10",
        "MeitY AI Governance Framework 2024",
        "BASCG Standard v3.6 — Bharat AI Sovereign Control Grid",
    ],
    "jurisdiction": "India",
    "certifier": "Ministry of Electronics and Information Technology (MeitY)",
    "note": (
        "This bundle constitutes an electronic record under IT Act S.65B and is "
        "legally admissible as evidence in Indian courts. The Ed25519 signature "
        "provides non-repudiation; the Merkle proofs and RFC 3161 TSA tokens "
        "provide cryptographic proof of the time and content of each audit log."
    ),
}


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class LegalBundle:
    """
    Fully assembled, signed evidence bundle.

    ``to_dict()`` returns the JSON-serialisable representation that is both
    returned to the caller and hashed for the LegalExportRecord.
    """
    bundle_id:      str
    bundle_version: str
    bundle_type:    str          # "inference" | "time_window"
    generated_at:   str          # ISO-8601 UTC
    generated_by:   str          # CONSENSUS_NODE_ID
    bascg_standard: str
    legal_basis:    Dict[str, Any]
    subject:        Dict[str, Any]
    artifacts:      Dict[str, Any]
    integrity:      Dict[str, Any]
    signature:      Optional[str] = None
    signed_by:      Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_id":      self.bundle_id,
            "bundle_version": self.bundle_version,
            "bundle_type":    self.bundle_type,
            "generated_at":   self.generated_at,
            "generated_by":   self.generated_by,
            "bascg_standard": self.bascg_standard,
            "legal_basis":    self.legal_basis,
            "subject":        self.subject,
            "artifacts":      self.artifacts,
            "integrity":      self.integrity,
            "signature":      self.signature,
            "signed_by":      self.signed_by,
        }


# ══════════════════════════════════════════════════════════════════════════════
#  LegalBundleService
# ══════════════════════════════════════════════════════════════════════════════

class LegalBundleService:
    """
    Stateless service that assembles and signs legal evidence bundles.
    All persistent state lives in the DB; no module-level mutable state.
    """

    # ── Public entry points ────────────────────────────────────────────────────

    async def export_inference_bundle(
        self,
        db:           AsyncSession,
        inference_id: str,
        actor:        Optional[str] = "system",
    ) -> LegalBundle:
        """
        Assemble a full evidence bundle for a single inference decision.

        Raises ValueError if ``inference_id`` is not found.
        """
        artifacts, subject = await self._collect_for_inference(db, inference_id)
        return await self._assemble(
            db          = db,
            bundle_type = "inference",
            subject     = subject,
            artifacts   = artifacts,
            actor       = actor,
            subject_id  = inference_id,
        )

    async def export_time_window_bundle(
        self,
        db:               AsyncSession,
        since:            datetime,
        until:            datetime,
        model_id_filter:  Optional[str] = None,
        actor:            Optional[str] = "system",
    ) -> LegalBundle:
        """
        Assemble an evidence bundle for all inferences in a time window.

        Always succeeds — returns an empty-artifact bundle if nothing matches.
        """
        artifacts, subject = await self._collect_for_time_window(
            db, since, until, model_id_filter
        )
        return await self._assemble(
            db              = db,
            bundle_type     = "time_window",
            subject         = subject,
            artifacts       = artifacts,
            actor           = actor,
            model_id_filter = model_id_filter,
            window_since    = since,
            window_until    = until,
        )

    # ── Assembly ──────────────────────────────────────────────────────────────

    async def _assemble(
        self,
        db:              AsyncSession,
        bundle_type:     str,
        subject:         Dict[str, Any],
        artifacts:       Dict[str, Any],
        actor:           Optional[str],
        subject_id:      Optional[str] = None,
        model_id_filter: Optional[str] = None,
        window_since:    Optional[datetime] = None,
        window_until:    Optional[datetime] = None,
    ) -> LegalBundle:
        node_id       = getattr(settings, "CONSENSUS_NODE_ID", "local-node")
        generated_at  = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        artifacts_sha = _sha256_json(artifacts)
        counts        = {k: len(v) if isinstance(v, list) else (1 if v else 0)
                         for k, v in artifacts.items()}

        integrity = {
            "artifacts_sha256": artifacts_sha,
            "counts":           counts,
        }

        bundle = LegalBundle(
            bundle_id      = str(uuid.uuid4()),
            bundle_version = "1.0",
            bundle_type    = bundle_type,
            generated_at   = generated_at,
            generated_by   = node_id,
            bascg_standard = "BASCG-3.6",
            legal_basis    = _LEGAL_BASIS,
            subject        = subject,
            artifacts      = artifacts,
            integrity      = integrity,
        )

        # Sign the bundle (excluding the signature fields themselves)
        if getattr(settings, "LEGAL_EXPORT_SIGN_BUNDLES", True):
            try:
                from app.core.crypto import crypto_service
                signable = bundle.to_dict()
                signable.pop("signature", None)
                signable.pop("signed_by",  None)
                bundle.signature = crypto_service.signer.sign(signable)
                bundle.signed_by = crypto_service.signer.issuer
            except Exception as exc:
                logger.warning("Legal bundle signing failed: %s", exc)

        # Persist export record
        bundle_dict   = bundle.to_dict()
        bundle_sha256 = _sha256_json(bundle_dict)

        try:
            record = LegalExportRecord(
                bundle_type     = bundle_type,
                subject_id      = subject_id,
                model_id_filter = model_id_filter,
                window_since    = window_since,
                window_until    = window_until,
                inference_count = len(artifacts.get("inference_events", [])),
                audit_log_count = len(artifacts.get("audit_logs", [])),
                proof_count     = len(artifacts.get("merkle_proofs", [])),
                policy_count    = len(artifacts.get("governance_policies", [])),
                nael_count      = len(artifacts.get("nael_licenses", [])),
                tee_count       = len(artifacts.get("tee_attestations", [])),
                bundle_sha256   = bundle_sha256,
                artifacts_sha256= artifacts_sha,
                signature       = bundle.signature,
                signed_by       = bundle.signed_by,
                exported_by     = actor,
                bascg_node_id   = node_id,
            )
            db.add(record)
            await db.commit()
            logger.info(
                "Legal bundle exported: type=%s bundle_id=%s sha256=%s",
                bundle_type, bundle.bundle_id, bundle_sha256,
            )
        except Exception as exc:
            logger.error("Failed to persist legal export record: %s", exc)

        return bundle

    # ── Inference artifact collector ───────────────────────────────────────────

    async def _collect_for_inference(
        self, db: AsyncSession, inference_id: str
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        # 1. Look up the inference event
        res = await db.execute(
            select(InferenceEvent).where(InferenceEvent.id == inference_id)
        )
        ev = res.scalars().first()
        if not ev:
            raise ValueError(f"Inference event {inference_id!r} not found")

        model_id = ev.model_id

        # 2. Audit logs for this inference
        res = await db.execute(
            select(AuditLog)
            .where(AuditLog.entity_id == inference_id)
            .order_by(AuditLog.timestamp.asc())
            .limit(getattr(settings, "LEGAL_EXPORT_MAX_AUDIT_LOGS", 1000))
        )
        audit_logs = list(res.scalars().all())

        # 3. Merkle proofs for anchored logs
        merkle_proofs = await self._compute_proofs(db, audit_logs)

        # 4. Unique LedgerAnchors referenced
        ledger_anchors = await self._anchors_for_logs(db, audit_logs)

        # 5. Governance policies that were violated
        policy_ids = _extract_policy_ids(ev.policy_violations)
        governance_policies = await self._policies_for_ids(db, policy_ids)

        # 6. NAEL licenses for this model
        nael_licenses = await self._nael_for_model(db, model_id) if model_id else []

        # 7. TEE attestations for this model
        tee_attestations = await self._tee_for_model(db, model_id) if model_id else []

        # 8. Synthetic media scans linked via context_metadata.scan_id
        scan_id = _extract_scan_id(ev.context_metadata)
        synthetic_scans = await self._synthetic_scans([scan_id], db) if scan_id else []

        artifacts = {
            "inference_events":   [_serialize_inference(ev)],
            "audit_logs":         [_serialize_audit_log(l) for l in audit_logs],
            "merkle_proofs":      merkle_proofs,
            "ledger_anchors":     [_serialize_anchor(a) for a in ledger_anchors],
            "governance_policies": [_serialize_policy(p) for p in governance_policies],
            "nael_licenses":      nael_licenses,
            "tee_attestations":   tee_attestations,
            "synthetic_media_scans": [_serialize_scan(s) for s in synthetic_scans],
            "peer_attestations":  [],   # not scoped to single inference
        }

        subject = {
            "type":                "inference_decision",
            "inference_id":        inference_id,
            "model_id":            model_id,
            "enforcement_decision": ev.enforcement_decision,
            "risk_score":          ev.risk_score,
            "timestamp":           _fmt_dt(ev.timestamp),
            "session_id":          ev.session_id,
        }

        return artifacts, subject

    # ── Time-window artifact collector ─────────────────────────────────────────

    async def _collect_for_time_window(
        self,
        db:              AsyncSession,
        since:           datetime,
        until:           datetime,
        model_id_filter: Optional[str],
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        max_logs = getattr(settings, "LEGAL_EXPORT_MAX_AUDIT_LOGS", 1000)

        # 1. Inference events in window
        q = (
            select(InferenceEvent)
            .where(and_(InferenceEvent.timestamp >= since,
                        InferenceEvent.timestamp <= until))
            .order_by(InferenceEvent.timestamp.asc())
            .limit(max_logs)
        )
        if model_id_filter:
            q = q.where(InferenceEvent.model_id == model_id_filter)
        res = await db.execute(q)
        events = list(res.scalars().all())

        # 2. Audit logs in window
        q = (
            select(AuditLog)
            .where(and_(AuditLog.timestamp >= since,
                        AuditLog.timestamp <= until))
            .order_by(AuditLog.timestamp.asc())
            .limit(max_logs)
        )
        res = await db.execute(q)
        audit_logs = list(res.scalars().all())

        # 3. Merkle proofs + anchors
        merkle_proofs  = await self._compute_proofs(db, audit_logs)
        ledger_anchors = await self._anchors_for_logs(db, audit_logs)

        # 4. Policy violations across all events
        policy_ids = set()
        for ev in events:
            policy_ids.update(_extract_policy_ids(ev.policy_violations))
        governance_policies = await self._policies_for_ids(db, list(policy_ids))

        # 5. NAEL + TEE per unique model
        model_ids = list({ev.model_id for ev in events if ev.model_id})
        nael_licenses:   List[dict] = []
        tee_attestations: List[dict] = []
        for mid in model_ids:
            nael_licenses.extend(await self._nael_for_model(db, mid))
            tee_attestations.extend(await self._tee_for_model(db, mid))

        # 6. Synthetic scans for scanned events
        scan_ids = [_extract_scan_id(ev.context_metadata) for ev in events]
        scan_ids = [s for s in scan_ids if s]
        synthetic_scans = await self._synthetic_scans(scan_ids, db) if scan_ids else []

        # 7. Peer attestations (all active peers in window)
        res = await db.execute(
            select(RemoteNodeAttestation)
            .where(and_(RemoteNodeAttestation.attested_at >= since,
                        RemoteNodeAttestation.attested_at <= until))
            .order_by(RemoteNodeAttestation.attested_at.asc())
            .limit(200)
        )
        peers = list(res.scalars().all())

        artifacts = {
            "inference_events":      [_serialize_inference(ev) for ev in events],
            "audit_logs":            [_serialize_audit_log(l) for l in audit_logs],
            "merkle_proofs":         merkle_proofs,
            "ledger_anchors":        [_serialize_anchor(a) for a in ledger_anchors],
            "governance_policies":   [_serialize_policy(p) for p in governance_policies],
            "nael_licenses":         nael_licenses,
            "tee_attestations":      tee_attestations,
            "synthetic_media_scans": [_serialize_scan(s) for s in synthetic_scans],
            "peer_attestations":     [_serialize_peer_attest(p) for p in peers],
        }

        subject = {
            "type":             "time_window",
            "since":            _fmt_dt(since),
            "until":            _fmt_dt(until),
            "model_id_filter":  model_id_filter,
            "inference_count":  len(events),
            "audit_log_count":  len(audit_logs),
        }

        return artifacts, subject

    # ── Helpers ────────────────────────────────────────────────────────────────

    async def _compute_proofs(
        self, db: AsyncSession, logs: List[AuditLog]
    ) -> List[Dict[str, Any]]:
        """Compute Merkle proof for each anchored audit log."""
        proofs: List[Dict[str, Any]] = []
        anchor_cache: Dict[str, Optional[LedgerAnchor]] = {}

        for log in logs:
            if not log.merkle_anchor_id or log.merkle_leaf_index is None:
                continue
            anchor_id = log.merkle_anchor_id
            if anchor_id not in anchor_cache:
                r = await db.execute(
                    select(LedgerAnchor).where(LedgerAnchor.id == anchor_id)
                )
                anchor_cache[anchor_id] = r.scalars().first()
            anchor = anchor_cache[anchor_id]
            if not anchor or anchor.anchor_status != "anchored":
                continue
            if not anchor.merkle_tree_json:
                continue
            try:
                from app.services.sovereign_ledger_sync import MerkleTree
                tree_data = (
                    anchor.merkle_tree_json
                    if isinstance(anchor.merkle_tree_json, dict)
                    else json.loads(anchor.merkle_tree_json)
                )
                leaves = tree_data.get("leaves", [])
                tree   = MerkleTree(leaves)
                steps  = tree.get_proof(log.merkle_leaf_index)
                proofs.append({
                    "audit_log_id":     log.id,
                    "chain_hash":       log.chain_hash,
                    "anchor_id":        anchor.id,
                    "leaf_index":       log.merkle_leaf_index,
                    "merkle_root":      anchor.merkle_root,
                    "tsa_provider":     anchor.tsa_provider,
                    "tsa_serial":       anchor.tsa_serial,
                    "tsa_timestamp":    _fmt_dt(anchor.tsa_timestamp),
                    "tsa_token_b64":    anchor.tsa_token_b64,
                    "proof_steps":      steps,
                    "verification_note": (
                        "Compute leaf = SHA256(bytes.fromhex(chain_hash)); "
                        "walk proof_steps bottom-up to root; "
                        "compare root with merkle_root; "
                        "verify merkle_root against TSA token (RFC 3161 or HMAC)."
                    ),
                })
            except Exception as exc:
                logger.warning("Merkle proof failed for log %s: %s", log.id, exc)

        return proofs

    async def _anchors_for_logs(
        self, db: AsyncSession, logs: List[AuditLog]
    ) -> List[LedgerAnchor]:
        ids = list({l.merkle_anchor_id for l in logs if l.merkle_anchor_id})
        if not ids:
            return []
        res = await db.execute(
            select(LedgerAnchor).where(LedgerAnchor.id.in_(ids))
        )
        return list(res.scalars().all())

    async def _policies_for_ids(
        self, db: AsyncSession, policy_ids: List[str]
    ) -> List[GovernancePolicy]:
        if not policy_ids:
            return []
        res = await db.execute(
            select(GovernancePolicy).where(GovernancePolicy.id.in_(policy_ids))
        )
        return list(res.scalars().all())

    async def _nael_for_model(
        self, db: AsyncSession, model_id: str
    ) -> List[Dict[str, Any]]:
        res = await db.execute(
            select(NAELLicense)
            .where(NAELLicense.model_id == model_id)
            .order_by(NAELLicense.created_at.desc())
            .limit(5)
        )
        return [_serialize_nael(n) for n in res.scalars().all()]

    async def _tee_for_model(
        self, db: AsyncSession, model_id: str
    ) -> List[Dict[str, Any]]:
        include_raw = getattr(settings, "LEGAL_EXPORT_INCLUDE_RAW_DOCUMENTS", False)
        res = await db.execute(
            select(AttestationReport)
            .where(AttestationReport.model_id == model_id)
            .order_by(AttestationReport.created_at.desc())
            .limit(5)
        )
        return [_serialize_attestation(r, include_raw) for r in res.scalars().all()]

    async def _synthetic_scans(
        self, scan_ids: List[str], db: AsyncSession
    ) -> List[SyntheticMediaScanRecord]:
        res = await db.execute(
            select(SyntheticMediaScanRecord)
            .where(SyntheticMediaScanRecord.id.in_(scan_ids))
        )
        return list(res.scalars().all())

    # ── Export record listing ──────────────────────────────────────────────────

    async def list_export_records(
        self,
        db:          AsyncSession,
        limit:       int = 50,
        bundle_type: Optional[str] = None,
    ) -> List[LegalExportRecord]:
        q = (
            select(LegalExportRecord)
            .order_by(LegalExportRecord.created_at.desc())
            .limit(limit)
        )
        if bundle_type:
            q = q.where(LegalExportRecord.bundle_type == bundle_type)
        res = await db.execute(q)
        return list(res.scalars().all())

    async def get_export_record(
        self, db: AsyncSession, record_id: str
    ) -> Optional[LegalExportRecord]:
        res = await db.execute(
            select(LegalExportRecord).where(LegalExportRecord.id == record_id)
        )
        return res.scalars().first()


# ══════════════════════════════════════════════════════════════════════════════
#  Serialisers — convert ORM rows to JSON-safe dicts
# ══════════════════════════════════════════════════════════════════════════════

def _serialize_inference(ev: InferenceEvent) -> Dict[str, Any]:
    return {
        "id":                  ev.id,
        "model_id":            ev.model_id,
        "confidence":          ev.confidence,
        "risk_score":          ev.risk_score,
        "enforcement_decision": ev.enforcement_decision,
        "fairness_flags":      ev.fairness_flags,
        "policy_violations":   ev.policy_violations,
        "timestamp":           _fmt_dt(ev.timestamp),
        "session_id":          ev.session_id,
    }


def _serialize_audit_log(log: AuditLog) -> Dict[str, Any]:
    return {
        "id":               log.id,
        "event_type":       log.event_type,
        "entity_id":        log.entity_id,
        "entity_type":      log.entity_type,
        "actor":            log.actor,
        "action":           log.action,
        "risk_level":       log.risk_level,
        "timestamp":        _fmt_dt(log.timestamp),
        "prev_hash":        log.prev_hash,
        "chain_hash":       log.chain_hash,
        "merkle_anchor_id": log.merkle_anchor_id,
        "merkle_leaf_index": log.merkle_leaf_index,
    }


def _serialize_anchor(a: LedgerAnchor) -> Dict[str, Any]:
    return {
        "id":                a.id,
        "log_count":         a.log_count,
        "merkle_root":       a.merkle_root,
        "tsa_provider":      a.tsa_provider,
        "tsa_serial":        a.tsa_serial,
        "tsa_timestamp":     _fmt_dt(a.tsa_timestamp),
        "anchor_status":     a.anchor_status,
        "anchored_at":       _fmt_dt(a.anchored_at),
    }


def _serialize_policy(p: GovernancePolicy) -> Dict[str, Any]:
    return {
        "id":              p.id,
        "name":            p.name,
        "policy_type":     p.policy_type,
        "severity":        p.severity,
        "jurisdiction":    p.jurisdiction,
        "enabled":         p.enabled,
        "policy_signature": p.policy_signature,
        "signed_by":       p.signed_by,
        "bundle_version":  p.bundle_version,
        "bundle_valid_until": _fmt_dt(p.bundle_valid_until),
    }


def _serialize_nael(n: NAELLicense) -> Dict[str, Any]:
    return {
        "id":                   n.id,
        "model_id":             n.model_id,
        "model_sha256":         n.model_sha256,
        "risk_classification":  n.risk_classification,
        "sector_restrictions":  n.sector_restrictions,
        "licensed_tee_platforms": n.licensed_tee_platforms,
        "issued_by":            n.issued_by,
        "issued_at":            _fmt_dt(n.issued_at),
        "valid_from":           _fmt_dt(n.valid_from),
        "valid_until":          _fmt_dt(n.valid_until),
        "revoked":              n.revoked,
        "revocation_reason":    n.revocation_reason,
    }


def _serialize_attestation(
    r: AttestationReport, include_raw: bool = False
) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "id":                   r.id,
        "platform":             r.platform,
        "model_id":             r.model_id,
        "nael_license_id":      r.nael_license_id,
        "pcr0":                 r.pcr0,
        "verified":             r.verified,
        "pcr0_match":           r.pcr0_match,
        "nael_valid":           r.nael_valid,
        "failure_reason":       r.failure_reason,
        "clearance_valid_until": _fmt_dt(r.clearance_valid_until),
        "created_at":           _fmt_dt(r.created_at),
    }
    if include_raw:
        d["raw_document_b64"] = r.raw_document_b64
    return d


def _serialize_scan(s: SyntheticMediaScanRecord) -> Dict[str, Any]:
    return {
        "id":               s.id,
        "content_hash":     s.content_hash,
        "content_type":     s.content_type,
        "detector":         s.detector,
        "is_synthetic":     s.is_synthetic,
        "confidence":       s.confidence,
        "detection_labels": s.detection_labels,
        "enforcement_action": s.enforcement_action,
        "election_context": s.election_context,
        "election_state":   s.election_state,
        "escalated_to_eci": s.escalated_to_eci,
        "evidence_hash":    s.evidence_hash,
        "created_at":       _fmt_dt(s.created_at),
    }


def _serialize_peer_attest(r: RemoteNodeAttestation) -> Dict[str, Any]:
    return {
        "id":                    r.id,
        "node_id":               r.node_id,
        "node_url":              r.node_url,
        "platform":              r.platform,
        "pcr0":                  r.pcr0,
        "pcr0_match":            r.pcr0_match,
        "verified":              r.verified,
        "clearance_valid_until": _fmt_dt(r.clearance_valid_until),
        "attested_at":           _fmt_dt(r.attested_at),
    }


def _serialize_export_record(r: LegalExportRecord) -> Dict[str, Any]:
    return {
        "id":               r.id,
        "bundle_type":      r.bundle_type,
        "subject_id":       r.subject_id,
        "model_id_filter":  r.model_id_filter,
        "window_since":     _fmt_dt(r.window_since),
        "window_until":     _fmt_dt(r.window_until),
        "inference_count":  r.inference_count,
        "audit_log_count":  r.audit_log_count,
        "proof_count":      r.proof_count,
        "policy_count":     r.policy_count,
        "nael_count":       r.nael_count,
        "tee_count":        r.tee_count,
        "bundle_sha256":    r.bundle_sha256,
        "artifacts_sha256": r.artifacts_sha256,
        "signed_by":        r.signed_by,
        "exported_by":      r.exported_by,
        "bascg_node_id":    r.bascg_node_id,
        "created_at":       _fmt_dt(r.created_at),
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _fmt_dt(dt) -> Optional[str]:
    if not dt:
        return None
    if isinstance(dt, str):
        return dt
    s = dt.isoformat()
    if s.endswith("+00:00"):
        return s[:-6] + "Z"
    if "+" not in s and not s.endswith("Z"):
        return s + "Z"
    return s


def _sha256_json(obj: Any) -> str:
    """Canonical SHA-256 of a JSON-serialisable object."""
    canonical = json.dumps(obj, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _extract_policy_ids(policy_violations: Any) -> List[str]:
    """Extract policy IDs from a policy_violations JSON list."""
    if not policy_violations or not isinstance(policy_violations, list):
        return []
    ids = []
    for v in policy_violations:
        if isinstance(v, dict) and v.get("policy_id"):
            ids.append(str(v["policy_id"]))
    return list(set(ids))


def _extract_scan_id(context_metadata: Any) -> Optional[str]:
    """Extract synthetic_media_scan_id from inference context_metadata."""
    if not context_metadata or not isinstance(context_metadata, dict):
        return None
    return context_metadata.get("synthetic_media_scan_id")


# Module-level singleton
legal_bundle_service = LegalBundleService()
