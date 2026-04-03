import time
import uuid
import json
import hashlib
import random
import re
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.config import settings
from app.models.schemas import InferenceRequest, GovernanceResult, EnforcementDecision, ExplanationOutput, RiskLevel, FairnessFlag as FF
from app.models.orm_models import InferenceEvent, AIModel, AuditLog, GovernancePolicy
from app.services.consent_service import consent_service
from app.modules.policy_engine import PolicyEngine
from app.modules.fairness_monitor import FairnessMonitor
from app.modules.explainability import ExplainabilityEngine
from app.modules.risk_scorer import RiskScorer
from app.modules.safety_scanner import SafetyScanner
from app.modules.pii_scanner import pii_scanner as _pii_scanner

import logging as _log
_gsvc_log = _log.getLogger("kavachx.governance")

# ── OCR availability probe (runs once at import time) ─────────────────────────
try:
    import pytesseract as _pytesseract
    from PIL import Image as _PILImage
    import io as _io
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False


def _ocr_extract_text(image_b64: str) -> str:
    """
    Decode a base64 image and run Tesseract OCR on it.
    Returns extracted text, or "" if OCR is unavailable or fails.

    This makes the PII scanner effective against:
      • Photos of Aadhaar cards, PAN cards, passports
      • Screenshots of bank statements
      • Document scans with sensitive numbers
    """
    if not _OCR_AVAILABLE or not image_b64:
        return ""
    try:
        import base64
        img_bytes = base64.b64decode(image_b64)
        img = _PILImage.open(_io.BytesIO(img_bytes)).convert("RGB")
        # --psm 3 = fully automatic page segmentation; oem 3 = LSTM + legacy
        text = _pytesseract.image_to_string(img, config="--psm 3 --oem 3")
        return text.strip()
    except Exception as _e:
        _gsvc_log.debug("OCR extraction failed (non-fatal): %s", _e)
        return ""


class GovernanceService:
    def __init__(self):
        self.fairness_monitor = FairnessMonitor()
        self.explainability_engine = ExplainabilityEngine()
        self.risk_scorer = RiskScorer()
        self.safety_scanner = SafetyScanner()

    async def _load_federated_policies(self, db: AsyncSession, jurisdiction: Optional[str]) -> List[Dict[str, Any]]:
        """
        Load and verify governance policies from the database, then merge with built-ins.

        BASCG P0 — Signed Policy Bundle Enforcement:
          Built-in policies: fetched from policy_bundle_service, verified via Ed25519
            bundle signature before use.  If bundle verification fails (should never
            happen in normal operation), a CRITICAL warning is emitted and the raw
            BUILT_IN_POLICIES list is used as a safe fallback so inference is never
            silently broken.
          DB policies: each ORM row must carry a valid per-row Ed25519 signature;
            rows without a signature or with an invalid signature are SILENTLY DROPPED.

        Jurisdiction matching is prefix-based (national / state layering):
          'GLOBAL' always applies
          'IN'     applies to all of India
          'IN.KA'  applies to Karnataka and also sees 'IN' and 'GLOBAL'
        """
        import logging as _log
        from app.modules.policy_engine import BUILT_IN_POLICIES
        from app.services.policy_bundle_service import policy_bundle_service

        _logger = _log.getLogger("kavachx.governance")

        # ── BASCG T1-B: verify built-in bundle signature before use ──────────
        builtin_policies: List[Dict[str, Any]]
        try:
            builtin_bundle = policy_bundle_service.get_builtin_bundle()
            if policy_bundle_service.verify_bundle(builtin_bundle):
                builtin_policies = builtin_bundle.policies
            else:
                _logger.critical(
                    "BASCG CRITICAL: built-in policy bundle signature INVALID — "
                    "falling back to raw BUILT_IN_POLICIES. Investigate key rotation."
                )
                builtin_policies = BUILT_IN_POLICIES
        except Exception as _exc:
            _logger.critical(
                "BASCG CRITICAL: built-in policy bundle verification raised %s — "
                "falling back to raw BUILT_IN_POLICIES.", _exc
            )
            builtin_policies = BUILT_IN_POLICIES

        result = await db.execute(
            select(GovernancePolicy).where(GovernancePolicy.enabled.is_(True))
        )
        rows = result.scalars().all()

        def _jurisdiction_match(policy_jur: Optional[str], ctx_jur: Optional[str]) -> bool:
            if not policy_jur or policy_jur.upper() == "GLOBAL":
                return True
            if not ctx_jur:
                return True
            pj = policy_jur.upper()
            cj = ctx_jur.upper()
            return cj.startswith(pj) or pj.startswith(cj)

        active_ctx_jur = (jurisdiction or "GLOBAL").upper()
        db_policies: List[Dict[str, Any]] = []
        rejected = 0

        for p in rows:
            if not _jurisdiction_match(p.jurisdiction or "GLOBAL", active_ctx_jur):
                continue
            # ── BASCG P0: reject unsigned / invalid-signature DB policies ─────
            if not policy_bundle_service.verify_db_policy(p):
                rejected += 1
                continue
            db_policies.append({
                "id":          p.id,
                "name":        p.name,
                "description": p.description or "",
                "policy_type": p.policy_type,
                "severity":    p.severity or "medium",
                "jurisdiction": p.jurisdiction or "GLOBAL",
                "rules":       p.rules or [],
            })

        if rejected:
            _logger.warning(
                "BASCG: %d DB policy row(s) rejected (unsigned/invalid signature) "
                "— only signed policies are enforced.", rejected
            )

        return builtin_policies + db_policies

    async def _get_last_audit_hash(self, db: AsyncSession) -> Optional[str]:
        result = await db.execute(
            select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(1)
        )
        last = result.scalars().first()
        return getattr(last, "chain_hash", None) if last else None

    def _build_chain_link(self, prev_hash: Optional[str], payload: Dict[str, Any]) -> Dict[str, Optional[str]]:
        """Compute deterministic hash chain link for audit log integrity."""
        # Stable, sorted JSON for reproducible hashes
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload_hash = hashlib.sha256(body).hexdigest()
        base = (prev_hash or "") + payload_hash
        chain_hash = hashlib.sha256(base.encode("utf-8")).hexdigest()
        return {"prev_hash": prev_hash, "chain_hash": chain_hash}

    async def evaluate_inference(
        self,
        request: InferenceRequest,
        db: AsyncSession,
        model: AIModel,
        is_simulation: bool = False
    ) -> GovernanceResult:
        start_time = time.time()
        
        # ── BASCG Core: Ensure context is initialized ──
        if request.context is None:
            request.context = {}

        # ── BASCG P1: NAEL Execution License Gate ────────────────────────────
        # Verify that this model holds a valid National AI Execution License
        # before allowing the inference to proceed.
        if not is_simulation:
            from app.services.nael_service import nael_service
            sector = (request.context or {}).get("domain")
            nael_result = await nael_service.validate_for_inference(
                db=db, model_id=model.id, sector=sector
            )
            if not nael_result.valid and nael_result.action == "block":
                # Immediate block — return synthetic GovernanceResult without running the full pipeline
                return await self._record_system_block(
                    db=db,
                    model=model,
                    request=request,
                    start_time=start_time,
                    policy_id="nael-gate",
                    policy_name="NAEL Execution License",
                    rule_id="nael-gate-001",
                    message=nael_result.reason,
                    risk_analysis={"nael_blocked": True}
                )
            # ALERT: license missing but enforcement not yet hard — log and continue
            if not nael_result.valid and nael_result.action == "alert":
                import logging
                logging.getLogger("kavachx.governance").warning(
                    "NAEL alert: model=%s reason=%s", model.id[:8], nael_result.reason
                )

        # ── BASCG T1-A: TEE Attestation Clearance Gate ───────────────────────
        # Verify that the compute node running this inference holds a valid
        # hardware attestation clearance (PCR0 verified, non-expired).
        #
        # Provider architecture:
        #   TEE_ATTESTATION_MODE=mock      → MockTEEClient   (local, no hardware)
        #   TEE_ATTESTATION_MODE=aws-nitro → NitroClient     (production enclave)
        #
        # Local Bridge (TEE_AUTO_ATTEST_DEV=True + ENVIRONMENT=development):
        #   Auto-generates a mock clearance on first inference — zero setup required.
        #
        # Production Bridge (TEE_AUTO_ATTEST_DEV=False):
        #   Compute node must pre-submit a real attestation document via
        #   POST /api/v1/attestation/verify before any inference is permitted.
        #   Missing or expired clearance → BLOCK (if TEE_ENFORCEMENT_ENABLED=True).
        if not is_simulation:
            from app.services.tee_attestation_service import tee_attestation_service
            tee_result = await tee_attestation_service.check_inference_clearance(
                db         = db,
                model_id   = model.id,
                session_id = request.session_id,
            )
            if not tee_result.valid and tee_result.action == "block":
                return await self._record_system_block(
                    db=db,
                    model=model,
                    request=request,
                    start_time=start_time,
                    policy_id="tee-attestation-gate",
                    policy_name="TEE Attestation Clearance",
                    rule_id="tee-gate-001",
                    message=tee_result.reason,
                    risk_analysis={"tee_blocked": True, "tee_platform": tee_result.platform}
                )
            if not tee_result.valid and tee_result.action == "alert":
                import logging as _tee_log
                _tee_log.getLogger("kavachx.governance").warning(
                    "TEE alert: model=%s platform=%s reason=%s",
                    model.id[:8], tee_result.platform, tee_result.reason,
                )
            # Stamp clearance info into context for audit trail
            if request.context is None:
                request.context = {}
            request.context["tee_clearance"] = {
                "valid":      tee_result.valid,
                "platform":   tee_result.platform,
                "pcr0_match": tee_result.pcr0_match,
                "report_id":  tee_result.report_id,
            }

        # Fairness evaluation
        raw_flags = self.fairness_monitor.evaluate(request.input_data, request.prediction, request.confidence)
        fairness_flags = []
        for f in raw_flags:
            try:
                fairness_flags.append(FF(
                    metric=f.get("metric", "unknown"),
                    group_a=f.get("group_a", "group_a"),
                    group_b=f.get("group_b", "group_b"),
                    disparity=float(f.get("disparity", 0.0)),
                    threshold=float(f.get("threshold", settings.FAIRNESS_DISPARITY_THRESHOLD)),
                    passed=bool(f.get("passed", False)),
                ))
            except Exception:
                pass

        inference_data = {
            "input_data": request.input_data, 
            "confidence": request.confidence, 
            "context": request.context or {}
        }
        
        # ===================================================================
        # INTENT-BASED MONITORING LAYER
        # Only trigger policy signals when there is clear NEGATIVE INTENT.
        # Normal analytical queries → PASS (no signals injected).
        # ===================================================================
        input_text = str(request.input_data.get("prompt", request.input_data.get("text", ""))).lower()
        output_text = str(request.prediction.get("content", request.prediction.get("text", ""))).lower()
        platform = str(request.input_data.get("platform", request.context.get("platform", "unknown")))

        if request.input_data.get("source") == "extension" or request.context.get("source") == "extension":
            request.context["shadow_ai_detected"] = True
            request.context["platform"] = platform
            request.input_data.setdefault("external_tool_signature", f"browser-extension:{platform}")

        # ── CATEGORY 0: BASCG T2-A PII & SENSITIVE DOCUMENT SHIELD ───────────────────────
        # Full regex scanner covers 30+ Indian statutory docs + global identifiers.
        # Runs on the ORIGINAL (case-sensitive) text before lowercasing.
        original_text = str(request.input_data.get("prompt", request.input_data.get("text", "")))

        # ── OCR: extract text from any embedded image before PII scan ─────────
        # Supports input_data.image_b64 (direct upload) and media_content_b64
        # (BASCG P3 synthetic media path).  Appended to original_text so the
        # same PII scanner runs over both without code duplication.
        _image_b64 = (
            request.input_data.get("image_b64")
            or request.input_data.get("document_b64")
            or getattr(request, "media_content_b64", None)
        )
        if _image_b64 and _OCR_AVAILABLE:
            _ocr_text = _ocr_extract_text(_image_b64)
            if _ocr_text:
                original_text = original_text + "\n" + _ocr_text
                request.input_data["ocr_text_extracted"] = True
                request.context["ocr_chars"] = len(_ocr_text)
                _gsvc_log.info("OCR extracted %d chars from uploaded image", len(_ocr_text))
        pii_result = _pii_scanner.scan(original_text)

        if pii_result.pii_detected or pii_result.should_alert:
            request.input_data["pii_detected"]      = pii_result.pii_detected
            request.input_data["pii_types"]         = pii_result.pii_types
            request.input_data["personal_data_used"] = pii_result.personal_data_used
            request.input_data["pii_risk_boost"]    = pii_result.risk_boost
            request.context["pii_types"]            = pii_result.pii_types
            if pii_result.violations:
                request.context["pii_violations"]   = pii_result.violations
            # Inherit domain hints from scan
            if pii_result.health_access_intent and "domain" not in request.context:
                request.context["domain"] = "healthcare"
            elif pii_result.financial_access_intent and "domain" not in request.context:
                request.context["domain"] = "finance"
            elif pii_result.pii_detected:
                request.context.setdefault("domain", "privacy")
            # Consent gate — absent for third-party / financial access patterns
            if pii_result.consent_likely_absent and "consent_verified" not in request.input_data:
                request.input_data["consent_verified"] = False
            # Third-party access flag for DPDP S.9 / Aadhaar Act S.29
            if pii_result.third_party_access:
                request.input_data["third_party_pii_access"] = True
            # Propagate risk boost into context so risk_scorer can use it
            if pii_result.risk_boost > 0:
                request.context["pii_risk_boost"] = pii_result.risk_boost

        
        # 1a. Financial Bias — pincode/caste proxy discrimination (RBI Fair Lending)
        # Using pincode/location as ANY factor in loan decisions IS the violation itself.
        LOAN_KW    = ["loan", "credit", "lending", "approval", "application", "approve", "reject"]
        PINCODE_KW = ["632001", "pincode", "pin code", "zip code", "area code", "location"]
        if any(w in input_text for w in LOAN_KW) and any(w in input_text for w in PINCODE_KW):
            request.input_data["caste_proxy_score"] = 0.90
            request.context["domain"] = "finance"

        # 1b. Financial Policy Bypass — explicit attempts to override DTI limits
        if ("loan" in input_text or "credit" in input_text) and any(w in input_text for w in ["ignore", "bypass", "override", "skip", "circumvent"]):
            if any(w in input_text for w in ["debt", "income", "ratio", "dti", "limit", "cap"]):
                request.input_data["debt_ratio"] = 0.55
                request.context["domain"] = "finance"

        # 1c. Healthcare Privacy Breach — accessing patient data without consent
        if any(w in input_text for w in ["patient", "abdm", "medical record", "health record"]):
            if any(w in input_text for w in ["extract", "download", "export", "share", "leak", "send"]):
                request.context["domain"] = "healthcare"
                request.context["abdm"] = True
                request.input_data["personal_data_used"] = True
                request.input_data["consent_verified"] = False

        # 1d. Parental Monitoring & Child Safety — profiling minors without consent
        if any(w in input_text for w in ["student", "minor", "child", "son", "daughter", "kid"]):
            if any(w in input_text for w in ["track", "profile", "surveil", "monitor behavior", "spy", "watch", "history"]):
                request.context["domain"] = "education"
                request.input_data["continuous_monitoring"] = True
                request.input_data["parental_consent"] = False

        # ── CATEGORY 2: HUMAN_REVIEW triggers (ambiguous risk, needs judgment) ──
        
        # 2a. DTI ratio checks (legitimate compliance query)
        if ("loan" in input_text or "credit" in input_text) and ("debt" in input_text or "income" in input_text or "ratio" in input_text):
            if "debt_ratio" not in request.input_data:  # Don't override if BLOCK already set
                request.input_data["debt_ratio"] = 0.45
                request.context["domain"] = "finance"

        # ── India DPDP 2023 Consent Check ──
        # Check formal consent ledger for healthcare or personal data context
        if request.context.get("jurisdiction") == "IN" or request.context.get("domain") == "healthcare":
            if request.input_data.get("personal_data_used") or request.context.get("domain") == "healthcare":
                principal_id = request.context.get("user_id", "anonymous")
                purpose = request.context.get("domain", "general_processing")
                has_consent = await consent_service.verify_consent(db, principal_id, purpose)
                request.input_data["consent_verified"] = has_consent
                if not has_consent:
                    request.input_data["dpdp_violation"] = True


        # 2b. Worker deactivation / gig economy decisions
        if any(w in input_text for w in ["deactivate", "terminate", "fire", "suspend"]):
            if any(w in input_text for w in ["worker", "driver", "rider", "employee", "account"]):
                request.context["algorithmic_deactivation"] = True

        # 2c. Insurance claim decisions needing explainability
        if ("insurance" in input_text or "claim" in input_text) and any(w in input_text for w in ["reject", "deny", "approve", "process", "decide"]):
            request.context["domain"] = "insurance"
            request.input_data["explainability_score"] = 0.25

        # 2d. Low confidence prompt (user expresses uncertainty)
        if any(w in input_text for w in ["not sure", "unsure", "uncertain", "confused about"]):
            request.confidence = 0.45

        # ── CATEGORY 3: ALERT triggers (monitoring, no action needed) ──
        # Analytical technical queries now PASS by default (no signals injected)
        # to align with user requirement: "Likely allow unless a real policy risk exists"
        
        # 3a. Model drift alert — Only trigger if it's a NEGATIVE INTENT or CRITICAL levels
        # (Previously this triggered ALERT, now we just log it in context without score)
        if "model" in input_text and any(w in input_text for w in ["drift", "degrade", "degradation", "psi"]):
            request.context["performance_check"] = True

        # 3b. Economic equity analysis — explicit disparity measurement
        # (Previously this triggered ALERT, now we just log it in context)
        if any(w in input_text for w in ["disparity", "bias report", "equity gap", "inclusion audit"]):
            if any(w in input_text for w in ["analyze", "report", "measure", "assess", "check"]):
                request.context["equity_analysis"] = True

        # ── NO triggers for normal/benign prompts ──
        # "Analyze the economic disparity gap" → triggers 3b (ALERT) only  
        # "Run a performance check" → NO trigger (normal query = PASS)
        # "Help me write code" → NO trigger (normal query = PASS)
        # "What is machine learning?" → NO trigger (normal query = PASS)

        # ── BASCG P3 Synthetic Media Shield ──────────────────────────────────
        # If the inference carries base64-encoded media bytes, scan for deepfakes
        # BEFORE policy evaluation.  A BLOCK/ESCALATE result short-circuits the
        # full pipeline — same pattern as the NAEL gate above.
        media_b64 = getattr(request, "media_content_b64", None)
        if media_b64:
            import base64
            from app.services.synthetic_media_service import synthetic_media_service
            try:
                media_bytes = base64.b64decode(media_b64)
                media_ct    = getattr(request, "media_content_type", None)
                scan_result = await synthetic_media_service.scan(
                    content      = media_bytes,
                    content_type = media_ct,
                    submitted_by = request.model_id,
                    db           = db,
                )
                if scan_result.enforcement_action in ("BLOCK", "ESCALATE"):
                    return await self._record_system_block(
                        db=db,
                        model=model,
                        request=request,
                        start_time=start_time,
                        policy_id="synthetic-media-shield",
                        policy_name="BASCG Synthetic Media Shield",
                        rule_id="p3-deepfake-block",
                        message=f"Deepfake/synthetic media detected: labels={scan_result.detection.labels}",
                        risk_analysis={
                            "synthetic_media_scan_id": scan_result.scan_id,
                            "synthetic_confidence": scan_result.detection.confidence,
                        }
                    )
                # ALERT: flag in context but continue evaluation
                if scan_result.enforcement_action == "ALERT":
                    request.input_data["synthetic_media_confidence"] = scan_result.detection.confidence
                    request.input_data["synthetic_media_labels"]     = scan_result.detection.labels
                    request.context["synthetic_media_scan_id"]       = scan_result.scan_id
            except Exception as _sm_exc:
                import logging as _l
                _l.getLogger("kavachx.governance").warning(
                    "Synthetic media scan failed (non-fatal): %s", _sm_exc
                )

        # Safety scan — always run for toxicity/injection detection
        if not request.input_data.get("toxicity_score") and not request.input_data.get("prompt_injection_score"):
            safety_results = self.safety_scanner.analyze_exchange(input_text, output_text)
            request.input_data.update(safety_results)
            if "injection_score" in request.input_data and "prompt_injection_score" not in request.input_data:
                request.input_data["prompt_injection_score"] = request.input_data["injection_score"]
            inference_data["input_data"] = request.input_data

        flag_dicts = [f.model_dump() for f in fairness_flags]

        # Federated policy set (national/state/sector modules + built-ins)
        active_jurisdiction = (request.context or {}).get("jurisdiction")
        policies = await self._load_federated_policies(db, active_jurisdiction)
        policy_engine = PolicyEngine(policies=policies)

        # Prepare final inference data payload for policy evaluation
        inference_data = {
            "input_data": request.input_data,
            "confidence": request.confidence,
            "context": request.context or {}
        }

        # Policy Evaluation (Pass 1 — without risk score)
        policy_violations, _ = policy_engine.evaluate(inference_data, flag_dicts, 0.0)
        
        # Risk Scoring (derived from violations + flags)
        risk_score = self.risk_scorer.compute(request.confidence, flag_dicts, policy_violations, request.context or {})
        risk_level = self.risk_scorer.get_risk_level(risk_score)
        
        # Final Enforcement (Pass 2 — check if risk score triggers additional policies)
        violations_with_risk, final_decision = policy_engine.evaluate(inference_data, flag_dicts, risk_score)
        policy_violations = violations_with_risk

        # ── Build human-readable reason ──
        if policy_violations:
            primary_reason = policy_violations[0].get("message", "Policy violation detected")
            policy_name = policy_violations[0].get("policy_name", "Unknown Policy")
        elif risk_score > 0.60:
            primary_reason = f"Elevated Risk ({int(risk_score*100)}%) — monitoring advised"
            policy_name = "Systemic Risk Threshold"
        else:
            primary_reason = "No policy violation detected."
            policy_name = "None"

        # Explainability
        domain = (request.context or {}).get("domain", "default")
        explanation = self.explainability_engine.explain(request.input_data, request.prediction, request.confidence, domain)
        explanation["reason"] = primary_reason
        explanation["policy_triggered"] = policy_name

        inference_id = str(uuid.uuid4())
        processing_ms = round((time.time() - start_time) * 1000, 2)

        # Context metadata
        context_metadata = {**(request.context or {}), "processing_ms": processing_ms, "platform": platform}
        if is_simulation:
            context_metadata["source"] = "simulation"

        # Persist inference event
        event = InferenceEvent(
            id=inference_id,
            model_id=model.id,
            input_data=request.input_data,
            prediction=request.prediction,
            confidence=request.confidence,
            risk_score=risk_score,
            enforcement_decision=final_decision.value,
            fairness_flags=flag_dicts,
            policy_violations=policy_violations,
            explanation=explanation,
            context_metadata=context_metadata,
            session_id=request.session_id,
        )
        db.add(event)

        # ── Audit Logs ──
        audit_actor = request.model_id if not is_simulation else f"simulation/{domain}"
        raw_prompt = str(request.input_data.get("prompt", request.input_data.get("text", "")))
        # Guardian Protocol #7 — PII masking before audit-log storage
        if request.input_data.get("pii_detected"):
            prompt_text = _pii_scanner.mask(raw_prompt)[:200]
        else:
            prompt_text = raw_prompt[:200]

        audit_details = {
            "risk_score": risk_score, 
            "reason": primary_reason,
            "prompt": prompt_text,
            "policy_triggered": policy_name,
            "decision": final_decision.value,
            "platform": platform,
            "session_id": request.session_id,
            "violations": [v.get("policy_name") for v in policy_violations],
            "fairness_flags": len(fairness_flags), 
            "scenario": domain if is_simulation else None
        }

        # Compute integrity chain link for this and subsequent audit entries
        last_hash = await self._get_last_audit_hash(db)
        chain_link = self._build_chain_link(last_hash, {
            "event_type": "inference_evaluated",
            "entity_id": inference_id,
            "actor": audit_actor,
            "details": audit_details,
        })

        db.add(AuditLog(
            event_type="inference_evaluated",
            entity_id=inference_id,
            entity_type="inference",
            actor=audit_actor,
            action=f"decision={final_decision.value}",
            details=audit_details,
            risk_level=risk_level.value,
            prev_hash=chain_link["prev_hash"],
            chain_hash=chain_link["chain_hash"],
        ))

        current_hash = chain_link["chain_hash"]

        if final_decision == EnforcementDecision.BLOCK:
            details_block = {
                "inference_id": inference_id,
                "reason": primary_reason,
                "prompt": prompt_text,
                "violations": policy_violations[:3],
            }
            link_block = self._build_chain_link(current_hash, {
                "event_type": "model_blocked",
                "entity_id": model.id,
                "actor": "governance_engine",
                "details": details_block,
            })
            current_hash = link_block["chain_hash"]
            db.add(AuditLog(
                event_type="model_blocked",
                entity_id=model.id,
                entity_type="ai_model",
                actor="governance_engine",
                action="blocked inference due to policy violation",
                details=details_block,
                risk_level="critical",
                prev_hash=link_block["prev_hash"],
                chain_hash=link_block["chain_hash"],
            ))
        elif policy_violations:
            details_violation = {
                "reason": primary_reason,
                "prompt": prompt_text,
                "violations": policy_violations[:3],
            }
            link_violation = self._build_chain_link(current_hash, {
                "event_type": "policy_violated",
                "entity_id": inference_id,
                "actor": audit_actor,
                "details": details_violation,
            })
            current_hash = link_violation["chain_hash"]
            db.add(AuditLog(
                event_type="policy_violated", 
                entity_id=inference_id, 
                entity_type="inference",
                actor=audit_actor, 
                action="policy violation detected",
                details=details_violation, 
                risk_level=risk_level.value,
                prev_hash=link_violation["prev_hash"],
                chain_hash=link_violation["chain_hash"],
            ))

        fairness_failed = [f for f in fairness_flags if not f.passed]
        if fairness_failed:
            details_fair = {"flags": [f.model_dump() for f in fairness_failed]}
            link_fair = self._build_chain_link(current_hash, {
                "event_type": "fairness_issue_detected",
                "entity_id": inference_id,
                "actor": audit_actor,
                "details": details_fair,
            })
            current_hash = link_fair["chain_hash"]
            db.add(AuditLog(
                event_type="fairness_issue_detected", 
                entity_id=inference_id, 
                entity_type="inference",
                actor=audit_actor, 
                action="fairness threshold exceeded",
                details=details_fair, 
                risk_level="high",
                prev_hash=link_fair["prev_hash"],
                chain_hash=link_fair["chain_hash"],
            ))

        # Randomized audit probing: occasionally emit an additional probe log,
        # even when everything looks safe, to harden against gaming.
        probe_prob = getattr(settings, "AUDIT_PROBE_PROBABILITY", 0.05)
        if random.random() < probe_prob:
            probe_details = {
                "inference_id": inference_id,
                "risk_score": risk_score,
                "decision": final_decision.value,
                "platform": platform,
                "probe_reason": "Randomized governance probe for continuous behavioral monitoring.",
            }
            link_probe = self._build_chain_link(current_hash, {
                "event_type": "random_audit_probe",
                "entity_id": inference_id,
                "actor": "governance_engine",
                "details": probe_details,
            })
            current_hash = link_probe["chain_hash"]
            db.add(AuditLog(
                event_type="random_audit_probe",
                entity_id=inference_id,
                entity_type="inference",
                actor="governance_engine",
                action="random_probe",
                details=probe_details,
                risk_level=risk_level.value,
                prev_hash=link_probe["prev_hash"],
                chain_hash=link_probe["chain_hash"],
            ))

        await db.commit()

        # Broadcast real-time update over WebSocket
        from app.services.websocket_manager import manager
        import asyncio
        asyncio.create_task(manager.broadcast({
            "type": "new_inference",
            "inference_id": inference_id,
            "risk_score": risk_score,
            "enforcement_decision": final_decision.value,
        }))

        _risk_analysis: Dict[str, Any] = {
            "composite_risk": risk_score,
            "risk_level": risk_level.value,
            "violation_count": len(policy_violations),
            "fairness_flags": len(fairness_flags),
            "platform": platform,
        }
        if request.input_data.get("pii_detected"):
            _risk_analysis["pii_detected"]   = True
            _risk_analysis["pii_types"]      = request.input_data.get("pii_types", [])
            _risk_analysis["pii_risk_boost"] = request.input_data.get("pii_risk_boost", 0.0)
        if request.context.get("pii_violations"):
            _risk_analysis["pii_violations"] = request.context["pii_violations"]

        return GovernanceResult(
            inference_id=inference_id,
            model_id=model.id,
            risk_score=risk_score,
            risk_level=risk_level,
            enforcement_decision=final_decision,
            fairness_flags=fairness_flags,
            policy_violations=policy_violations,
            risk_analysis=_risk_analysis,
            explanation=ExplanationOutput(
                top_features=explanation.get("top_features", []),
                summary=explanation.get("summary", ""),
                confidence_note=explanation.get("confidence_note", ""),
                reason=explanation.get("reason"),
                policy_triggered=explanation.get("policy_triggered")
            ),
            timestamp=datetime.utcnow(),
            processing_time_ms=processing_ms,
        )

    async def _record_system_block(
        self,
        db: AsyncSession,
        model: AIModel,
        request: InferenceRequest,
        start_time: float,
        policy_id: str,
        policy_name: str,
        rule_id: str,
        message: str,
        risk_analysis: Dict[str, Any] = {}
    ) -> GovernanceResult:
        """Helper to log and respond to early-return security/compliance blocks."""
        from app.services.websocket_manager import manager
        import asyncio

        inf_id = str(uuid.uuid4())
        ms = round((time.time() - start_time) * 1000, 2)
        
        # 1. Create Inference Event
        event = InferenceEvent(
            id=inf_id,
            model_id=model.id,
            input_data=request.input_data,
            prediction=request.prediction,
            confidence=request.confidence,
            risk_score=1.0,
            enforcement_decision=EnforcementDecision.BLOCK.value,
            fairness_flags=[],
            policy_violations=[{
                "policy_id": policy_id,
                "policy_name": policy_name,
                "rule_id": rule_id,
                "severity": "critical",
                "action": "block",
                "message": message,
                "jurisdiction": "IN",
            }],
            explanation={
                "summary": message,
                "reason": message,
                "policy_triggered": policy_name,
                "confidence_note": "Early system interdiction."
            },
            context_metadata={**(request.context or {}), "processing_ms": ms, "system_gate": policy_id},
        )
        db.add(event)

        # 2. Sequential Audit Chaining
        last_hash = await self._get_last_audit_hash(db)
        audit_details = {
            "risk_score": 1.0,
            "reason": message,
            "policy_triggered": policy_name,
            "decision": "BLOCK",
            "gate_id": policy_id,
        }
        
        # Chain Link 1: The Event
        link1 = self._build_chain_link(last_hash, {
            "event_type": "system_gate_interdiction",
            "entity_id": inf_id,
            "details": audit_details
        })
        db.add(AuditLog(
            event_type="system_gate_interdiction",
            entity_id=inf_id,
            entity_type="inference",
            actor="governance_engine",
            action=f"block_at_{policy_id}",
            details=audit_details,
            risk_level="critical",
            prev_hash=link1["prev_hash"],
            chain_hash=link1["chain_hash"],
        ))

        # Chain Link 2: The Model Block (explicitly logged)
        link2 = self._build_chain_link(link1["chain_hash"], {
            "event_type": "model_blocked",
            "entity_id": model.id,
            "details": audit_details
        })
        db.add(AuditLog(
            event_type="model_blocked",
            entity_id=model.id,
            entity_type="ai_model",
            actor="governance_engine",
            action="enforced_system_policy_interdiction",
            details=audit_details,
            risk_level="critical",
            prev_hash=link2["prev_hash"],
            chain_hash=link2["chain_hash"],
        ))
        
        await db.commit()

        # 3. WebSocket Broadcast
        asyncio.create_task(manager.broadcast({
            "type": "new_inference",
            "inference_id": inf_id,
            "risk_score": 1.0,
            "enforcement_decision": "BLOCK",
        }))

        return GovernanceResult(
            inference_id=inf_id,
            model_id=model.id,
            risk_score=1.0,
            risk_level=RiskLevel.HIGH,
            enforcement_decision=EnforcementDecision.BLOCK,
            fairness_flags=[],
            policy_violations=[{
                "policy_id": policy_id,
                "policy_name": policy_name,
                "rule_id": rule_id,
                "severity": "critical",
                "action": "block",
                "message": message,
                "jurisdiction": "IN",
            }],
            risk_analysis={"composite_risk": 1.0, "risk_level": "high", **risk_analysis},
            explanation=ExplanationOutput(
                top_features=[], summary=message,
                confidence_note="Inference blocked by system gateway.",
                reason=message,
                policy_triggered=policy_name,
            ),
            timestamp=datetime.now(timezone.utc),
            processing_time_ms=ms,
        )

# Global service instance
governance_service = GovernanceService()
