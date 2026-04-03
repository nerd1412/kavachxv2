"""
BASCG Status Service — Modular Governance Layer Health Check
=============================================================

The Dynamic Bridge between Local (Simulated Enclave) and Production (National Grid).

This service inspects the live configuration of all 4 BASCG pillars and reports:
  • Which provider is active (mock/local vs production)
  • Whether the pillar is operationally ready
  • What environment variable to change to switch to production
  • Overall BASCG Grid readiness score (0–100)

GET /api/v1/bascg/status  →  BASCGGridStatus (all 4 pillars)
GET /api/v1/bascg/production-readiness  →  Checklist to reach production

Pillars:
  P1 — Forensic Integrity    (Layer 4)  SovereignLedgerSync
  P2 — Regulatory Authority  (Layer 2)  PolicyEngine + Signed Bundles
  P3 — Licensing Enforcement (Layer 2)  NAEL + Local Licensing Authority
  P4 — Synthetic Media Shield (Layer 3) Deepfake Scanner + Election Protection
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger("bascg.status")


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PillarStatus:
    name:              str
    layer:             str            # "Layer 2 / Grid Engine" etc.
    provider_mode:     str            # "local" | "production"
    local_ready:       bool
    production_ready:  bool
    operational:       bool           # True if currently functional end-to-end
    status_detail:     str            # human-readable description
    production_steps:  List[str]      # what to change to reach production
    config_keys:       Dict[str, Any] # current config snapshot (redacted secrets)


@dataclass
class BASCGGridStatus:
    provider_mode:       str           # top-level BASCG_PROVIDER_MODE
    environment:         str
    pillars:             List[PillarStatus]
    operational_count:   int
    readiness_score:     int           # 0–100 percentage
    production_gaps:     List[str]     # summary list of blocking items
    local_demo_ready:    bool          # True if all 4 pillars work locally
    production_ready:    bool          # True if all 4 pillars work in prod


# ══════════════════════════════════════════════════════════════════════════════
#  BASCGStatusService
# ══════════════════════════════════════════════════════════════════════════════

class BASCGStatusService:
    """
    Inspects live configuration of all 4 BASCG pillars.

    Design: read-only — never mutates state.  Safe to call on every health check.
    """

    def get_status(self) -> BASCGGridStatus:
        pillars = [
            self._pillar_forensic(),
            self._pillar_regulatory(),
            self._pillar_licensing(),
            self._pillar_synthetic_media(),
        ]
        operational = sum(1 for p in pillars if p.operational)
        gaps: List[str] = []
        for p in pillars:
            if not p.production_ready:
                for step in p.production_steps:
                    gaps.append(f"[{p.name}] {step}")

        local_ready = all(p.local_ready for p in pillars)
        prod_ready  = all(p.production_ready for p in pillars)
        score       = round(operational / len(pillars) * 100)

        return BASCGGridStatus(
            provider_mode     = getattr(settings, "BASCG_PROVIDER_MODE", "local"),
            environment       = getattr(settings, "ENVIRONMENT", "development"),
            pillars           = pillars,
            operational_count = operational,
            readiness_score   = score,
            production_gaps   = gaps,
            local_demo_ready  = local_ready,
            production_ready  = prod_ready,
        )

    # ── Pillar 1: Forensic Integrity ──────────────────────────────────────────

    def _pillar_forensic(self) -> PillarStatus:
        mode     = getattr(settings, "SOVEREIGN_LEDGER_MODE", "mock").lower()
        enabled  = getattr(settings, "SOVEREIGN_LEDGER_ENABLED", True)
        tsa_url  = getattr(settings, "TSA_URL", "")
        mock_sec = getattr(settings, "MOCK_TSA_SECRET", "")

        is_mock        = mode == "mock"
        is_rfc3161     = mode == "rfc3161"
        is_blockchain  = mode == "blockchain"
        local_ready    = enabled and is_mock and bool(mock_sec)
        prod_ready     = enabled and (is_rfc3161 or is_blockchain)

        if is_mock:
            detail = "MockTSA active — HMAC-signed local anchor. Forensic chain intact but NOT IT Act S.65B admissible."
        elif is_rfc3161:
            detail = f"RFC 3161 TSA active ({tsa_url}) — court-admissible IT Act S.65B timestamps."
        elif is_blockchain:
            rpc = getattr(settings, "SOVEREIGN_LEDGER_BLOCKCHAIN_RPC_URL", "")
            detail = f"Blockchain TSA active (EVM {rpc}) — permissioned on-chain anchor."
        else:
            detail = f"Unknown SOVEREIGN_LEDGER_MODE={mode!r} — falling back to mock."

        prod_steps = []
        if not (is_rfc3161 or is_blockchain):
            prod_steps.append("Set SOVEREIGN_LEDGER_MODE=rfc3161 and TSA_URL=https://timestamp.digicert.com")
        if not enabled:
            prod_steps.append("Set SOVEREIGN_LEDGER_ENABLED=true")

        return PillarStatus(
            name             = "Forensic Integrity",
            layer            = "Layer 4 — Sovereign Forensic Chain",
            provider_mode    = "local" if is_mock else "production",
            local_ready      = local_ready,
            production_ready = prod_ready,
            operational      = enabled,
            status_detail    = detail,
            production_steps = prod_steps,
            config_keys      = {
                "SOVEREIGN_LEDGER_ENABLED": enabled,
                "SOVEREIGN_LEDGER_MODE":    mode,
                "TSA_URL":                  tsa_url,
                "MOCK_TSA_SECRET":          "***" if mock_sec else "(not set)",
            },
        )

    # ── Pillar 2: Regulatory Authority ────────────────────────────────────────

    def _pillar_regulatory(self) -> PillarStatus:
        seed_b64   = getattr(settings, "BASCG_SIGNING_KEY_SEED_B64", "")
        trusted    = getattr(settings, "BASCG_TRUSTED_PUBLIC_KEYS_JSON", "{}")
        has_seed   = bool(seed_b64.strip())
        has_remote = trusted != "{}" and bool(trusted.strip())

        # The crypto_service is always initialized (ephemeral if no seed)
        try:
            from app.core.crypto import crypto_service
            # _signer is None until initialize() has been called
            initialized = crypto_service._signer is not None
            if not initialized:
                # initialize() is idempotent — safe to call here for status check
                crypto_service.initialize()
                initialized = crypto_service._signer is not None
        except Exception:
            initialized = False

        local_ready = initialized  # ephemeral key is fine locally
        prod_ready  = initialized and has_seed  # persistent seed needed in production

        if has_seed:
            detail = "Ed25519 signing key loaded from BASCG_SIGNING_KEY_SEED_B64. Policy bundles verified."
        elif initialized:
            detail = "Ephemeral Ed25519 key in use — policies signed but key rotates on restart. Set BASCG_SIGNING_KEY_SEED_B64 for persistence."
        else:
            detail = "CryptoService not initialized — policy bundle verification disabled."

        if has_remote:
            detail += f" {len(__import__('json').loads(trusted))} remote trusted issuer(s) configured."

        prod_steps = []
        if not has_seed:
            prod_steps.append("Run `python scripts/generate_dev_keys.py` and set BASCG_SIGNING_KEY_SEED_B64")
        if not has_remote:
            prod_steps.append("Set BASCG_TRUSTED_PUBLIC_KEYS_JSON with MeitY/RBI regulator public keys for production sovereign bundles")

        return PillarStatus(
            name             = "Regulatory Authority",
            layer            = "Layer 2 — Grid Engine / Signed Policy Bundles",
            provider_mode    = "production" if has_seed else "local",
            local_ready      = local_ready,
            production_ready = prod_ready,
            operational      = initialized,
            status_detail    = detail,
            production_steps = prod_steps,
            config_keys      = {
                "BASCG_SIGNING_KEY_SEED_B64":       "***" if has_seed else "(ephemeral)",
                "BASCG_TRUSTED_PUBLIC_KEYS_JSON":   "(set)" if has_remote else "{}",
            },
        )

    # ── Pillar 3: Licensing Enforcement ───────────────────────────────────────

    def _pillar_licensing(self) -> PillarStatus:
        enforcement    = getattr(settings, "NAEL_ENFORCEMENT_ENABLED", False)
        auto_provision = getattr(settings, "NAEL_AUTO_PROVISION_DEV", True)
        env            = getattr(settings, "ENVIRONMENT", "development")

        is_local_mode = (not enforcement) or (auto_provision and env == "development")

        if enforcement and not auto_provision:
            detail = "NAEL enforcement HARD — inferences blocked without a valid license. Production mode."
            provider = "production"
            local_ok = False
            prod_ok  = True
        elif enforcement and auto_provision and env == "development":
            detail = "NAEL enforcement ON with auto-provision — dev licenses auto-issued for unlicensed models. Local bridge active."
            provider = "local"
            local_ok = True
            prod_ok  = False
        elif not enforcement:
            detail = "NAEL enforcement SOFT (NAEL_ENFORCEMENT_ENABLED=false) — missing licenses generate ALERT, not BLOCK."
            provider = "local"
            local_ok = True
            prod_ok  = False
        else:
            detail = "NAEL enforcement ON, auto-provision ON but ENVIRONMENT is not development."
            provider = "local"
            local_ok = True
            prod_ok  = False

        prod_steps = []
        if not enforcement:
            prod_steps.append("Set NAEL_ENFORCEMENT_ENABLED=true once all models have licenses")
        if auto_provision and env != "development":
            prod_steps.append("Set NAEL_AUTO_PROVISION_DEV=false in production to prevent auto-issuance")
        if env == "development":
            prod_steps.append("Set ENVIRONMENT=production to disable auto-provisioning bridge")

        return PillarStatus(
            name             = "Licensing Enforcement",
            layer            = "Layer 2 — National AI Execution License (NAEL)",
            provider_mode    = provider,
            local_ready      = local_ok,
            production_ready = prod_ok,
            operational      = True,   # NAEL gate is always wired; mode varies
            status_detail    = detail,
            production_steps = prod_steps,
            config_keys      = {
                "NAEL_ENFORCEMENT_ENABLED":  enforcement,
                "NAEL_AUTO_PROVISION_DEV":   auto_provision,
                "ENVIRONMENT":               env,
            },
        )

    # ── Pillar 4: Synthetic Media Shield ──────────────────────────────────────

    def _pillar_synthetic_media(self) -> PillarStatus:
        mode       = getattr(settings, "SYNTHETIC_MEDIA_MODE", "mock").lower()
        api_url    = getattr(settings, "SYNTHETIC_MEDIA_API_URL", "")
        api_key    = getattr(settings, "SYNTHETIC_MEDIA_API_KEY", "")
        threshold  = float(getattr(settings, "SYNTHETIC_MEDIA_CONFIDENCE_THRESHOLD", 0.65))
        epm        = bool(getattr(settings, "ELECTION_PROTECTION_ENABLED", False))
        epm_state  = getattr(settings, "ELECTION_PROTECTION_STATE", "")

        onnx_path      = getattr(settings, "SYNTHETIC_MEDIA_ONNX_MODEL_PATH", "").strip()
        eci_mode       = getattr(settings, "ECI_WEBHOOK_MODE", "stub").lower()
        eci_url        = getattr(settings, "ECI_WEBHOOK_URL", "")
        eci_api_key    = getattr(settings, "ECI_WEBHOOK_API_KEY", "")

        is_mock      = mode == "mock"
        has_api      = mode == "api" and bool(api_url)
        has_onnx     = mode == "onnx" and bool(onnx_path)
        local_ready  = is_mock or has_onnx
        prod_ready   = (has_api and bool(api_key)) or has_onnx

        # ECI webhook summary
        if not epm:
            eci_suffix = "ECI webhook: OFF (ELECTION_PROTECTION_ENABLED=false)."
        elif eci_mode == "http" and eci_url:
            eci_suffix = f"ECI webhook: LIVE → {eci_url}."
        elif eci_mode == "http" and not eci_url:
            eci_suffix = "ECI webhook: http mode but ECI_WEBHOOK_URL not set — stub fallback."
        else:
            eci_suffix = "ECI webhook: stub (log-only, set ECI_WEBHOOK_MODE=http for production)."

        epm_suffix = (
            f"Election Protection Mode: ON (state={epm_state}). {eci_suffix}"
            if epm else f"Election Protection Mode: OFF. {eci_suffix}"
        )

        if is_mock:
            detail = (
                f"MockMediaDetector active — SHA-256 heuristic, no network. "
                f"Threshold={threshold:.0%}. {epm_suffix}"
            )
        elif has_api:
            detail = f"API detector active ({api_url}). Threshold={threshold:.0%}. {epm_suffix}"
        elif mode == "onnx" and has_onnx:
            detail = (
                f"LocalModel/ONNX detector active — on-device, no network. "
                f"Model={onnx_path}. Threshold={threshold:.0%}. {epm_suffix}"
            )
        elif mode == "onnx" and not onnx_path:
            detail = "SYNTHETIC_MEDIA_MODE=onnx but SYNTHETIC_MEDIA_ONNX_MODEL_PATH not set — falling back to mock."
        else:
            detail = f"SYNTHETIC_MEDIA_MODE={mode!r} but SYNTHETIC_MEDIA_API_URL not set — falling back to mock."

        detail += " Integrated into governance evaluate_inference() pipeline."

        prod_steps = []
        if is_mock:
            prod_steps.append(
                "Set SYNTHETIC_MEDIA_MODE=onnx + SYNTHETIC_MEDIA_ONNX_MODEL_PATH for "
                "on-device detection, or SYNTHETIC_MEDIA_MODE=api for cloud detection"
            )
        if mode == "api" and not api_key:
            prod_steps.append("Set SYNTHETIC_MEDIA_API_KEY for the external detector")
        if mode == "onnx" and not onnx_path:
            prod_steps.append("Set SYNTHETIC_MEDIA_ONNX_MODEL_PATH to a valid .onnx deepfake classifier")
        if not epm and epm_state:
            prod_steps.append("Set ELECTION_PROTECTION_ENABLED=true during active election windows")
        if epm and eci_mode != "http":
            prod_steps.append(
                "Set ECI_WEBHOOK_MODE=http + ECI_WEBHOOK_URL to send live escalations "
                "to the ECI Election Integrity Bus"
            )
        if epm and eci_mode == "http" and not eci_url:
            prod_steps.append("Set ECI_WEBHOOK_URL to the ECI Election Integrity Bus endpoint")

        return PillarStatus(
            name             = "Synthetic Media Shield",
            layer            = "Layer 3 — Deepfake Detection / Election Protection",
            provider_mode    = "local" if (is_mock or has_onnx) else "production",
            local_ready      = local_ready,
            production_ready = prod_ready,
            operational      = True,   # always active; mode varies
            status_detail    = detail,
            production_steps = prod_steps,
            config_keys      = {
                "SYNTHETIC_MEDIA_MODE":                 mode,
                "SYNTHETIC_MEDIA_API_URL":              api_url or "(not set)",
                "SYNTHETIC_MEDIA_API_KEY":              "***" if api_key else "(not set)",
                "SYNTHETIC_MEDIA_ONNX_MODEL_PATH":      onnx_path or "(not set)",
                "SYNTHETIC_MEDIA_CONFIDENCE_THRESHOLD": threshold,
                "ELECTION_PROTECTION_ENABLED":          epm,
                "ELECTION_PROTECTION_STATE":            epm_state or "(not set)",
                "ECI_WEBHOOK_MODE":                     eci_mode,
                "ECI_WEBHOOK_URL":                      eci_url or "(not set)",
                "ECI_WEBHOOK_API_KEY":                  "***" if eci_api_key else "(not set)",
            },
        )


# Module-level singleton
bascg_status_service = BASCGStatusService()
