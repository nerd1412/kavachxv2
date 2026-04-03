"""
BASCG Phase 1 — National AI Execution Licensing (NAEL)  (Layer 2: Grid Engine)
================================================================================

NAEL is the "Digital DNA" of a licensed AI system.  Every high-risk AI model
operating in Bharat must carry a NAEL token before executing on BASCG-certified
compute.  The token is:

  • Cryptographically signed by the BASCG issuing authority (Ed25519)
  • Bound to a specific model identity hash (prevents weight substitution)
  • Scoped to approved sectors (finance, healthcare, etc.)
  • Time-limited with a hard expiry
  • Optionally restricted to verified TEE platforms

Token structure (signed JSON):
    {
        "nael_version":          "1.0",
        "license_id":            "<uuid>",
        "model_id":              "<ai_models.id>",
        "model_sha256":          "<hex | null>",
        "sector_restrictions":   ["finance", "healthcare"],
        "risk_classification":   "HIGH",
        "licensed_tee_platforms": ["aws-nitro", "intel-sgx-dcap"],
        "issued_by":             "dev-local",
        "issued_at":             "<ISO-8601 UTC>",
        "valid_from":            "<ISO-8601 UTC>",
        "valid_until":           "<ISO-8601 UTC>",
        "iss":                   "https://nael.bascg.in",
        "signature":             "<Ed25519 base64>"
    }

Enforcement (NAEL_ENFORCEMENT_ENABLED=True in config):
    Missing license  → ALERT  (model runs, incident logged)
    Expired          → BLOCK
    Sector mismatch  → BLOCK
    Revoked          → BLOCK
    Invalid sig      → BLOCK

During the onboarding / migration period keep NAEL_ENFORCEMENT_ENABLED=False
so existing models continue running while licenses are being issued.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.crypto import canonical_json, crypto_service

logger = logging.getLogger("kavachx.nael")

NAEL_ISS = "https://nael.bascg.in"


# ══════════════════════════════════════════════════════════════════════════════
#  NAELToken dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class NAELToken:
    """In-memory representation of a deserialized NAEL token."""
    nael_version:           str
    license_id:             str
    model_id:               str
    model_sha256:           Optional[str]
    sector_restrictions:    List[str]
    risk_classification:    str              # LOW | MEDIUM | HIGH | PROHIBITED
    licensed_tee_platforms: List[str]
    issued_by:              str
    issued_at:              str
    valid_from:             str
    valid_until:            str
    iss:                    str
    signature:              str = ""

    # ── Serialisation ─────────────────────────────────────────────────────────

    def signable_dict(self) -> dict:
        return {
            "nael_version":           self.nael_version,
            "license_id":             self.license_id,
            "model_id":               self.model_id,
            "model_sha256":           self.model_sha256,
            "sector_restrictions":    sorted(self.sector_restrictions),
            "risk_classification":    self.risk_classification,
            "licensed_tee_platforms": sorted(self.licensed_tee_platforms),
            "issued_by":              self.issued_by,
            "issued_at":              self.issued_at,
            "valid_from":             self.valid_from,
            "valid_until":            self.valid_until,
            "iss":                    self.iss,
        }

    def to_json(self) -> str:
        d = self.signable_dict()
        d["signature"] = self.signature
        return json.dumps(d, sort_keys=True)

    @classmethod
    def from_json(cls, token_json: str) -> "NAELToken":
        d = json.loads(token_json)
        return cls(
            nael_version           = d["nael_version"],
            license_id             = d["license_id"],
            model_id               = d["model_id"],
            model_sha256           = d.get("model_sha256"),
            sector_restrictions    = d.get("sector_restrictions", []),
            risk_classification    = d.get("risk_classification", "MEDIUM"),
            licensed_tee_platforms = d.get("licensed_tee_platforms", []),
            issued_by              = d["issued_by"],
            issued_at              = d["issued_at"],
            valid_from             = d["valid_from"],
            valid_until            = d["valid_until"],
            iss                    = d.get("iss", NAEL_ISS),
            signature              = d.get("signature", ""),
        )

    # ── Validity helpers ──────────────────────────────────────────────────────

    @property
    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except Exception:
            return True

    @property
    def is_active(self) -> bool:
        try:
            start = datetime.fromisoformat(self.valid_from.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) >= start
        except Exception:
            return False

    def allows_sector(self, sector: Optional[str]) -> bool:
        """Returns True if no restrictions or sector is in allowed list."""
        if not self.sector_restrictions:
            return True
        if not sector:
            return True
        return sector.lower() in [s.lower() for s in self.sector_restrictions]

    def allows_tee(self, platform: Optional[str]) -> bool:
        """Returns True if no TEE restrictions or platform is in allowed list."""
        if not self.licensed_tee_platforms:
            return True
        if not platform:
            return True
        return platform.lower() in [p.lower() for p in self.licensed_tee_platforms]


# ══════════════════════════════════════════════════════════════════════════════
#  Validation result
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class NAELValidationResult:
    valid:     bool
    action:    str              # "pass" | "alert" | "block"
    reason:    str
    token:     Optional[NAELToken] = None
    license_id: Optional[str]  = None


# ══════════════════════════════════════════════════════════════════════════════
#  NAELService
# ══════════════════════════════════════════════════════════════════════════════

class NAELService:
    """
    Handles NAEL token lifecycle: issuance, storage, retrieval, and validation.
    """

    # ── Issuance ──────────────────────────────────────────────────────────────

    async def issue_license(
        self,
        db:                     AsyncSession,
        model_id:               str,
        sector_restrictions:    List[str]    = None,
        risk_classification:    str          = "MEDIUM",
        licensed_tee_platforms: List[str]    = None,
        model_sha256:           Optional[str] = None,
        valid_days:             int          = 365,
    ):
        """
        Issue a new NAEL license for the given model_id and store it in the DB.
        Returns the ORM NAELLicense row.
        """
        from app.models.orm_models import NAELLicense, AIModel

        # Verify model exists
        res = await db.execute(select(AIModel).where(AIModel.id == model_id))
        model = res.scalars().first()
        if not model:
            raise ValueError(f"AIModel {model_id!r} not found in registry")

        now        = datetime.now(timezone.utc)
        valid_from = now
        valid_until = now + timedelta(days=valid_days)
        issuer     = crypto_service.signer.issuer
        sectors    = sector_restrictions or []
        tee_plats  = licensed_tee_platforms or []
        lic_id     = str(uuid.uuid4())

        token = NAELToken(
            nael_version           = "1.0",
            license_id             = lic_id,
            model_id               = model_id,
            model_sha256           = model_sha256,
            sector_restrictions    = sectors,
            risk_classification    = risk_classification,
            licensed_tee_platforms = tee_plats,
            issued_by              = issuer,
            issued_at              = now.isoformat(),
            valid_from             = valid_from.isoformat(),
            valid_until            = valid_until.isoformat(),
            iss                    = NAEL_ISS,
        )
        token.signature = crypto_service.signer.sign(token.signable_dict())

        row = NAELLicense(
            id                     = lic_id,
            model_id               = model_id,
            model_sha256           = model_sha256,
            license_token          = token.to_json(),
            sector_restrictions    = sectors,
            risk_classification    = risk_classification,
            licensed_tee_platforms = tee_plats,
            issued_by              = issuer,
            issued_at              = now,
            valid_from             = valid_from,
            valid_until            = valid_until,
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)

        logger.info(
            "NAEL issued: license=%s model=%s risk=%s sectors=%s valid_until=%s",
            lic_id[:8], model_id[:8], risk_classification, sectors,
            valid_until.date().isoformat(),
        )
        return row

    # ── Revocation ────────────────────────────────────────────────────────────

    async def revoke_license(
        self, db: AsyncSession, license_id: str, reason: str = "manual revocation"
    ):
        from app.models.orm_models import NAELLicense
        res = await db.execute(select(NAELLicense).where(NAELLicense.id == license_id))
        lic = res.scalars().first()
        if not lic:
            raise ValueError(f"NAELLicense {license_id!r} not found")
        lic.revoked            = True
        lic.revocation_reason  = reason
        await db.commit()
        logger.warning("NAEL revoked: license=%s reason=%r", license_id[:8], reason)
        return lic

    # ── Validation ────────────────────────────────────────────────────────────

    async def validate_for_inference(
        self,
        db:        AsyncSession,
        model_id:  str,
        sector:    Optional[str] = None,
        tee_platform: Optional[str] = None,
    ) -> NAELValidationResult:
        """
        Core enforcement gate called by GovernanceService before each inference.
        Returns a NAELValidationResult with action "pass"|"alert"|"block".
        """
        from app.models.orm_models import NAELLicense

        enforcement = getattr(settings, "NAEL_ENFORCEMENT_ENABLED", False)

        # Fetch the most recent non-revoked license for this model
        res = await db.execute(
            select(NAELLicense)
            .where(NAELLicense.model_id == model_id)
            .where(NAELLicense.revoked.is_(False))
            .order_by(NAELLicense.valid_until.desc())
            .limit(1)
        )
        lic = res.scalars().first()

        # ── No license ────────────────────────────────────────────────────────
        if not lic:
            msg = f"No NAEL license found for model {model_id[:8]}…"
            logger.warning("NAEL: %s", msg)

            # ── BASCG Local Bridge: auto-provision a dev license ───────────────
            # When NAEL_AUTO_PROVISION_DEV=True and ENVIRONMENT=development,
            # automatically issue a scoped NAEL license instead of blocking.
            # This makes Pillar 3 (Licensing) live in local mode without manual setup.
            # Production: set NAEL_AUTO_PROVISION_DEV=False — no auto-issue.
            auto_provision = getattr(settings, "NAEL_AUTO_PROVISION_DEV", True)
            env = getattr(settings, "ENVIRONMENT", "development")
            if auto_provision and env == "development":
                try:
                    lic_row = await self.issue_license(
                        db=db,
                        model_id=model_id,
                        sector_restrictions=[sector] if sector else [],
                        risk_classification="MEDIUM",
                        licensed_tee_platforms=["mock"],
                        valid_days=365,
                    )
                    token = NAELToken.from_json(lic_row.license_token)
                    logger.info(
                        "NAEL auto-provisioned dev license=%s for model=%s",
                        lic_row.id[:8], model_id[:8],
                    )
                    return NAELValidationResult(
                        valid=True, action="pass",
                        reason=f"NAEL dev-license auto-provisioned (local mode, expires {token.valid_until[:10]})",
                        token=token, license_id=lic_row.id,
                    )
                except Exception as exc:
                    logger.warning("NAEL auto-provision failed: %s — falling through to alert", exc)

            action = "block" if enforcement else "alert"
            return NAELValidationResult(valid=False, action=action, reason=msg)

        # ── Parse and verify the token ─────────────────────────────────────
        try:
            token = NAELToken.from_json(lic.license_token)
        except Exception as exc:
            msg = f"NAEL token parse error: {exc}"
            logger.error("NAEL: %s", msg)
            return NAELValidationResult(valid=False, action="block", reason=msg, license_id=lic.id)

        # Signature check
        sig_ok = crypto_service.verifier.verify(
            payload       = token.signable_dict(),
            signature_b64 = token.signature,
            issuer        = token.issued_by,
        )
        if not sig_ok:
            msg = "NAEL token signature invalid"
            return NAELValidationResult(valid=False, action="block", reason=msg, license_id=lic.id)

        # Expiry
        if token.is_expired:
            msg = f"NAEL token expired: valid_until={token.valid_until}"
            return NAELValidationResult(valid=False, action="block", reason=msg,
                                        token=token, license_id=lic.id)

        # Not yet active
        if not token.is_active:
            msg = f"NAEL token not yet active: valid_from={token.valid_from}"
            return NAELValidationResult(valid=False, action="block", reason=msg,
                                        token=token, license_id=lic.id)

        # Sector check
        if sector and not token.allows_sector(sector):
            msg = (f"NAEL sector restriction: model not licensed for sector={sector!r}. "
                   f"Allowed: {token.sector_restrictions}")
            return NAELValidationResult(valid=False, action="block", reason=msg,
                                        token=token, license_id=lic.id)

        # TEE platform check
        if tee_platform and not token.allows_tee(tee_platform):
            msg = (f"NAEL TEE restriction: platform={tee_platform!r} not licensed. "
                   f"Allowed: {token.licensed_tee_platforms}")
            return NAELValidationResult(valid=False, action="block", reason=msg,
                                        token=token, license_id=lic.id)

        # Prohibited classification
        if token.risk_classification == "PROHIBITED":
            msg = "NAEL: model classified PROHIBITED — execution blocked"
            return NAELValidationResult(valid=False, action="block", reason=msg,
                                        token=token, license_id=lic.id)

        logger.debug(
            "NAEL valid: license=%s model=%s sector=%s risk=%s",
            lic.id[:8], model_id[:8], sector, token.risk_classification,
        )
        return NAELValidationResult(
            valid=True, action="pass",
            reason=f"NAEL license valid (expires {token.valid_until[:10]})",
            token=token, license_id=lic.id,
        )

    async def get_license_for_model(self, db: AsyncSession, model_id: str):
        """Return the latest active non-revoked license for a model, or None."""
        from app.models.orm_models import NAELLicense
        res = await db.execute(
            select(NAELLicense)
            .where(NAELLicense.model_id == model_id)
            .where(NAELLicense.revoked.is_(False))
            .order_by(NAELLicense.valid_until.desc())
            .limit(1)
        )
        return res.scalars().first()


# ── Singleton ─────────────────────────────────────────────────────────────────
nael_service = NAELService()
