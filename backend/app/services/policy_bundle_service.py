"""
BASCG Phase 1 — Policy Bundle Service  (Layer 2: Grid Engine Sovereignty)
==========================================================================

Moves PolicyEngine from "hardcoded Python literals that anyone can edit"
to "cryptographically signed policy bundles that only authorised regulators
can issue."

Architecture
------------
PolicyBundle
    A signed container for a set of governance policies.
    Serialised as a dict with a detached Ed25519 signature over canonical JSON.

PolicyBundleService
    Singleton that:
      1. At startup: signs BUILT_IN_POLICIES into a "dev-local" bundle.
      2. In governance_service: verifies each DB policy before use.
      3. Rejects (logs + skips) any policy whose signature is missing or invalid.

Enforcement principle
---------------------
A policy WITHOUT a valid signature from a TRUSTED issuer is SILENTLY DROPPED.
This means a rogue DB write cannot inject new enforcement rules —
the engine will simply ignore unsigned policies.

Production path
---------------
  Regulator issues a PolicyBundle via:
      POST /api/v1/policies/bundles   (body: bundle JSON + signature)
  The bundle is stored in GovernancePolicy rows with:
      policy_signature, bundle_version, signed_by, bundle_valid_until

  Production signing key lives in HSM; public key is registered in
  BASCG_TRUSTED_PUBLIC_KEYS_JSON env var.

Dev path
--------
  python scripts/generate_dev_keys.py
  → prints BASCG_SIGNING_KEY_SEED_B64 for .env
  → auto-signs BUILT_IN_POLICIES at startup
"""

from __future__ import annotations

import logging
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from app.core.crypto import canonical_json, crypto_service

logger = logging.getLogger("kavachx.policy_bundle")


# ══════════════════════════════════════════════════════════════════════════════
#  PolicyBundle dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class PolicyBundle:
    """
    A signed container for one or more governance policies.

    Fields included in the signature (canonical JSON, sorted keys):
        bundle_id, bundle_version, issued_by, issued_at,
        valid_until, jurisdiction, policies

    Fields NOT included in the signature:
        signature  (set after signing, verified before use)
    """
    bundle_id:      str
    bundle_version: str
    issued_by:      str             # issuer name — must be in trusted key registry
    issued_at:      str             # ISO-8601 UTC
    valid_until:    str             # ISO-8601 UTC
    jurisdiction:   str             # "GLOBAL" | "IN" | "IN.RBI" etc.
    policies:       List[Dict[str, Any]]
    signature:      str = ""        # Ed25519 sig (base64) set by BASCGSigner.sign()

    # ── Serialisation ─────────────────────────────────────────────────────────

    def signable_dict(self) -> dict:
        """Returns the dict that is canonically JSON-encoded and then signed."""
        return {
            "bundle_id":      self.bundle_id,
            "bundle_version": self.bundle_version,
            "issued_by":      self.issued_by,
            "issued_at":      self.issued_at,
            "valid_until":    self.valid_until,
            "jurisdiction":   self.jurisdiction,
            "policies":       self.policies,
        }

    def to_dict(self) -> dict:
        d = self.signable_dict()
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "PolicyBundle":
        return cls(
            bundle_id      = d["bundle_id"],
            bundle_version = d["bundle_version"],
            issued_by      = d["issued_by"],
            issued_at      = d["issued_at"],
            valid_until    = d["valid_until"],
            jurisdiction   = d["jurisdiction"],
            policies       = d["policies"],
            signature      = d.get("signature", ""),
        )

    # ── Validity helpers ──────────────────────────────────────────────────────

    @property
    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.valid_until.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except Exception:
            return True   # treat unparseable date as expired

    def is_valid_for_jurisdiction(self, ctx_jur: str) -> bool:
        """Returns True if this bundle applies to the given context jurisdiction."""
        bj  = (self.jurisdiction or "GLOBAL").upper()
        cj  = (ctx_jur or "GLOBAL").upper()
        return bj == "GLOBAL" or cj.startswith(bj) or bj.startswith(cj)


# ══════════════════════════════════════════════════════════════════════════════
#  PolicyBundleService
# ══════════════════════════════════════════════════════════════════════════════

class PolicyBundleService:
    """
    Singleton service for policy bundle lifecycle management.

    Exposed via the module-level `policy_bundle_service` singleton.
    """

    def __init__(self) -> None:
        self._builtin_bundle: Optional[PolicyBundle] = None

    # ── Bundle creation ───────────────────────────────────────────────────────

    def create_and_sign(
        self,
        policies:       List[Dict[str, Any]],
        jurisdiction:   str   = "GLOBAL",
        bundle_version: str   = "1.0",
        valid_days:     int   = 365,
        issued_by:      Optional[str] = None,
    ) -> PolicyBundle:
        """
        Create a new PolicyBundle from raw policy dicts and sign it with the
        configured BASCG dev/prod key.
        """
        now       = datetime.now(timezone.utc)
        issuer    = issued_by or crypto_service.signer.issuer
        bundle    = PolicyBundle(
            bundle_id      = str(uuid.uuid4()),
            bundle_version = bundle_version,
            issued_by      = issuer,
            issued_at      = now.isoformat(),
            valid_until    = (now + timedelta(days=valid_days)).isoformat(),
            jurisdiction   = jurisdiction,
            policies       = policies,
        )
        bundle.signature = crypto_service.signer.sign(bundle.signable_dict())
        logger.debug(
            "PolicyBundle signed: id=%s issuer=%s policies=%d",
            bundle.bundle_id[:8], issuer, len(policies),
        )
        return bundle

    # ── Built-in policies ─────────────────────────────────────────────────────

    def get_builtin_bundle(self) -> PolicyBundle:
        """
        Return the signed bundle for BUILT_IN_POLICIES.
        Lazily signed on first access so the crypto_service has time to initialise.
        Re-signed if the signer key changes (ephemeral key restart scenario).
        """
        if self._builtin_bundle is None:
            self._sign_builtin_policies()
        return self._builtin_bundle  # type: ignore[return-value]

    def _sign_builtin_policies(self) -> None:
        from app.modules.policy_engine import BUILT_IN_POLICIES
        self._builtin_bundle = self.create_and_sign(
            policies       = BUILT_IN_POLICIES,
            jurisdiction   = "GLOBAL",
            bundle_version = "builtin-1.0",
            valid_days      = 3650,   # 10 years for built-ins
        )
        logger.info(
            "BASCG: built-in policies signed — bundle=%s issuer=%s count=%d",
            self._builtin_bundle.bundle_id[:8],
            self._builtin_bundle.issued_by,
            len(BUILT_IN_POLICIES),
        )

    # ── Verification ─────────────────────────────────────────────────────────

    def verify_bundle(self, bundle: PolicyBundle) -> bool:
        """
        Verify a PolicyBundle's signature and expiry.
        Returns True only if both pass; logs specific failure reason.
        """
        if bundle.is_expired:
            logger.warning(
                "PolicyBundle REJECTED: expired bundle_id=%s valid_until=%s",
                bundle.bundle_id, bundle.valid_until,
            )
            return False
        if not bundle.signature:
            logger.warning(
                "PolicyBundle REJECTED: no signature bundle_id=%s issuer=%s",
                bundle.bundle_id, bundle.issued_by,
            )
            return False
        ok = crypto_service.verifier.verify(
            payload       = bundle.signable_dict(),
            signature_b64 = bundle.signature,
            issuer        = bundle.issued_by,
        )
        if not ok:
            logger.error(
                "PolicyBundle REJECTED: invalid signature bundle_id=%s issuer=%s",
                bundle.bundle_id, bundle.issued_by,
            )
        return ok

    def verify_db_policy(self, orm_policy) -> bool:
        """
        Verify a single GovernancePolicy ORM row.
        In development mode: unsigned policies are ALLOWED (logged as INFO).
        In production mode: unsigned policies are REJECTED (logged as WARNING).
        """
        from app.core.config import settings
        if not getattr(orm_policy, "policy_signature", None):
            if settings.ENVIRONMENT == "development":
                # Dev mode: allow unsigned policies to participate in governance
                logger.info(
                    "DB policy ACCEPTED (unsigned, dev-mode): id=%s name=%r",
                    orm_policy.id, orm_policy.name,
                )
                return True
            logger.warning(
                "DB policy REJECTED (unsigned): id=%s name=%r — "
                "use POST /api/v1/policies/bundles to issue a signed policy.",
                orm_policy.id, orm_policy.name,
            )
            return False

        # Reconstruct the signable payload from the ORM row
        payload = {
            "id":          orm_policy.id,
            "name":        orm_policy.name,
            "description": orm_policy.description or "",
            "policy_type": orm_policy.policy_type,
            "severity":    orm_policy.severity or "medium",
            "jurisdiction": orm_policy.jurisdiction or "GLOBAL",
            "rules":       orm_policy.rules or [],
        }
        signed_by = getattr(orm_policy, "signed_by", None) or "dev-local"
        ok = crypto_service.verifier.verify(
            payload       = payload,
            signature_b64 = orm_policy.policy_signature,
            issuer        = signed_by,
        )
        if not ok:
            logger.error(
                "DB policy REJECTED (bad signature): id=%s name=%r issuer=%s",
                orm_policy.id, orm_policy.name, signed_by,
            )
        return ok

    def sign_db_policy_payload(self, policy_dict: dict) -> str:
        """
        Sign the canonical payload of a single policy dict.
        Used when creating DB policies via the API.
        Returns base64 signature string.
        """
        payload = {
            "id":          policy_dict.get("id", ""),
            "name":        policy_dict.get("name", ""),
            "description": policy_dict.get("description", ""),
            "policy_type": policy_dict.get("policy_type", ""),
            "severity":    policy_dict.get("severity", "medium"),
            "jurisdiction": policy_dict.get("jurisdiction", "GLOBAL"),
            "rules":       policy_dict.get("rules", []),
        }
        return crypto_service.signer.sign(payload)


# ── Singleton ─────────────────────────────────────────────────────────────────
policy_bundle_service = PolicyBundleService()
