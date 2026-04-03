"""
BASCG Core Cryptographic Utilities
====================================

Shared Ed25519 signing/verification infrastructure used by:
  - PolicyBundleService  (Layer 2: signed policy enforcement)
  - NAELService          (Layer 2: execution licensing)
  - TEEAttestationService (Layer 1: hardware trust)

Key design:
  - One Ed25519 key seed (BASCG_SIGNING_KEY_SEED_B64) drives all local signing.
  - Production readiness: swap to HSM-backed KMS by replacing BASCGSigner.sign().
  - Verifier holds a registry of trusted issuer public keys; unknown issuers are rejected.

Ed25519 properties relevant to BASCG:
  - 64-byte deterministic signatures (no randomness, reproducible for audits)
  - 32-byte public keys (compact for embedding in NAEL tokens and policy bundles)
  - ~128-bit security level (exceeds IT Act requirements)
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
from dataclasses import dataclass, field
from typing import Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logger = logging.getLogger("kavachx.crypto")

# ── Issuer name for the local dev / CI key ────────────────────────────────────
DEV_ISSUER = "dev-local"


# ══════════════════════════════════════════════════════════════════════════════
#  Key loading helpers
# ══════════════════════════════════════════════════════════════════════════════

def load_private_key(seed_b64: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a base64-encoded 32-byte seed."""
    seed = base64.b64decode(seed_b64.encode("ascii"))
    if len(seed) != 32:
        raise ValueError(f"Ed25519 seed must be 32 bytes, got {len(seed)}")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_to_b64(private_key: Ed25519PrivateKey) -> str:
    """Return the base64-encoded 32-byte raw public key for a given private key."""
    raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def public_key_from_b64(pub_b64: str) -> Ed25519PublicKey:
    """Load an Ed25519PublicKey from a base64-encoded 32-byte raw key."""
    raw = base64.b64decode(pub_b64.encode("ascii"))
    return Ed25519PublicKey.from_public_bytes(raw)


def generate_seed_b64() -> str:
    """Generate a new random 32-byte seed, base64-encoded. Used by dev key script."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


# ══════════════════════════════════════════════════════════════════════════════
#  Canonical JSON  (deterministic, sort-keyed)
# ══════════════════════════════════════════════════════════════════════════════

def canonical_json(data: dict) -> bytes:
    """
    Produce a deterministic JSON byte string for signing.
    Keys are recursively sorted; no whitespace.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
#  Signer
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class BASCGSigner:
    """
    Signs arbitrary dicts with an Ed25519 private key.

    Production swap:
        Override sign() to call AWS KMS / Google Cloud KMS / PKCS#11 HSM.
        The public_key_b64 property must still return the corresponding public key.
    """
    issuer:       str
    _private_key: Ed25519PrivateKey = field(repr=False)

    def sign(self, payload: dict) -> str:
        """
        Sign the canonical JSON of *payload* and return the base64 signature.
        The payload must NOT contain a "signature" key (it will be added by callers).
        """
        msg = canonical_json(payload)
        sig = self._private_key.sign(msg)
        return base64.b64encode(sig).decode("ascii")

    @property
    def public_key_b64(self) -> str:
        return public_key_to_b64(self._private_key)


# ══════════════════════════════════════════════════════════════════════════════
#  Verifier
# ══════════════════════════════════════════════════════════════════════════════

class BASCGVerifier:
    """
    Verifies Ed25519 signatures from a registry of trusted issuers.

    Trusted keys are loaded from:
      1. The dev-local signer's public key (always registered at startup)
      2. BASCG_TRUSTED_PUBLIC_KEYS_JSON env var (production regulator keys)

    Unknown issuers are REJECTED — the enforcement principle of BASCG.
    """

    def __init__(self, trusted_keys: Dict[str, str]) -> None:
        """
        Args:
            trusted_keys: mapping of issuer_name → base64-encoded raw public key
        """
        self._keys: Dict[str, Ed25519PublicKey] = {}
        for issuer, pub_b64 in trusted_keys.items():
            try:
                self._keys[issuer] = public_key_from_b64(pub_b64)
                logger.debug("BASCGVerifier: loaded key for issuer=%s", issuer)
            except Exception as exc:
                logger.error("BASCGVerifier: failed to load key for issuer=%s: %s", issuer, exc)

    @property
    def trusted_issuers(self) -> list:
        return list(self._keys.keys())

    def add_trusted_key(self, issuer: str, pub_b64: str) -> None:
        """
        Register a new trusted issuer key at runtime (without restart).

        Args:
            issuer:  Human-readable issuer name, e.g. "MeitY-BASCG-v1"
            pub_b64: Base64-encoded 32-byte Ed25519 raw public key

        Raises:
            ValueError: if pub_b64 is not valid base64 or not 32 bytes
        """
        import base64 as _b64
        try:
            raw = _b64.b64decode(pub_b64)
        except Exception as exc:
            raise ValueError(f"pub_b64 is not valid base64: {exc}") from exc
        if len(raw) != 32:
            raise ValueError(
                f"Ed25519 public key must be 32 bytes, got {len(raw)}"
            )
        self._keys[issuer] = public_key_from_b64(pub_b64)
        logger.info("BASCGVerifier: trusted key added for issuer=%s", issuer)

    def remove_trusted_key(self, issuer: str) -> bool:
        """
        Remove a trusted issuer key at runtime.
        Returns True if the key existed and was removed, False otherwise.
        The dev-local key cannot be removed.
        """
        from app.core.crypto import DEV_ISSUER  # avoid circular at class level
        if issuer == DEV_ISSUER:
            logger.warning(
                "BASCGVerifier: cannot remove dev-local issuer key — ignored"
            )
            return False
        removed = self._keys.pop(issuer, None) is not None
        if removed:
            logger.info("BASCGVerifier: trusted key removed for issuer=%s", issuer)
        return removed

    def verify(self, payload: dict, signature_b64: str, issuer: str) -> bool:
        """
        Verify that *signature_b64* is a valid Ed25519 signature over the
        canonical JSON of *payload* by *issuer*.

        Returns False (does NOT raise) on any failure — callers decide response.
        """
        pub_key = self._keys.get(issuer)
        if pub_key is None:
            logger.warning("BASCGVerifier: unknown issuer=%r — REJECTED", issuer)
            return False
        try:
            sig   = base64.b64decode(signature_b64.encode("ascii"))
            msg   = canonical_json(payload)
            pub_key.verify(sig, msg)
            return True
        except InvalidSignature:
            logger.warning("BASCGVerifier: invalid signature for issuer=%s", issuer)
            return False
        except Exception as exc:
            logger.error("BASCGVerifier: verification error issuer=%s: %s", issuer, exc)
            return False


# ══════════════════════════════════════════════════════════════════════════════
#  Singleton factory  (initialised by CryptoService at app startup)
# ══════════════════════════════════════════════════════════════════════════════

class CryptoService:
    """
    Application-level singleton that initialises and exposes the signer/verifier.
    Called once from the FastAPI lifespan; all downstream services import the
    module-level `crypto_service` singleton.
    """

    def __init__(self) -> None:
        self._signer:   Optional[BASCGSigner]   = None
        self._verifier: Optional[BASCGVerifier] = None
        self._ready = False

    def initialize(self) -> None:
        """
        Load keys from settings and build signer + verifier.
        Must be called after settings are available (i.e., inside lifespan or import-time).
        """
        from app.core.config import settings

        # ── Signer ────────────────────────────────────────────────────────────
        seed_b64 = getattr(settings, "BASCG_SIGNING_KEY_SEED_B64", "").strip()
        if seed_b64:
            try:
                private_key = load_private_key(seed_b64)
                logger.info("BASCG CryptoService: loaded signing key from config")
            except Exception as exc:
                logger.error("BASCG CryptoService: bad BASCG_SIGNING_KEY_SEED_B64 — %s", exc)
                private_key = Ed25519PrivateKey.generate()
                logger.warning("BASCG CryptoService: falling back to ephemeral key")
        else:
            private_key = Ed25519PrivateKey.generate()
            logger.warning(
                "BASCG CryptoService: BASCG_SIGNING_KEY_SEED_B64 not set — "
                "using ephemeral key (run `python scripts/generate_dev_keys.py` to fix)"
            )

        self._signer = BASCGSigner(issuer=DEV_ISSUER, _private_key=private_key)

        # ── Verifier ──────────────────────────────────────────────────────────
        trusted: Dict[str, str] = {DEV_ISSUER: self._signer.public_key_b64}

        extra_json = getattr(settings, "BASCG_TRUSTED_PUBLIC_KEYS_JSON", "{}").strip()
        try:
            extra = json.loads(extra_json)
            trusted.update(extra)
            if extra:
                logger.info("BASCG CryptoService: loaded %d extra trusted keys", len(extra))
        except Exception as exc:
            logger.error("BASCG CryptoService: bad BASCG_TRUSTED_PUBLIC_KEYS_JSON — %s", exc)

        self._verifier = BASCGVerifier(trusted)
        self._ready    = True
        logger.info(
            "BASCG CryptoService ready — issuer=%s trusted=%s",
            DEV_ISSUER, self._verifier.trusted_issuers,
        )

    # ── Runtime regulator key management ─────────────────────────────────────

    def import_regulator_key(self, issuer: str, pub_b64: str) -> None:
        """
        Add a regulator public key to the live verifier at runtime.

        Validates the key, registers it with the verifier, and updates
        settings.BASCG_TRUSTED_PUBLIC_KEYS_JSON in-memory so the new issuer
        is immediately trusted for policy-bundle and NAEL-token verification.

        Persistence across restarts requires the operator to copy the returned
        trusted_keys_json value into their deployment environment, or the
        sidecar file bascg_regulator_keys.json is loaded at startup.

        Raises:
            ValueError: if issuer is empty, pub_b64 is invalid, or issuer
                        would shadow the dev-local signing key.
        """
        if not issuer or not issuer.strip():
            raise ValueError("issuer name must not be empty")

        issuer = issuer.strip()

        if not self._ready:
            self.initialize()

        # Guard: prevent shadowing the local signer issuer
        if issuer == DEV_ISSUER:
            raise ValueError(
                f"Cannot import key under reserved issuer name {DEV_ISSUER!r}. "
                "Use a distinct regulator name e.g. 'MeitY-BASCG-v1'."
            )

        # Delegate validation + registration to verifier
        self._verifier.add_trusted_key(issuer, pub_b64)  # raises ValueError on bad key

        # Mirror into settings so serialize/status calls see the live state
        import json
        from app.core.config import settings
        existing_json = getattr(settings, "BASCG_TRUSTED_PUBLIC_KEYS_JSON", "{}").strip()
        try:
            existing = json.loads(existing_json)
        except Exception:
            existing = {}
        existing[issuer] = pub_b64
        settings.BASCG_TRUSTED_PUBLIC_KEYS_JSON = json.dumps(existing)

        logger.info(
            "BASCG CryptoService: regulator key imported — issuer=%s "
            "trusted_count=%d", issuer, len(self._verifier.trusted_issuers)
        )

    def remove_regulator_key(self, issuer: str) -> bool:
        """
        Remove a regulator key from the live verifier.
        Returns True if the key existed and was removed.
        The dev-local key is protected and cannot be removed.
        """
        if not self._ready:
            self.initialize()

        removed = self._verifier.remove_trusted_key(issuer)
        if removed:
            import json
            from app.core.config import settings
            existing_json = getattr(settings, "BASCG_TRUSTED_PUBLIC_KEYS_JSON", "{}").strip()
            try:
                existing = json.loads(existing_json)
            except Exception:
                existing = {}
            existing.pop(issuer, None)
            settings.BASCG_TRUSTED_PUBLIC_KEYS_JSON = json.dumps(existing)

        return removed

    def list_trusted_keys(self) -> Dict[str, str]:
        """
        Return {issuer: public_key_b64} for all currently trusted issuers,
        including the local dev-signing key.
        """
        if not self._ready:
            self.initialize()

        result: Dict[str, str] = {}
        for issuer, pub_key in self._verifier._keys.items():
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            raw    = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            import base64 as _b64
            result[issuer] = _b64.b64encode(raw).decode("ascii")
        return result

    # ── Accessors (safe — initialize() lazily if not yet called) ─────────────

    @property
    def signer(self) -> BASCGSigner:
        if not self._ready:
            self.initialize()
        return self._signer  # type: ignore[return-value]

    @property
    def verifier(self) -> BASCGVerifier:
        if not self._ready:
            self.initialize()
        return self._verifier  # type: ignore[return-value]


# ── Module-level singleton ─────────────────────────────────────────────────────
crypto_service = CryptoService()
