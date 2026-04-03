"""
ECI Election Integrity Webhook Service
=======================================

Escalates synthetic media detections to the Election Commission of India's
Election Integrity Bus during active election windows.

Architecture
------------
  ECIWebhookService.escalate()
        │
        ├─ stub mode  → log-only, no network  (ECI_WEBHOOK_MODE=stub, default)
        └─ http mode  → sign payload + POST to ECI_WEBHOOK_URL

Payload structure
-----------------
  {
    "scan_id":        "<hex>",
    "state":          "MH",           # 2-letter state code from ELECTION_PROTECTION_STATE
    "confidence":     0.87,
    "labels":         [...],
    "evidence_hash":  "<sha256>",
    "detector":       "onnx:/path",
    "bascg_version":  "3.0",
    "issued_at":      "<iso8601>",
    "nonce":          "<hex8>"        # replay protection
  }

The payload is Ed25519-signed with the BASCG signing key before transmission.
The signature is sent in the `X-BASCG-Signature` header alongside the canonical
JSON body so the ECI receiver can verify the source.

Config
------
  ECI_WEBHOOK_URL               — full endpoint URL (required in http mode)
  ECI_WEBHOOK_API_KEY           — Bearer token added as `Authorization` header
  ECI_WEBHOOK_MODE              — "stub" (default) | "http"
  ECI_WEBHOOK_TIMEOUT_SECONDS   — per-request timeout  (default 10)

Legal basis
-----------
  ECI Model Code of Conduct, 2024 — Prohibition on synthetic political media
  IT Act S.66E — Privacy violation by dissemination of manipulated media
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger("bascg.eci_webhook")


# ══════════════════════════════════════════════════════════════════════════════
#  Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ECIEscalationResult:
    """Result of a single ECI escalation attempt."""
    scan_id:      str
    sent:         bool          # True if the HTTP POST was accepted (2xx)
    stub:         bool          # True when running in stub/local mode
    status_code:  Optional[int] = None   # HTTP status from ECI endpoint
    response_body: Optional[Any] = None  # parsed JSON or raw text
    signed_by:    Optional[str] = None   # issuer name of the signing key
    error:        Optional[str] = None   # exception message on failure


# ══════════════════════════════════════════════════════════════════════════════
#  ECIWebhookService
# ══════════════════════════════════════════════════════════════════════════════

class ECIWebhookService:
    """
    Escalates confirmed synthetic-media detections to the ECI Election Integrity Bus.

    Design: stateless — safe to call from any async context, no shared mutable state.
    """

    def _build_payload(
        self,
        scan_id:       str,
        state:         str,
        confidence:    float,
        labels:        List[str],
        evidence_hash: str,
        detector:      str,
    ) -> Dict[str, Any]:
        return {
            "scan_id":       scan_id,
            "state":         state,
            "confidence":    round(confidence, 4),
            "labels":        sorted(labels),
            "evidence_hash": evidence_hash,
            "detector":      detector,
            "bascg_version": "3.0",
            "issued_at":     datetime.now(timezone.utc).isoformat(),
            "nonce":         secrets.token_hex(8),
        }

    async def escalate(
        self,
        scan_id:       str,
        state:         str,
        confidence:    float,
        labels:        List[str],
        evidence_hash: str,
        detector:      str,
    ) -> ECIEscalationResult:
        """
        Send an escalation to the ECI Election Integrity Bus.

        In stub mode (default, dev/CI), logs the event and returns a stub result
        with ``sent=False, stub=True`` — no network access.

        In http mode, signs the payload with the BASCG Ed25519 key and POSTs it to
        ``ECI_WEBHOOK_URL``.  On any non-2xx response or network error, returns a
        result with ``sent=False`` and the error message populated.
        """
        mode    = getattr(settings, "ECI_WEBHOOK_MODE", "stub").lower()
        payload = self._build_payload(scan_id, state, confidence, labels,
                                      evidence_hash, detector)

        if mode != "http":
            logger.warning(
                "[ECI STUB] Escalation scan_id=%s state=%s confidence=%.2f labels=%s "
                "(set ECI_WEBHOOK_MODE=http + ECI_WEBHOOK_URL to send to live endpoint)",
                scan_id, state, confidence, labels,
            )
            return ECIEscalationResult(
                scan_id = scan_id,
                sent    = False,
                stub    = True,
            )

        return await self._post_to_eci(scan_id, payload)

    async def _post_to_eci(
        self,
        scan_id: str,
        payload: Dict[str, Any],
    ) -> ECIEscalationResult:
        """Sign and POST the escalation payload to ECI_WEBHOOK_URL."""
        import json as _json

        webhook_url = getattr(settings, "ECI_WEBHOOK_URL", "").strip()
        api_key     = getattr(settings, "ECI_WEBHOOK_API_KEY", "").strip()
        timeout     = int(getattr(settings, "ECI_WEBHOOK_TIMEOUT_SECONDS", 10))

        if not webhook_url:
            logger.error(
                "[ECI] ECI_WEBHOOK_MODE=http but ECI_WEBHOOK_URL is not set — "
                "cannot escalate scan_id=%s", scan_id,
            )
            return ECIEscalationResult(
                scan_id = scan_id,
                sent    = False,
                stub    = False,
                error   = "ECI_WEBHOOK_URL is not configured",
            )

        # Sign with BASCG Ed25519 key
        try:
            from app.core.crypto import crypto_service
            signature = crypto_service.signer.sign(payload)
            signed_by = crypto_service.signer.issuer
        except Exception as exc:
            logger.error("[ECI] Signing failed for scan_id=%s: %s", scan_id, exc)
            return ECIEscalationResult(
                scan_id = scan_id,
                sent    = False,
                stub    = False,
                error   = f"Signing failed: {exc}",
            )

        headers: Dict[str, str] = {
            "Content-Type":      "application/json",
            "X-BASCG-Signature": signature,
            "X-BASCG-Issuer":    signed_by,
        }
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        body = _json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(webhook_url, content=body, headers=headers)

            if resp.is_success:
                logger.info(
                    "[ECI] Escalation accepted — scan_id=%s status=%d",
                    scan_id, resp.status_code,
                )
                try:
                    resp_body = resp.json()
                except Exception:
                    resp_body = resp.text
                return ECIEscalationResult(
                    scan_id      = scan_id,
                    sent         = True,
                    stub         = False,
                    status_code  = resp.status_code,
                    response_body = resp_body,
                    signed_by    = signed_by,
                )
            else:
                logger.error(
                    "[ECI] Escalation rejected — scan_id=%s status=%d body=%.200s",
                    scan_id, resp.status_code, resp.text,
                )
                return ECIEscalationResult(
                    scan_id      = scan_id,
                    sent         = False,
                    stub         = False,
                    status_code  = resp.status_code,
                    signed_by    = signed_by,
                    error        = f"HTTP {resp.status_code}: {resp.text[:200]}",
                )

        except Exception as exc:
            logger.error(
                "[ECI] Network error escalating scan_id=%s: %s", scan_id, exc,
            )
            return ECIEscalationResult(
                scan_id   = scan_id,
                sent      = False,
                stub      = False,
                signed_by = signed_by if "signed_by" in dir() else None,
                error     = str(exc),
            )


# Module-level singleton
eci_webhook_service = ECIWebhookService()
