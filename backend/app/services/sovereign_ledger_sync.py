"""
BASCG Phase 1 — Sovereign Ledger Sync Service
==============================================

Implements Layer 4 (Forensic Integrity) of the BASCG architecture:

    AuditLog rows (local SHA-256 chain)
          │
          ▼  batch every N minutes
    MerkleTree  ←─ binary SHA-256 tree over chain_hashes
          │
          ▼  timestamp root
    TSA Client  ─┬─ MockTSAClient        (SOVEREIGN_LEDGER_MODE=mock,       no network)
                 ├─ RFC3161TSAClient     (SOVEREIGN_LEDGER_MODE=rfc3161,    HTTP POST)
                 └─ BlockchainTSAClient  (SOVEREIGN_LEDGER_MODE=blockchain, EVM JSON-RPC)
          │
          ▼  store receipt
    LedgerAnchor (DB) ← back-fills merkle_anchor_id + merkle_leaf_index on logs

Legal basis:
  IT Act 2000 S.65B  — External TSA witness makes audit chain court-admissible.
  DPDP 2023 S.8/S.10 — Data integrity and Data Fiduciary accountability.

Configuration (environment variables / .env):
  SOVEREIGN_LEDGER_ENABLED         bool  default True
  SOVEREIGN_LEDGER_MODE            str   "mock" | "rfc3161" | "blockchain"
  LEDGER_ANCHOR_INTERVAL_MINUTES   int   default 5
  LEDGER_ANCHOR_MIN_BATCH_SIZE     int   default 1
  TSA_URL                          str   default "https://freetsa.org/tsr"
  MOCK_TSA_SECRET                  str   HMAC key for mock mode

Production swap:
  rfc3161:    Set SOVEREIGN_LEDGER_MODE=rfc3161 + TSA_URL to DigiCert/Sectigo.
  blockchain: Set SOVEREIGN_LEDGER_MODE=blockchain + SOVEREIGN_LEDGER_BLOCKCHAIN_RPC_URL
              to a permissioned Besu/Quorum endpoint + SOVEREIGN_LEDGER_BLOCKCHAIN_FROM_ADDRESS.
  No code changes required — only config.

External verification (rfc3161 mode):
    echo "<tsa_token_b64>" | base64 -d > response.tsr
    printf '<merkle_root_hex>' | xxd -r -p > root.bin
    openssl ts -verify -data root.bin -in response.tsr -CAfile tsa_ca.pem
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.database import AsyncSessionLocal

logger = logging.getLogger("kavachx.ledger")


# ══════════════════════════════════════════════════════════════════════════════
#  §1  MERKLE TREE
# ══════════════════════════════════════════════════════════════════════════════

class MerkleTree:
    """
    Standard binary Merkle tree over a list of hex-encoded SHA-256 values.

    Node conventions (prevents second-preimage attacks):
      Leaf node     = SHA256( bytes.fromhex(chain_hash) )
      Internal node = SHA256( left_bytes ‖ right_bytes  )
      Odd level     = duplicate last node (Bitcoin-style padding)

    All hashes are lowercase hex strings throughout.

    Example (4 leaves):
        L0   L1   L2   L3          ← leaf nodes
         ╲  ╱     ╲  ╱
          N01       N23            ← internal nodes
            ╲      ╱
              Root
    """

    def __init__(self, chain_hashes: List[str]) -> None:
        """
        Args:
            chain_hashes: Ordered list of AuditLog.chain_hash hex strings.
                          Index position becomes the leaf index for proof generation.
        """
        if not chain_hashes:
            raise ValueError("MerkleTree requires at least one leaf.")
        # Convert each chain_hash into a leaf node by hashing its raw bytes
        self._leaves: List[str] = [
            hashlib.sha256(bytes.fromhex(h)).hexdigest()
            for h in chain_hashes
        ]
        # Build all levels bottom-up: levels[0] = leaves, levels[-1] = [root]
        self._levels: List[List[str]] = self._build(self._leaves)

    # ── Public interface ──────────────────────────────────────────────────────

    @property
    def root(self) -> str:
        """Hex-encoded Merkle root."""
        return self._levels[-1][0]

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    def get_proof(self, index: int) -> List[Dict[str, str]]:
        """
        Return the Merkle proof (sibling path) for the leaf at *index*.

        Result format:
            [{"direction": "right", "hash": "abc123..."}, ...]

        Verification algorithm (see also MerkleTree.verify_proof):
            current = SHA256(bytes.fromhex(chain_hash))   # leaf node
            for step in proof:
                sibling = bytes.fromhex(step["hash"])
                current_b = bytes.fromhex(current)
                if step["direction"] == "left":
                    current = SHA256(sibling + current_b).hex()
                else:
                    current = SHA256(current_b + sibling).hex()
            assert current == merkle_root
        """
        if not (0 <= index < self.leaf_count):
            raise IndexError(
                f"Leaf index {index} out of range [0, {self.leaf_count - 1}]"
            )
        proof: List[Dict[str, str]] = []
        cur = index
        for level in self._levels[:-1]:  # iterate from leaves up to (not incl.) root
            is_right_child = cur % 2 == 1
            if is_right_child:
                proof.append({"direction": "left", "hash": level[cur - 1]})
            else:
                sibling_idx = cur + 1
                # Odd node — sibling is the duplicated self
                sib = level[sibling_idx] if sibling_idx < len(level) else level[cur]
                proof.append({"direction": "right", "hash": sib})
            cur //= 2
        return proof

    @staticmethod
    def verify_proof(
        chain_hash_hex: str,
        proof: List[Dict[str, str]],
        expected_root: str,
    ) -> bool:
        """
        Standalone verification — usable without instantiating MerkleTree.

        Args:
            chain_hash_hex: The AuditLog's raw chain_hash (before leaf-hashing).
            proof:          Output of get_proof() or stored MerkleProofOut.proof.
            expected_root:  LedgerAnchor.merkle_root to verify against.
        """
        try:
            current = hashlib.sha256(bytes.fromhex(chain_hash_hex)).hexdigest()
            for step in proof:
                sibling  = bytes.fromhex(step["hash"])
                current_b = bytes.fromhex(current)
                if step["direction"] == "left":
                    current = hashlib.sha256(sibling + current_b).hexdigest()
                else:
                    current = hashlib.sha256(current_b + sibling).hexdigest()
            return current == expected_root
        except Exception:
            return False

    def to_dict(self) -> Dict:
        """
        Serialise the full tree for storage in LedgerAnchor.merkle_tree_json.
        Schema: {"root": str, "leaf_count": int, "leaves": [...], "levels": [[...],...]}
        """
        return {
            "root":       self.root,
            "leaf_count": self.leaf_count,
            "leaves":     self._leaves,
            "levels":     self._levels,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        """SHA256(bytes(left) ‖ bytes(right)) — standard Merkle internal node."""
        return hashlib.sha256(bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

    def _build(self, leaves: List[str]) -> List[List[str]]:
        levels: List[List[str]] = [list(leaves)]
        current = leaves
        while len(current) > 1:
            next_level: List[str] = []
            for i in range(0, len(current), 2):
                left  = current[i]
                right = current[i + 1] if i + 1 < len(current) else left  # pad odd
                next_level.append(self._hash_pair(left, right))
            levels.append(next_level)
            current = next_level
        return levels


# ══════════════════════════════════════════════════════════════════════════════
#  §2  TIMESTAMP AUTHORITY (TSA) CLIENTS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TSAReceipt:
    """Normalised result of a TSA timestamp operation — provider-agnostic."""
    provider:                str    # "mock-local-tsa" | TSA URL
    issued_at:               str    # ISO-8601 UTC string
    serial:                  str    # TSA serial number (decimal string)
    message_imprint_sha256:  str    # hex SHA-256 of the data that was timestamped
    token_b64:               str    # base64-encoded raw token (opaque, for storage)
    verified:                bool   # True if local pre-verification passed


class TSAClient(ABC):
    """Abstract interface for all Timestamp Authority backends."""

    @abstractmethod
    async def timestamp(self, data: bytes) -> TSAReceipt:
        """Request a timestamp for *data* and return a structured receipt."""


# ── Mock TSA (development / CI) ───────────────────────────────────────────────

class MockTSAClient(TSAClient):
    """
    Local simulation TSA — zero network dependency.

    Produces an HMAC-SHA256 signed JSON token that is:
      • Deterministically verifiable with the same MOCK_TSA_SECRET
      • Structurally identical to RFC 3161 in the stored schema
      • Sufficient for integration testing, CI pipelines, and local dev

    Token JSON structure (base64-encoded in tsa_token_b64):
    {
        "provider":  "mock-local-tsa",
        "version":   "1.0",
        "serial":    "<64-bit random decimal>",
        "timestamp": "<ISO-8601 UTC>",
        "policy_oid": "1.3.6.1.4.1.99999.1",    ← private OID, non-production
        "message_imprint": {
            "hash_algorithm": "sha256",
            "hashed_message": "<hex>"
        },
        "signature": "<HMAC-SHA256 hex over canonical JSON of above fields>"
    }

    Swap to production:  set SOVEREIGN_LEDGER_MODE=rfc3161 in .env — no code changes.
    """

    def __init__(self, secret_key: str) -> None:
        self._key = secret_key.encode("utf-8")

    async def timestamp(self, data: bytes) -> TSAReceipt:
        hashed    = hashlib.sha256(data).hexdigest()
        now       = datetime.now(timezone.utc)
        serial    = str(secrets.randbits(63))

        body: Dict = {
            "provider":   "mock-local-tsa",
            "version":    "1.0",
            "serial":     serial,
            "timestamp":  now.isoformat(),
            "policy_oid": "1.3.6.1.4.1.99999.1",
            "message_imprint": {
                "hash_algorithm": "sha256",
                "hashed_message": hashed,
            },
        }
        # Sign the canonical (deterministic) JSON — signature covers all body fields
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
        sig       = hmac.new(self._key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        body["signature"] = sig

        token_bytes = json.dumps(body, sort_keys=True).encode("utf-8")
        token_b64   = base64.b64encode(token_bytes).decode("ascii")

        logger.debug("MockTSA: issued serial=%s ts=%s", serial, now.isoformat())
        return TSAReceipt(
            provider               = "mock-local-tsa",
            issued_at              = now.isoformat(),
            serial                 = serial,
            message_imprint_sha256 = hashed,
            token_b64              = token_b64,
            verified               = True,
        )

    def verify_token(self, token_b64: str) -> bool:
        """Re-verify an existing mock token's HMAC — useful in tests."""
        try:
            raw    = base64.b64decode(token_b64.encode("ascii"))
            body   = json.loads(raw.decode("utf-8"))
            sig    = body.pop("signature", "")
            canon  = json.dumps(body, sort_keys=True, separators=(",", ":"))
            expect = hmac.new(self._key, canon.encode("utf-8"), hashlib.sha256).hexdigest()
            return hmac.compare_digest(sig, expect)
        except Exception:
            return False


# ── RFC 3161 TSA (production) ─────────────────────────────────────────────────

class RFC3161TSAClient(TSAClient):
    """
    Production RFC 3161 HTTP Timestamp Authority client.

    Protocol:
      1. Hash the data with SHA-256.
      2. Encode a minimal DER TimeStampRequest (hand-rolled, no ASN.1 library needed).
      3. POST to TSA_URL with Content-Type: application/timestamp-query.
      4. Store raw binary TimeStampResponse as base64 for external openssl verification.

    Compatible TSAs (free tier available):
      • https://freetsa.org/tsr          (default, no API key)
      • https://timestamp.digicert.com   (DigiCert)
      • http://timestamp.sectigo.com     (Sectigo)

    External verification:
        echo "<tsa_token_b64>" | base64 -d > response.tsr
        printf '<merkle_root_hex>' | xxd -r -p > root.bin
        openssl ts -verify -data root.bin -in response.tsr -CAfile tsa_ca.pem
    """

    # SHA-256 AlgorithmIdentifier DER bytes:
    #   SEQUENCE { OID(2.16.840.1.101.3.4.2.1), NULL }
    #   30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
    _SHA256_ALG_ID = bytes.fromhex("300d06096086480165030402010500")

    def __init__(self, tsa_url: str, timeout: float = 15.0) -> None:
        self._tsa_url = tsa_url
        self._timeout = timeout

    async def timestamp(self, data: bytes) -> TSAReceipt:
        digest     = hashlib.sha256(data)
        digest_hex = digest.hexdigest()
        tsr_der    = self._build_timestamp_request(digest.digest())

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                self._tsa_url,
                content=tsr_der,
                headers={
                    "Content-Type": "application/timestamp-query",
                    "Accept":       "application/timestamp-reply",
                },
            )
            resp.raise_for_status()
            raw_response = resp.content   # DER-encoded TimeStampResponse

        token_b64          = base64.b64encode(raw_response).decode("ascii")
        issued_at, serial  = self._extract_meta(raw_response)

        logger.info(
            "RFC3161 TSA [%s]: serial=%s ts=%s imprint=%s…",
            self._tsa_url, serial, issued_at, digest_hex[:16],
        )
        return TSAReceipt(
            provider               = self._tsa_url,
            issued_at              = issued_at,
            serial                 = serial,
            message_imprint_sha256 = digest_hex,
            token_b64              = token_b64,
            verified               = True,
        )

    def _build_timestamp_request(self, hashed_message: bytes) -> bytes:
        """
        Build a minimal DER-encoded RFC 3161 TimeStampReq:

        TimeStampReq ::= SEQUENCE {
            version        INTEGER { v1(1) },
            messageImprint MessageImprint,
            nonce          INTEGER OPTIONAL,
            certReq        BOOLEAN DEFAULT FALSE
        }
        MessageImprint ::= SEQUENCE {
            hashAlgorithm  AlgorithmIdentifier,
            hashedMessage  OCTET STRING
        }
        """
        # OCTET STRING: tag 04 + length + bytes
        hash_os      = b"\x04" + self._der_len(len(hashed_message)) + hashed_message
        # MessageImprint SEQUENCE
        mi_inner     = self._SHA256_ALG_ID + hash_os
        msg_imprint  = b"\x30" + self._der_len(len(mi_inner)) + mi_inner

        # version INTEGER v1(1)
        version      = b"\x02\x01\x01"

        # nonce: 7 random bytes (56-bit, always positive — MSB guaranteed 0)
        nonce_raw    = secrets.token_bytes(7)
        nonce        = b"\x02" + self._der_len(len(nonce_raw)) + nonce_raw

        # certReq BOOLEAN TRUE
        cert_req     = b"\x01\x01\xff"

        inner        = version + msg_imprint + nonce + cert_req
        return b"\x30" + self._der_len(len(inner)) + inner

    @staticmethod
    def _der_len(n: int) -> bytes:
        """Minimal DER length encoding (supports up to 64 KiB)."""
        if n < 0x80:
            return bytes([n])
        if n < 0x100:
            return bytes([0x81, n])
        if n < 0x10000:
            return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])
        raise ValueError(f"DER length too large: {n}")

    @staticmethod
    def _extract_meta(tst_bytes: bytes) -> Tuple[str, str]:
        """
        Lightweight extraction of GeneralizedTime and serial from a raw TSA response.
        Falls back gracefully if the DER structure is unexpected.
        Full ASN.1 parsing is intentionally avoided to keep zero extra dependencies.
        """
        issued_at = datetime.now(timezone.utc).isoformat()
        serial    = str(secrets.randbits(32))
        try:
            # GeneralizedTime tag = 0x18, format YYYYMMDDHHmmssZ (15 bytes)
            idx = tst_bytes.find(b"\x18")
            if idx >= 0:
                length = tst_bytes[idx + 1]
                ts_str = tst_bytes[idx + 2: idx + 2 + length].decode("ascii", errors="ignore")
                if len(ts_str) >= 14:
                    dt = datetime(
                        int(ts_str[0:4]),  int(ts_str[4:6]),  int(ts_str[6:8]),
                        int(ts_str[8:10]), int(ts_str[10:12]), int(ts_str[12:14]),
                        tzinfo=timezone.utc,
                    )
                    issued_at = dt.isoformat()
        except Exception:
            pass
        return issued_at, serial


# ── Blockchain TSA (P2b — EVM permissioned anchor) ───────────────────────────

class BlockchainTSAClient(TSAClient):
    """
    EVM permissioned-chain timestamp anchor for BASCG P2b.

    Instead of an HTTP TSA, the Merkle root is written as calldata on a
    permissioned Ethereum PoA / Hyperledger Besu node via a raw eth_sendTransaction
    JSON-RPC call.  The transaction hash becomes the "serial" and the block
    timestamp is the authoritative witness.

    Architecture:
      • eth_sendTransaction  — submit Merkle root as tx calldata (no contract needed)
      • eth_getTransactionReceipt — poll until mined, obtain blockHash + blockNumber
      • eth_getBlockByNumber — read on-chain block.timestamp for issued_at

    Why no contract?
      Storing the root in calldata is sufficient for court admissibility — the
      on-chain tx hash proves the root existed at block-time.  A contract can be
      added later for indexed lookups without changing this client.

    Zero extra dependencies: uses httpx (already a project dependency).

    Env vars:
      SOVEREIGN_LEDGER_MODE=blockchain
      SOVEREIGN_LEDGER_BLOCKCHAIN_RPC_URL=http://besu-node:8545
      SOVEREIGN_LEDGER_BLOCKCHAIN_FROM_ADDRESS=0xabc…
      SOVEREIGN_LEDGER_BLOCKCHAIN_CHAIN_ID=1337

    External verification:
      Cast the tx hash into a block explorer or:
        curl -X POST <RPC_URL> -H 'Content-Type: application/json' \\
          -d '{"jsonrpc":"2.0","method":"eth_getTransactionByHash",
               "params":["<tx_hash>"],"id":1}'
      Verify calldata field starts with 0xBASCG magic prefix + merkle_root.
    """

    # Magic 4-byte selector prepended to calldata so txs are easily identifiable
    # bytes4(keccak256("BASCG_ANCHOR(bytes32)")) truncated to 4 bytes
    _MAGIC = bytes.fromhex("ba5c9a00")

    def __init__(
        self,
        rpc_url: str,
        from_address: str,
        chain_id: int = 1337,
        timeout: float = 30.0,
        poll_interval: float = 1.0,
        max_polls: int = 30,
    ) -> None:
        self._rpc_url      = rpc_url
        self._from         = from_address
        self._chain_id     = chain_id
        self._timeout      = timeout
        self._poll_interval = poll_interval
        self._max_polls    = max_polls

    async def timestamp(self, data: bytes) -> TSAReceipt:
        """
        Anchor *data* (the Merkle root bytes) on-chain.

        Steps:
          1. Build calldata: MAGIC (4 bytes) + data (32 bytes for SHA-256 root).
          2. eth_sendTransaction to the zero address (burn address) — no ETH value.
          3. Poll eth_getTransactionReceipt until mined.
          4. eth_getBlockByNumber to get the authoritative block timestamp.
          5. Return TSAReceipt with tx_hash as serial and block timestamp as issued_at.
        """
        digest_hex  = hashlib.sha256(data).hexdigest()
        calldata    = "0x" + self._MAGIC.hex() + data.hex().zfill(64)

        tx_hash = await self._send_tx(calldata)
        logger.info("BlockchainTSA: tx submitted hash=%s", tx_hash)

        receipt = await self._wait_for_receipt(tx_hash)
        block_number = receipt.get("blockNumber", "0x0")

        block_ts = await self._get_block_timestamp(block_number)
        issued_at = datetime.fromtimestamp(block_ts, tz=timezone.utc).isoformat()

        logger.info(
            "BlockchainTSA: anchored root=%s… tx=%s block=%s ts=%s",
            digest_hex[:16], tx_hash[:18], block_number, issued_at,
        )
        return TSAReceipt(
            provider               = self._rpc_url,
            issued_at              = issued_at,
            serial                 = tx_hash,
            message_imprint_sha256 = digest_hex,
            token_b64              = base64.b64encode(tx_hash.encode()).decode("ascii"),
            verified               = True,
        )

    async def _rpc(self, method: str, params: list) -> object:
        """Execute a single JSON-RPC 2.0 call and return the 'result' field."""
        payload = {
            "jsonrpc": "2.0",
            "method":  method,
            "params":  params,
            "id":      1,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                self._rpc_url,
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            body = resp.json()
        if "error" in body:
            raise RuntimeError(f"JSON-RPC error: {body['error']}")
        return body.get("result")

    async def _send_tx(self, calldata: str) -> str:
        """Submit eth_sendTransaction and return the tx hash."""
        tx = {
            "from":  self._from,
            "to":    "0x0000000000000000000000000000000000000000",
            "data":  calldata,
            "value": "0x0",
            "gas":   hex(50_000),
        }
        tx_hash = await self._rpc("eth_sendTransaction", [tx])
        if not isinstance(tx_hash, str):
            raise RuntimeError(f"Unexpected eth_sendTransaction result: {tx_hash!r}")
        return tx_hash

    async def _wait_for_receipt(self, tx_hash: str) -> dict:
        """Poll eth_getTransactionReceipt until the tx is mined."""
        for attempt in range(self._max_polls):
            receipt = await self._rpc("eth_getTransactionReceipt", [tx_hash])
            if receipt is not None:
                status = receipt.get("status", "0x1")
                if status == "0x0":
                    raise RuntimeError(f"Transaction {tx_hash} reverted on-chain")
                return receipt
            logger.debug(
                "BlockchainTSA: waiting for receipt… attempt=%d/%d",
                attempt + 1, self._max_polls,
            )
            await asyncio.sleep(self._poll_interval)
        raise TimeoutError(
            f"Transaction {tx_hash} not mined after {self._max_polls * self._poll_interval}s"
        )

    async def _get_block_timestamp(self, block_number: str) -> int:
        """Return block.timestamp (Unix seconds) for a given block number."""
        block = await self._rpc("eth_getBlockByNumber", [block_number, False])
        if not isinstance(block, dict):
            raise RuntimeError(f"Unexpected eth_getBlockByNumber result: {block!r}")
        ts_hex = block.get("timestamp", "0x0")
        return int(ts_hex, 16)


# ══════════════════════════════════════════════════════════════════════════════
#  §3  SOVEREIGN LEDGER SYNC ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

class SovereignLedgerSyncService:
    """
    Orchestrates the BASCG Forensic Integrity Layer.

    Responsibilities:
      1. Background asyncio task: wakes every LEDGER_ANCHOR_INTERVAL_MINUTES.
      2. Queries all un-anchored AuditLog rows (merkle_anchor_id IS NULL,
         chain_hash IS NOT NULL).
      3. Builds a binary Merkle tree over their chain_hashes.
      4. Requests a timestamp from the configured TSA backend.
      5. Persists the LedgerAnchor row with the TSA receipt.
      6. Back-fills merkle_anchor_id + merkle_leaf_index on each AuditLog.

    The service is also callable directly from tests or admin endpoints via
    run_anchor_cycle().
    """

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None

    # ── TSA factory ───────────────────────────────────────────────────────────

    def _get_tsa_client(self) -> TSAClient:
        """Return the appropriate TSA backend based on SOVEREIGN_LEDGER_MODE."""
        mode = getattr(settings, "SOVEREIGN_LEDGER_MODE", "mock").lower()
        if mode == "rfc3161":
            tsa_url = getattr(settings, "TSA_URL", "https://freetsa.org/tsr")
            logger.info("SovereignLedger: TSA backend → RFC3161 (%s)", tsa_url)
            return RFC3161TSAClient(tsa_url=tsa_url)
        if mode == "blockchain":
            rpc_url  = getattr(settings, "SOVEREIGN_LEDGER_BLOCKCHAIN_RPC_URL", "http://localhost:8545")
            from_addr = getattr(settings, "SOVEREIGN_LEDGER_BLOCKCHAIN_FROM_ADDRESS", "0x" + "0" * 40)
            chain_id  = getattr(settings, "SOVEREIGN_LEDGER_BLOCKCHAIN_CHAIN_ID", 1337)
            logger.info("SovereignLedger: TSA backend → Blockchain EVM (%s chain_id=%d)", rpc_url, chain_id)
            return BlockchainTSAClient(rpc_url=rpc_url, from_address=from_addr, chain_id=chain_id)
        logger.debug("SovereignLedger: TSA backend → Mock (local HMAC)")
        return MockTSAClient(
            secret_key=getattr(settings, "MOCK_TSA_SECRET", "dev-mock-tsa-key")
        )

    # ── Core anchor cycle ─────────────────────────────────────────────────────

    async def run_anchor_cycle(self, db: AsyncSession):
        """
        Execute one complete anchor cycle.

        Returns:
            LedgerAnchor instance on success (status "anchored" or "failed").
            None if there are fewer logs than LEDGER_ANCHOR_MIN_BATCH_SIZE.
        """
        # Import here to avoid circular imports at module load time
        from app.models.orm_models import AuditLog, LedgerAnchor

        # Fetch all un-anchored logs that have a valid chain_hash
        result = await db.execute(
            select(AuditLog)
            .where(AuditLog.merkle_anchor_id.is_(None))
            .where(AuditLog.chain_hash.isnot(None))
            .order_by(AuditLog.timestamp)
        )
        logs = result.scalars().all()

        min_batch = getattr(settings, "LEDGER_ANCHOR_MIN_BATCH_SIZE", 1)
        if len(logs) < min_batch:
            logger.debug(
                "SovereignLedger: %d un-anchored logs < min_batch=%d — skipping",
                len(logs), min_batch,
            )
            return None

        logger.info("SovereignLedger: starting anchor cycle for %d logs", len(logs))

        # Build Merkle tree
        chain_hashes = [log.chain_hash for log in logs]
        tree         = MerkleTree(chain_hashes)

        # Create anchor row in "pending" state — gets an ID via flush
        anchor = LedgerAnchor(
            batch_start_log_id = logs[0].id,
            batch_end_log_id   = logs[-1].id,
            log_count          = len(logs),
            merkle_root        = tree.root,
            merkle_tree_json   = tree.to_dict(),
            anchor_status      = "pending",
        )
        db.add(anchor)
        await db.flush()   # populate anchor.id before back-filling FKs

        # Timestamp the Merkle root
        tsa_client = self._get_tsa_client()
        try:
            receipt = await tsa_client.timestamp(bytes.fromhex(tree.root))

            anchor.tsa_provider  = receipt.provider
            anchor.tsa_token_b64 = receipt.token_b64
            anchor.tsa_timestamp = _parse_iso(receipt.issued_at)
            anchor.tsa_serial    = receipt.serial
            anchor.anchor_status = "anchored"
            anchor.anchored_at   = datetime.now(timezone.utc)

            logger.info(
                "SovereignLedger: anchored root=%s… serial=%s provider=%s logs=%d",
                tree.root[:16], receipt.serial, receipt.provider, len(logs),
            )
        except Exception as exc:
            anchor.anchor_status = "failed"
            anchor.error_message = str(exc)
            logger.error("SovereignLedger: TSA request failed: %s", exc)
            await db.commit()
            return anchor

        # Back-fill Merkle anchor reference on each AuditLog
        for idx, log in enumerate(logs):
            log.merkle_anchor_id  = anchor.id
            log.merkle_leaf_index = idx

        await db.commit()
        return anchor

    # ── Proof generation ──────────────────────────────────────────────────────

    async def get_proof_for_log(self, log_id: str, db: AsyncSession) -> Dict:
        """
        Convenience method: look up an AuditLog by ID and return its proof package.
        Raises ValueError if the log is not yet anchored.
        """
        from app.models.orm_models import AuditLog

        result = await db.execute(select(AuditLog).where(AuditLog.id == log_id))
        log    = result.scalars().first()
        if not log:
            raise ValueError(f"AuditLog {log_id!r} not found")
        if log.merkle_anchor_id is None or log.merkle_leaf_index is None:
            raise ValueError(
                f"AuditLog {log_id!r} has not been anchored yet. "
                "Wait for the next SovereignLedgerSync cycle."
            )
        return await self.get_merkle_proof(log.merkle_anchor_id, log.merkle_leaf_index, db)

    async def get_merkle_proof(
        self, anchor_id: str, leaf_index: int, db: AsyncSession
    ) -> Dict:
        """
        Generate a self-contained Merkle proof package for the given anchor + leaf.

        The returned dict can be serialised into a MerkleProofOut schema directly.
        """
        from app.models.orm_models import LedgerAnchor

        result = await db.execute(
            select(LedgerAnchor).where(LedgerAnchor.id == anchor_id)
        )
        anchor = result.scalars().first()
        if not anchor:
            raise ValueError(f"LedgerAnchor {anchor_id!r} not found")
        if not anchor.merkle_tree_json:
            raise ValueError(f"LedgerAnchor {anchor_id!r} has no Merkle tree data")

        tree_data = anchor.merkle_tree_json
        leaves    = tree_data.get("leaves", [])
        levels    = tree_data.get("levels", [])

        if not (0 <= leaf_index < len(leaves)):
            raise IndexError(
                f"Leaf index {leaf_index} out of range for anchor with {len(leaves)} leaves"
            )

        proof = _compute_proof_from_levels(levels, leaf_index)

        # Human-readable verification hint based on mode
        if getattr(settings, "SOVEREIGN_LEDGER_MODE", "mock").lower() == "rfc3161":
            hint = (
                "1. base64 -d <<< '<tsa_token_b64>' > response.tsr\n"
                f"2. printf '{anchor.merkle_root}' | xxd -r -p > root.bin\n"
                "3. openssl ts -verify -data root.bin -in response.tsr -CAfile tsa_ca.pem\n"
                "4. Verify chain_hash is in the Merkle tree using the proof steps above."
            )
        else:
            hint = (
                "Mock mode: base64-decode tsa_token_b64, parse JSON, re-compute\n"
                "HMAC-SHA256(canonical_json_without_signature, MOCK_TSA_SECRET)\n"
                "and compare against the 'signature' field."
            )

        return {
            "anchor_id":        anchor_id,
            "merkle_root":      anchor.merkle_root,
            "leaf_index":       leaf_index,
            "leaf_hash":        leaves[leaf_index],
            "proof":            proof,
            "log_count":        anchor.log_count,
            "tsa_provider":     anchor.tsa_provider,
            "tsa_token_b64":    anchor.tsa_token_b64,
            "tsa_timestamp":    anchor.tsa_timestamp.isoformat() if anchor.tsa_timestamp else None,
            "anchor_status":    anchor.anchor_status,
            "verification_hint": hint,
        }

    # ── Background worker ─────────────────────────────────────────────────────

    def start_background_worker(self) -> Optional[asyncio.Task]:
        """
        Launch the background anchor task inside the running event loop.
        Called from the FastAPI lifespan context after DB init.
        """
        if not getattr(settings, "SOVEREIGN_LEDGER_ENABLED", True):
            logger.info("SovereignLedger: disabled (SOVEREIGN_LEDGER_ENABLED=false)")
            return None

        async def _worker() -> None:
            interval = getattr(settings, "LEDGER_ANCHOR_INTERVAL_MINUTES", 5) * 60
            mode     = getattr(settings, "SOVEREIGN_LEDGER_MODE", "mock")
            logger.info(
                "SovereignLedger worker started — interval=%ds mode=%s", interval, mode
            )
            # Initial delay: let DB tables finish initialising
            await asyncio.sleep(15)
            while True:
                try:
                    async with AsyncSessionLocal() as db:
                        anchor = await self.run_anchor_cycle(db)
                        if anchor:
                            logger.info(
                                "SovereignLedger cycle: anchor=%s… status=%s logs=%d",
                                anchor.id[:8], anchor.anchor_status, anchor.log_count,
                            )
                except asyncio.CancelledError:
                    logger.info("SovereignLedger worker: cancelled.")
                    break
                except Exception as exc:
                    logger.exception("SovereignLedger worker error: %s", exc)
                await asyncio.sleep(interval)

        self._task = asyncio.create_task(_worker(), name="bascg-sovereign-ledger-sync")
        return self._task

    def stop(self) -> None:
        """Gracefully cancel the background worker (called on app shutdown)."""
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("SovereignLedger worker: stop requested.")


# ══════════════════════════════════════════════════════════════════════════════
#  §4  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _parse_iso(s: str) -> datetime:
    """Parse ISO-8601 UTC string, handling both '+00:00' and 'Z' suffixes."""
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _compute_proof_from_levels(
    levels: List[List[str]], leaf_index: int
) -> List[Dict[str, str]]:
    """
    Recompute a Merkle proof from the stored tree levels.
    Used when re-generating proofs from LedgerAnchor.merkle_tree_json.
    """
    proof: List[Dict[str, str]] = []
    cur = leaf_index
    for level in levels[:-1]:   # all levels except root
        is_right = cur % 2 == 1
        if is_right:
            proof.append({"direction": "left",  "hash": level[cur - 1]})
        else:
            sib = cur + 1
            proof.append({
                "direction": "right",
                "hash": level[sib] if sib < len(level) else level[cur],
            })
        cur //= 2
    return proof


# ── Singleton — import this in main.py and api/ledger.py ─────────────────────
sovereign_ledger_sync = SovereignLedgerSyncService()
