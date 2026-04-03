#!/usr/bin/env python3
"""
BASCG Dev Key Generator
========================
Generates an Ed25519 keypair for local development and prints the
environment variables to add to your .env file.

Usage:
    python scripts/generate_dev_keys.py

Output (example):
    # Add to backend/.env
    BASCG_SIGNING_KEY_SEED_B64=<base64 32-byte seed>

    # Public key (for BASCG_TRUSTED_PUBLIC_KEYS_JSON on other nodes):
    dev-local: <base64 32-byte public key>

Security:
    - NEVER commit the seed to version control.
    - In production, use HSM-backed key management (AWS KMS / Google Cloud HSM).
    - The seed is 32 bytes of entropy — treat it like a database password.
"""

import base64
import sys
import os

# Allow running from project root or from scripts/ directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import secrets


def main():
    seed       = secrets.token_bytes(32)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    pub_raw    = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    seed_b64   = base64.b64encode(seed).decode("ascii")
    pub_b64    = base64.b64encode(pub_raw).decode("ascii")

    print("=" * 60)
    print("BASCG Dev Keypair — Add to backend/.env")
    print("=" * 60)
    print()
    print("# ── Signing key (KEEP SECRET) ──────────────────────────────")
    print(f"BASCG_SIGNING_KEY_SEED_B64={seed_b64}")
    print()
    print("# ── Public key (safe to share with other BASCG nodes) ──────")
    print(f'BASCG_TRUSTED_PUBLIC_KEYS_JSON={{"dev-local": "{pub_b64}"}}')
    print()
    print("=" * 60)
    print("WARNING: Never commit the SEED to version control.")
    print("Production: replace with HSM-backed key (AWS KMS / Cloud HSM)")
    print("=" * 60)


if __name__ == "__main__":
    main()
