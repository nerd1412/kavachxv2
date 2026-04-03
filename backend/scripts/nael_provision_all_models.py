#!/usr/bin/env python3
"""
BASCG NAEL Pre-flight Provisioner
===================================
Issues NAEL licenses for every registered AIModel that does not yet have a
valid (non-revoked, non-expired) license.

Run this BEFORE flipping NAEL_ENFORCEMENT_ENABLED=true in production to ensure
no model is blocked on first inference after enforcement goes live.

Usage
-----
  # Dry run — show what would be issued without touching the DB
  python scripts/nael_provision_all_models.py --dry-run

  # Provision all unlicensed models (default: 365-day validity, risk from model record)
  python scripts/nael_provision_all_models.py

  # Override validity window and risk class for all issued licenses
  python scripts/nael_provision_all_models.py --valid-days 730 --risk-class HIGH

  # Re-issue even for models that already have a valid license (rotate licenses)
  python scripts/nael_provision_all_models.py --force

  # Filter to a single model
  python scripts/nael_provision_all_models.py --model-id <uuid>

Exit codes
----------
  0  All models are licensed (or --dry-run completed successfully)
  1  One or more models could not be licensed (see ERROR lines above)
  2  No models found in registry
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone
from typing import List, Optional

# ── path bootstrap — works when run from project root OR scripts/ ─────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── result dataclass ──────────────────────────────────────────────────────────

class ProvisionResult:
    __slots__ = ("model_id", "model_name", "status", "license_id", "error")

    STATUS_ISSUED   = "ISSUED"
    STATUS_SKIPPED  = "SKIPPED"   # already has a valid license
    STATUS_DRY_RUN  = "DRY_RUN"
    STATUS_ERROR    = "ERROR"

    def __init__(
        self,
        model_id:   str,
        model_name: str,
        status:     str,
        license_id: Optional[str] = None,
        error:      Optional[str] = None,
    ):
        self.model_id   = model_id
        self.model_name = model_name
        self.status     = status
        self.license_id = license_id
        self.error      = error


# ── core provisioner ──────────────────────────────────────────────────────────

async def _get_active_license(db, model_id: str):
    """Return the most recent non-revoked, non-expired NAELLicense row, or None."""
    from sqlalchemy import select
    from app.models.orm_models import NAELLicense

    now = datetime.now(timezone.utc)
    res = await db.execute(
        select(NAELLicense)
        .where(NAELLicense.model_id == model_id)
        .where(NAELLicense.revoked.is_(False))
        .where(NAELLicense.valid_until > now)
        .order_by(NAELLicense.valid_until.desc())
        .limit(1)
    )
    return res.scalars().first()


async def _provision_model(
    db,
    model,
    *,
    risk_class_override: Optional[str],
    valid_days: int,
    dry_run: bool,
    force: bool,
) -> ProvisionResult:
    """Provision a single model. Returns a ProvisionResult."""
    from app.services.nael_service import nael_service

    model_id   = model.id
    model_name = model.name

    existing = await _get_active_license(db, model_id)
    if existing and not force:
        return ProvisionResult(
            model_id   = model_id,
            model_name = model_name,
            status     = ProvisionResult.STATUS_SKIPPED,
            license_id = existing.id,
        )

    # Derive risk classification: CLI override > model.risk_category > fallback MEDIUM
    risk_class = (
        risk_class_override
        or getattr(model, "risk_category", None)
        or "MEDIUM"
    ).upper()

    # Derive sector restrictions from the model's sector field (may be None)
    raw_sector = getattr(model, "sector", None)
    sectors: List[str] = [raw_sector] if raw_sector else []

    if dry_run:
        return ProvisionResult(
            model_id   = model_id,
            model_name = model_name,
            status     = ProvisionResult.STATUS_DRY_RUN,
        )

    try:
        row = await nael_service.issue_license(
            db                  = db,
            model_id            = model_id,
            risk_classification = risk_class,
            sector_restrictions = sectors,
            valid_days          = valid_days,
        )
        return ProvisionResult(
            model_id   = model_id,
            model_name = model_name,
            status     = ProvisionResult.STATUS_ISSUED,
            license_id = row.id,
        )
    except Exception as exc:  # noqa: BLE001
        return ProvisionResult(
            model_id   = model_id,
            model_name = model_name,
            status     = ProvisionResult.STATUS_ERROR,
            error      = str(exc),
        )


async def run(
    *,
    dry_run:             bool,
    force:               bool,
    valid_days:          int,
    risk_class_override: Optional[str],
    model_id_filter:     Optional[str],
) -> int:
    """Main async entrypoint. Returns exit code."""
    import app.models.orm_models  # ensure all ORM models register with Base  # noqa: F401
    from sqlalchemy import select
    from app.core.crypto import crypto_service
    from app.db.database import AsyncSessionLocal
    from app.models.orm_models import AIModel

    # Initialise crypto so NAEL signing works
    crypto_service.initialize()

    async with AsyncSessionLocal() as db:
        query = select(AIModel)
        if model_id_filter:
            query = query.where(AIModel.id == model_id_filter)

        res    = await db.execute(query)
        models = res.scalars().all()

    if not models:
        if model_id_filter:
            print(f"[ERROR] Model {model_id_filter!r} not found in registry.")
        else:
            print("[ERROR] No models found in registry. Run seed_demo_data.py first.")
        return 2

    results: List[ProvisionResult] = []

    async with AsyncSessionLocal() as db:
        for model in models:
            r = await _provision_model(
                db,
                model,
                risk_class_override = risk_class_override,
                valid_days          = valid_days,
                dry_run             = dry_run,
                force               = force,
            )
            results.append(r)
            _print_row(r)

    _print_summary(results, dry_run=dry_run)

    errors = [r for r in results if r.status == ProvisionResult.STATUS_ERROR]
    return 1 if errors else 0


# ── output helpers ────────────────────────────────────────────────────────────

_COL_W = 36  # model name column width

def _print_row(r: ProvisionResult) -> None:
    name_col = r.model_name[:_COL_W].ljust(_COL_W)
    id_col   = r.model_id[:8]
    if r.status == ProvisionResult.STATUS_ISSUED:
        lic_short = r.license_id[:8] if r.license_id else "?"
        print(f"  [ISSUED]   {name_col}  model={id_col}  license={lic_short}")
    elif r.status == ProvisionResult.STATUS_SKIPPED:
        lic_short = r.license_id[:8] if r.license_id else "?"
        print(f"  [SKIPPED]  {name_col}  model={id_col}  existing={lic_short}")
    elif r.status == ProvisionResult.STATUS_DRY_RUN:
        print(f"  [DRY_RUN]  {name_col}  model={id_col}  (would issue)")
    elif r.status == ProvisionResult.STATUS_ERROR:
        print(f"  [ERROR]    {name_col}  model={id_col}  error={r.error}")


def _print_summary(results: List[ProvisionResult], *, dry_run: bool) -> None:
    issued  = sum(1 for r in results if r.status == ProvisionResult.STATUS_ISSUED)
    skipped = sum(1 for r in results if r.status == ProvisionResult.STATUS_SKIPPED)
    dry     = sum(1 for r in results if r.status == ProvisionResult.STATUS_DRY_RUN)
    errors  = sum(1 for r in results if r.status == ProvisionResult.STATUS_ERROR)
    total   = len(results)

    print()
    print("=" * 70)
    print(f"  NAEL Pre-flight Provisioner — {'DRY RUN ' if dry_run else ''}Summary")
    print("=" * 70)
    print(f"  Total models   : {total}")
    if dry_run:
        print(f"  Would issue    : {dry}")
        print(f"  Already valid  : {skipped}")
    else:
        print(f"  Issued         : {issued}")
        print(f"  Already valid  : {skipped}")
    if errors:
        print(f"  Errors         : {errors}  <-- fix before enabling enforcement")
    print("=" * 70)

    if errors == 0 and not dry_run:
        print()
        print("  All models are licensed. Safe to flip:")
        print("    NAEL_ENFORCEMENT_ENABLED=true")
    elif dry_run and errors == 0:
        print()
        print("  Dry run complete. Re-run without --dry-run to apply.")
    elif errors:
        print()
        print("  Resolve errors above before enabling NAEL enforcement.")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="BASCG NAEL Pre-flight Provisioner — issue licenses for all unlicensed models.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be issued without writing to the database.",
    )
    p.add_argument(
        "--force", action="store_true",
        help="Re-issue a fresh license even for models that already have one.",
    )
    p.add_argument(
        "--valid-days", type=int, default=365, metavar="DAYS",
        help="License validity window in days (default: 365).",
    )
    p.add_argument(
        "--risk-class", choices=["LOW", "MEDIUM", "HIGH", "PROHIBITED"],
        default=None, metavar="LEVEL",
        help="Override risk classification for all issued licenses. "
             "Defaults to each model's own risk_classification field.",
    )
    p.add_argument(
        "--model-id", default=None, metavar="UUID",
        help="Provision a single model by its UUID instead of all models.",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    print()
    print("=" * 70)
    print("  BASCG NAEL Pre-flight Provisioner")
    print("=" * 70)
    if args.dry_run:
        print("  Mode       : DRY RUN (no DB writes)")
    else:
        print("  Mode       : LIVE (writing to DB)")
    print(f"  Valid days : {args.valid_days}")
    if args.risk_class:
        print(f"  Risk class : {args.risk_class} (override — applies to all issued licenses)")
    if args.force:
        print("  Force      : yes (re-issuing even for already-licensed models)")
    if args.model_id:
        print(f"  Model ID   : {args.model_id}")
    print()

    exit_code = asyncio.run(run(
        dry_run             = args.dry_run,
        force               = args.force,
        valid_days          = args.valid_days,
        risk_class_override = args.risk_class,
        model_id_filter     = args.model_id,
    ))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
