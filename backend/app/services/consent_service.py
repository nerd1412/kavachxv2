from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from datetime import datetime, timezone
from app.models.orm_models import ConsentRecord

class ConsentService:
    """Verifies data principal consent in accordance with India DPDP 2023."""
    
    async def verify_consent(self, db: AsyncSession, principal_id: str, purpose: str) -> bool:
        """
        Check if valid, non-expired consent exists for the principal and purpose.
        """
        if not principal_id or not purpose:
            return False

        result = await db.execute(
            select(ConsentRecord)
            .where(and_(
                ConsentRecord.data_principal_id == principal_id,
                ConsentRecord.purpose == purpose,
                ConsentRecord.consent_given == True
            ))
        )
        record = result.scalars().first()
        
        if not record:
            return False
            
        # Check expiry
        if record.expires_at and record.expires_at < datetime.now(timezone.utc):
            return False
            
        return True

    async def record_consent(
        self, 
        db: AsyncSession, 
        principal_id: str, 
        purpose: str, 
        given: bool = True,
        expiry: datetime = None
    ):
        """Creates or updates a consent record."""
        # Check for existing
        result = await db.execute(
            select(ConsentRecord)
            .where(and_(
                ConsentRecord.data_principal_id == principal_id,
                ConsentRecord.purpose == purpose
            ))
        )
        record = result.scalars().first()
        
        if record:
            record.consent_given = given
            record.collected_at = datetime.now(timezone.utc)
            record.expires_at = expiry
        else:
            record = ConsentRecord(
                data_principal_id=principal_id,
                purpose=purpose,
                consent_given=given,
                expires_at=expiry
            )
            db.add(record)
        
        await db.commit()
        return record

consent_service = ConsentService()
