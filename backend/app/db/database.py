"""Hardened Production Database Setup — Postgres + SQLite"""
import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.core.config import settings

logger = logging.getLogger("kavachx.db")

# Enterprise Engine — using defaults for Postgres.app stability
engine = create_async_engine(
    settings.DATABASE_URL.strip(),
    echo=False,
    pool_pre_ping=True
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession
)

class Base(DeclarativeBase):
    pass


async def _ensure_postgres_database() -> None:
    """
    If DATABASE_URL points to PostgreSQL and the target database does not yet
    exist, create it automatically.  No-op for SQLite.
    """
    url = settings.DATABASE_URL.strip()
    if not (url.startswith("postgresql") or url.startswith("postgres")):
        return  # SQLite — nothing to create

    # asyncpg DSN: postgresql+asyncpg://user[:pass]@host[:port]/dbname
    # We need to connect to the *default* postgres database first
    try:
        import asyncpg
        # Extract dbname from end of URL
        clean = url.replace("postgresql+asyncpg://", "").replace("postgresql://", "").replace("postgres://", "")
        # clean = user[:pass]@host[:port]/dbname[?params]
        dbname = clean.split("/")[-1].split("?")[0]
        # Build a connection string to the postgres meta-db
        admin_dsn = url.replace(f"/{dbname}", "/postgres").replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")

        conn = await asyncpg.connect(dsn=admin_dsn)
        try:
            exists = await conn.fetchval(
                "SELECT 1 FROM pg_database WHERE datname = $1", dbname
            )
            if not exists:
                # CREATE DATABASE cannot run inside a transaction block
                await conn.execute(f'CREATE DATABASE "{dbname}"')
                logger.info("Created PostgreSQL database: %s", dbname)
            else:
                logger.debug("PostgreSQL database already exists: %s", dbname)
        finally:
            await conn.close()
    except Exception as exc:
        # Non-fatal: if we can't auto-create, the subsequent create_all will fail
        # with a clear error message.
        logger.warning("Could not auto-create PostgreSQL database: %s", exc)


async def init_db():
    """
    Ensure the target database exists (Postgres only) then create all tables.
    Safe to call on every startup — CREATE TABLE IF NOT EXISTS is idempotent.
    """
    await _ensure_postgres_database()
    # Force import of all ORM models before create_all
    import app.models.orm_models  # noqa
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified / created.")

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
