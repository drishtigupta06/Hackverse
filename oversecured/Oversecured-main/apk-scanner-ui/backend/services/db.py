import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from models.base import Base

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://scanner:scannerpass@postgres:5432/apkscanner")

engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=5)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
