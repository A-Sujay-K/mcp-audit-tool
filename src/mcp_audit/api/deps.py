"""FastAPI dependency injection — database sessions and settings."""

from __future__ import annotations

from collections.abc import AsyncGenerator

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from mcp_audit.config import Settings, get_settings
from mcp_audit.db.repository import AuditRepository, get_async_session_factory, get_engine

settings = get_settings()
engine = get_engine(settings)
async_session_factory = get_async_session_factory(engine)


def get_app_settings() -> Settings:
    """Return the application settings."""
    return settings


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session."""
    async with async_session_factory() as session:
        yield session


def get_repository(
    session: AsyncSession = Depends(get_db_session),
) -> AuditRepository:
    """Return an AuditRepository bound to the current session."""
    return AuditRepository(session)
