"""Shared pytest fixtures for HAST test suite."""
from __future__ import annotations

import os
import tempfile

import pytest
import pytest_asyncio

# Use a fresh in-memory (temp file) SQLite database for each test session
os.environ.setdefault("HAST_DB_PATH", ":memory:")


@pytest.fixture(scope="session")
def event_loop_policy():
    """Use default asyncio event loop policy."""
    import asyncio
    return asyncio.DefaultEventLoopPolicy()


@pytest_asyncio.fixture
async def db():
    """Initialise a fresh in-memory database and tear it down after the test."""
    import aiosqlite
    from backend.db import database as database_module
    from backend.db.models import CREATE_TABLES

    # Create a dedicated temporary file so each test gets an isolated DB.
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    conn = await aiosqlite.connect(db_path)
    conn.row_factory = aiosqlite.Row
    await conn.executescript(CREATE_TABLES)
    await conn.commit()

    # Patch the module-level connection used by all database helpers.
    old_db = database_module._db
    old_path = database_module.DB_PATH
    database_module._db = conn
    database_module.DB_PATH = db_path

    yield conn

    # Teardown
    database_module._db = old_db
    database_module.DB_PATH = old_path
    await conn.close()
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest_asyncio.fixture
async def test_app(db):
    """Return an AsyncClient wrapping the FastAPI app with an isolated DB."""
    from httpx import AsyncClient, ASGITransport
    from backend.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
