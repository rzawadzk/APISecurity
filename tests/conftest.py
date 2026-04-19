"""Shared pytest fixtures."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from api_scout.auth import hash_password
from api_scout.database import Database


@pytest.fixture
def db(tmp_path: Path) -> Database:
    """Fresh isolated SQLite DB per test."""
    return Database(tmp_path / "test.db")


@pytest.fixture
def admin_user(db: Database) -> dict:
    uid = db.create_user("admin", hash_password("adminpass1"), role="admin")
    return db.get_user_by_id(uid)


@pytest.fixture
def analyst_user(db: Database) -> dict:
    uid = db.create_user("analyst", hash_password("analystpass1"), role="analyst")
    return db.get_user_by_id(uid)


@pytest.fixture
def viewer_user(db: Database) -> dict:
    uid = db.create_user("viewer", hash_password("viewerpass1"), role="viewer")
    return db.get_user_by_id(uid)


@pytest.fixture
def dashboard_app(db: Database, admin_user):
    """App with an admin bootstrapped so create_app() will start."""
    from api_scout.dashboard import create_app
    return create_app(db, log_level="WARNING")


@pytest.fixture
def client(dashboard_app):
    from fastapi.testclient import TestClient
    with TestClient(dashboard_app) as c:
        yield c
