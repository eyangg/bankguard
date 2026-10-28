"""공통 pytest fixture.

각 테스트는 tmp_path 아래 독립된 DB 경로를 사용한다(명세 7장 테스트 작성 규칙).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.factory import create_app


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "bankguard_test.db"


@pytest.fixture()
def secure_client(db_path):
    app = create_app(mode="secure", db_path=db_path)
    with TestClient(app) as client:
        yield client
