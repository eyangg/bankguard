"""공통 pytest fixture.

각 테스트는 tmp_path 아래 독립된 DB 경로를 사용한다(명세 7장 테스트 작성 규칙).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.factory import create_app


@pytest.fixture(autouse=True)
def isolated_artifacts_dir(tmp_path, monkeypatch):
    """모든 테스트가 사용자의 실제 artifacts/ 결과를 덮어쓰지 않도록 저장 위치를 임시 폴더로 고정한다."""
    monkeypatch.setenv("BANKGUARD_ARTIFACTS_DIR", str(tmp_path / "artifacts_out"))


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "bankguard_test.db"


@pytest.fixture()
def secure_client(db_path):
    app = create_app(mode="secure", db_path=db_path)
    with TestClient(app) as client:
        yield client
