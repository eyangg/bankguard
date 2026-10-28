"""DAY 1 스모크 테스트: 헬스체크, Swagger 문서, 공개 진입점 모드, 대시보드 첫 화면."""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.factory import create_app

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_health_returns_200_and_contract_body(secure_client):
    resp = secure_client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "BankGuard API"}


def test_health_works_without_db_file(secure_client, db_path):
    # 명세 6.1: DB 초기화 전에도 생존 여부를 확인할 수 있어야 한다.
    assert not db_path.exists()
    assert secure_client.get("/health").status_code == 200


def test_swagger_docs_and_openapi_available(secure_client):
    assert secure_client.get("/docs").status_code == 200
    spec = secure_client.get("/openapi.json").json()
    assert spec["info"]["title"] == "BankGuard API"
    assert "/health" in spec["paths"]


def test_public_entrypoint_is_secure_mode_only():
    from backend.main import app

    assert app.state.mode == "secure"
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200


@pytest.mark.parametrize("bad_mode", ["vulnerable", "insecure", "", "SECURE"])
def test_factory_rejects_unsupported_modes(bad_mode):
    # 알 수 없는 모드는 거절. "vulnerable"은 DAY 3부터 허용되지만 임시 DB 경로가 없으면 역시 거절된다
    # (자세한 격리 규칙은 tests/test_lab_isolation.py).
    with pytest.raises(ValueError):
        create_app(mode=bad_mode)


def test_streamlit_first_screen_renders_without_exception():
    # API 서버가 꺼져 있어도 첫 화면은 예외 없이 렌더링돼야 한다(명세 15장).
    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(str(PROJECT_ROOT / "frontend" / "app.py"), default_timeout=15)
    at.run()
    assert not at.exception
    assert "BANKGUARD" in at.title[0].value
    assert any("아직 검사를 실행하지 않았습니다" in info.value for info in at.info)
