"""취약 비교 모드가 공개 경로로 새지 않는지 검사 (명세 4장 설계 결정 1~2)."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from backend.config import DEFAULT_DB_PATH, PUBLIC_MODES
from backend.factory import create_app

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def test_public_modes_contain_only_secure():
    assert PUBLIC_MODES == frozenset({"secure"})


def test_vulnerable_requires_explicit_db_path():
    with pytest.raises(ValueError):
        create_app(mode="vulnerable")


def test_vulnerable_refuses_default_db_path():
    with pytest.raises(ValueError):
        create_app(mode="vulnerable", db_path=DEFAULT_DB_PATH)


def test_vulnerable_refuses_db_outside_system_temp():
    outside = PROJECT_ROOT / "data" / "not_temp.db"
    assert not outside.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
    with pytest.raises(ValueError):
        create_app(mode="vulnerable", db_path=outside)
    assert not outside.exists()  # 거절 과정에서 파일을 만들지 않았다


def test_vulnerable_allowed_with_temp_db(tmp_path):
    app = create_app(mode="vulnerable", db_path=tmp_path / "lab.db")
    assert app.state.mode == "vulnerable"


def test_secure_app_does_not_use_lab_endpoints():
    app = create_app(mode="secure")
    handler_modules = _handler_modules(app)
    assert handler_modules  # 라우트가 실제로 잡혔는지(빈 목록이면 이 검사는 무의미)
    assert not any("insecure_lab" in m for m in handler_modules)


def test_vulnerable_app_does_use_lab_endpoints(tmp_path):
    app = create_app(mode="vulnerable", db_path=tmp_path / "lab.db")
    assert any("insecure_lab" in m for m in _handler_modules(app))


def test_public_entrypoint_never_imports_lab_module():
    # 새 프로세스에서 backend.main만 import했을 때 취약 모듈이 올라오지 않아야 한다.
    # subprocess: 쉘 없이, 현재 인터프리터와 고정된 로컬 프로젝트 폴더만 사용.
    code = (
        "import sys, backend.main;"
        "print('LAB_LOADED' if 'backend.services.insecure_lab' in sys.modules else 'LAB_ABSENT')"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=60, shell=False,
    )
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "LAB_ABSENT"


def test_public_app_mode_is_secure_and_openapi_has_no_lab_tag():
    from backend.main import app

    assert app.state.mode == "secure"
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        spec = client.get("/openapi.json").json()
    tags = {tag for ops in spec["paths"].values() for op in ops.values() for tag in op.get("tags", [])}
    assert not any("INSECURE" in tag for tag in tags)


def _handler_modules(app) -> set[str]:
    """라우트 구조(_IncludedRouter 등)가 버전마다 달라서 OpenAPI 생성에 쓰이는 엔드포인트를 재귀로 수집한다."""
    found: set[str] = set()

    def walk(routes):
        for route in routes:
            endpoint = getattr(route, "endpoint", None)
            if endpoint is not None:
                found.add(endpoint.__module__)
            nested = getattr(route, "original_router", None)  # FastAPI 0.162: _IncludedRouter
            if nested is not None:
                walk(nested.routes)

    walk(app.routes)
    return found
