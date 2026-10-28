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
ALL_FLAWS = ["SC-01", "SC-02", "SC-03", "SC-04", "SC-05", "SC-06"]
LAB_TAG = "INSECURE-LAB (검사 전용)"


def test_public_modes_contain_only_secure():
    assert PUBLIC_MODES == frozenset({"secure"})


def test_vulnerable_requires_explicit_db_path():
    with pytest.raises(ValueError):
        create_app(mode="vulnerable", flaw="SC-01")


def test_vulnerable_refuses_default_db_path():
    with pytest.raises(ValueError):
        create_app(mode="vulnerable", db_path=DEFAULT_DB_PATH, flaw="SC-01")


def test_vulnerable_refuses_db_outside_system_temp():
    outside = PROJECT_ROOT / "data" / "not_temp.db"
    assert not outside.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())
    with pytest.raises(ValueError):
        create_app(mode="vulnerable", db_path=outside, flaw="SC-02")  # 전용 스키마 결함이어도 파일을 만들면 안 된다
    assert not outside.exists()  # 거절 과정에서 파일을 만들지 않았다


def test_vulnerable_requires_exactly_one_known_flaw(tmp_path):
    with pytest.raises(ValueError):
        create_app(mode="vulnerable", db_path=tmp_path / "lab.db")  # 결함 미지정
    with pytest.raises(ValueError):
        create_app(mode="vulnerable", db_path=tmp_path / "lab.db", flaw="SC-99")
    with pytest.raises(ValueError):
        create_app(mode="vulnerable", db_path=tmp_path / "lab.db", flaw=["SC-01", "SC-05"])  # 섞어 붙이기 불가


def test_secure_mode_rejects_flaw_argument(tmp_path):
    with pytest.raises(ValueError):
        create_app(mode="secure", db_path=tmp_path / "x.db", flaw="SC-01")


@pytest.mark.parametrize("flaw", ALL_FLAWS)
def test_vulnerable_allowed_with_temp_db_and_known_flaw(tmp_path, flaw):
    app = create_app(mode="vulnerable", db_path=tmp_path / "lab.db", flaw=flaw)
    assert app.state.mode == "vulnerable"


def test_secure_app_does_not_use_lab_endpoints():
    app = create_app(mode="secure")
    assert _routes(app)  # 라우트가 실제로 잡혔는지(빈 목록이면 이 검사는 무의미)
    assert not any(LAB_TAG in (getattr(r, "tags", None) or []) for r in _routes(app))
    assert not any("insecure_lab" in r.endpoint.__module__ for r in _routes(app))


@pytest.mark.parametrize("flaw", ALL_FLAWS)
def test_vulnerable_app_mounts_only_the_selected_flaw(tmp_path, flaw):
    app = create_app(mode="vulnerable", db_path=tmp_path / "lab.db", flaw=flaw)
    lab_routes = [r for r in _routes(app) if LAB_TAG in (getattr(r, "tags", None) or [])]
    expected = {
        "SC-01": {("GET", "/api/accounts/{account_id}/transactions")},
        "SC-02": {("POST", "/api/transfers")},
        "SC-03": {("POST", "/api/transfers")},
        "SC-04": {("POST", "/api/transfers")},
        "SC-05": {("POST", "/api/admin/accounts/{account_id}/freeze")},
        "SC-06": {("PATCH", "/api/accounts/{account_id}")},
    }[flaw]
    mounted = {(m, r.path) for r in lab_routes for m in r.methods}
    assert mounted == expected  # 다른 결함의 경로는 하나도 붙지 않는다


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


def _routes(app) -> list:
    """FastAPI 0.162는 include_router 결과를 _IncludedRouter로 감싸므로 original_router를 따라가며 라우트를 모은다."""
    found: list = []

    def walk(routes):
        for route in routes:
            if getattr(route, "endpoint", None) is not None:
                found.append(route)
            nested = getattr(route, "original_router", None)
            if nested is not None:
                walk(nested.routes)

    walk(app.routes)
    return found
