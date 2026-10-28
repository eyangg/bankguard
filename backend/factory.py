"""FastAPI 앱 생성 팩토리.

- 공개 진입점(backend.main)은 항상 mode="secure"로만 앱을 만든다.
- 취약 비교 모드("vulnerable")는 검사·테스트 코드에서만 만들 수 있다. 세 겹으로 막는다.
  1) backend.main은 secure를 하드코딩하고 취약 모듈을 import하지 않는다.
  2) 취약 라우터(backend.services.insecure_lab)는 vulnerable일 때만 지연 import한다.
  3) vulnerable은 시스템 임시 폴더 안의 명시적 DB 경로가 아니면 ValueError로 거절한다
     (기본 DB `data/bankguard.db`에는 절대 취약 로직을 붙일 수 없다).
"""
from __future__ import annotations

import tempfile
import threading
from pathlib import Path

from fastapi import FastAPI

from backend.config import (
    API_VERSION,
    DEFAULT_DB_PATH,
    LAB_MODES,
    PUBLIC_MODES,
    SERVICE_NAME,
)
from backend.routes import admin_router, router

SUPPORTED_MODES = PUBLIC_MODES | LAB_MODES


def _require_isolated_db(db_path: str | Path | None) -> Path:
    """취약 모드가 쓸 DB가 임시 폴더 안의 명시적 경로인지 확인한다."""
    if db_path is None:
        raise ValueError("vulnerable 모드는 임시 DB 경로(db_path)를 명시해야 합니다.")
    resolved = Path(db_path).resolve()
    if resolved == DEFAULT_DB_PATH.resolve():
        raise ValueError("vulnerable 모드는 기본 DB를 사용할 수 없습니다.")
    temp_root = Path(tempfile.gettempdir()).resolve()
    if not resolved.is_relative_to(temp_root):
        raise ValueError("vulnerable 모드의 DB는 시스템 임시 폴더 안에 있어야 합니다.")
    return resolved


def create_app(mode: str = "secure", db_path: str | Path | None = None) -> FastAPI:
    """BankGuard FastAPI 앱을 만든다.

    Args:
        mode: "secure"(공개 가능) 또는 "vulnerable"(검사 전용, 임시 DB 필수).
        db_path: SQLite 파일 경로. 테스트는 임시 경로를 넘긴다.
    """
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"지원하지 않는 모드입니다: {mode!r}")
    if mode in LAB_MODES:
        db_path = _require_isolated_db(db_path)

    app = FastAPI(
        title=SERVICE_NAME,
        version=API_VERSION,
        description="가상 은행 API 보안 실습용 로컬 서버 (실제 금융 서비스 아님)",
    )
    app.state.mode = mode
    app.state.db_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    # DB는 첫 API 요청 때 한 번 초기화한다(/health는 DB 없이 동작해야 함, 명세 6.1).
    app.state.db_ready = False
    app.state.db_lock = threading.Lock()

    if mode in LAB_MODES:
        # 지연 import: 공개(secure) 경로에서는 취약 모듈이 메모리에 올라오지도 않는다.
        from backend.services.insecure_lab import build_lab_router

        # 먼저 등록한 경로가 우선하므로, 취약 라우터가 같은 경로의 안전 라우트를 가린다.
        # 취약 라우터에 없는 경로(계좌 목록, 송금 등)는 아래 안전 라우터가 그대로 처리한다.
        app.include_router(build_lab_router())
    app.include_router(router)
    app.include_router(admin_router)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        """서버 생존 확인. DB 초기화 여부와 무관하게 동작해야 한다(명세 6.1)."""
        return {"status": "ok", "service": SERVICE_NAME}

    return app
