"""FastAPI 앱 생성 팩토리.

- 공개 진입점(backend.main)은 항상 mode="secure"로만 앱을 만든다.
- 취약 비교 모드("vulnerable")는 검사·테스트 코드에서만 만들 수 있다. 세 겹으로 막는다.
  1) backend.main은 secure를 하드코딩하고 취약 모듈을 import하지 않는다.
  2) 취약 라우터(backend.services.insecure_lab)는 vulnerable일 때만 지연 import한다.
  3) vulnerable은 시스템 임시 폴더 안의 명시적 DB 경로가 아니면 ValueError로 거절한다
     (기본 DB `data/bankguard.db`에는 절대 취약 로직을 붙일 수 없다).
"""
from __future__ import annotations

import logging
import sqlite3
import tempfile
import threading
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.config import (
    API_VERSION,
    DEFAULT_DB_PATH,
    LAB_MODES,
    PUBLIC_MODES,
    SERVICE_NAME,
)
from backend.routes import admin_router, router

SUPPORTED_MODES = PUBLIC_MODES | LAB_MODES

logger = logging.getLogger("bankguard.api")


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


def create_app(
    mode: str = "secure",
    db_path: str | Path | None = None,
    flaw: str | None = None,
) -> FastAPI:
    """BankGuard FastAPI 앱을 만든다.

    Args:
        mode: "secure"(공개 가능) 또는 "vulnerable"(검사 전용, 임시 DB 필수).
        db_path: SQLite 파일 경로. 테스트는 임시 경로를 넘긴다.
        flaw: vulnerable일 때 붙일 결함 ID("SC-01"~"SC-07") 하나. 결함을 섞어서 붙일 수 없다.
    """
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"지원하지 않는 모드입니다: {mode!r}")
    if mode in PUBLIC_MODES and flaw is not None:
        raise ValueError("secure 모드에는 결함(flaw)을 지정할 수 없습니다.")
    if mode in LAB_MODES:
        if flaw is None:
            raise ValueError("vulnerable 모드는 결함 ID(flaw)를 하나 지정해야 합니다.")
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
        from backend.db import init_db
        from backend.services.insecure_lab import build_lab

        setup = build_lab(flaw)
        if setup.schema_sql is not None:
            # 결함 전용 스키마(SC-02): 안전 코드 경로가 안전 스키마로 먼저 만들지 않도록 여기서 초기화한다.
            init_db(app.state.db_path, setup.schema_sql)
            app.state.db_ready = True
        # 먼저 등록한 경로가 우선하므로, 취약 라우터가 같은 경로의 안전 라우트를 가린다.
        # 취약 라우터에 없는 경로(계좌 목록 등)는 아래 안전 라우터가 그대로 처리한다.
        app.include_router(setup.router)
        app.dependency_overrides.update(setup.dependency_overrides)  # SC-07: 인증 의존성 교체(그 외 결함은 비어 있음)
    app.include_router(router)
    app.include_router(admin_router)

    # 응답에는 일반화된 메시지만 담는다(스택트레이스·로컬 경로·SQL·예외 메시지 비노출, T16).
    # 자세한 내용은 서버 콘솔 로그에만 남긴다.
    @app.exception_handler(sqlite3.OperationalError)
    async def database_error_handler(request: Request, exc: sqlite3.OperationalError) -> JSONResponse:
        logger.exception("DB 오류: %s %s", request.method, request.url.path)
        if "locked" in str(exc).lower() or "busy" in str(exc).lower():
            # 오류를 숨기지 않고 '일시적 사용 중'임을 알려 재시도할 수 있게 한다(명세 15장 DB 파일 잠김).
            return JSONResponse(
                status_code=503,
                content={"detail": "데이터베이스가 일시적으로 사용 중입니다. 잠시 후 다시 시도하세요."},
                headers={"Retry-After": "1"},
            )
        return JSONResponse(status_code=500, content={"detail": "서버 내부 오류가 발생했습니다."})

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("처리되지 않은 오류: %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "서버 내부 오류가 발생했습니다."})

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        """서버 생존 확인. DB 초기화 여부와 무관하게 동작해야 한다(명세 6.1)."""
        return {"status": "ok", "service": SERVICE_NAME}

    return app
