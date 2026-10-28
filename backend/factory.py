"""FastAPI 앱 생성 팩토리.

- 공개 진입점(backend.main)은 항상 mode="secure"로만 앱을 만든다.
- 취약 비교 모드("vulnerable")는 DAY 3에 추가하며, 그때도 TestClient + 임시 DB에서만 생성한다.
  현재(DAY 1)는 secure 외의 모드를 요청하면 즉시 ValueError로 거절한다.
"""
from __future__ import annotations

import threading
from pathlib import Path

from fastapi import FastAPI

from backend.config import API_VERSION, DEFAULT_DB_PATH, PUBLIC_MODES, SERVICE_NAME
from backend.routes import router

SUPPORTED_MODES = PUBLIC_MODES  # DAY 3에서 테스트 전용 "vulnerable"을 별도 경로로 추가 예정


def create_app(mode: str = "secure", db_path: str | Path | None = None) -> FastAPI:
    """BankGuard FastAPI 앱을 만든다.

    Args:
        mode: 실행 모드. 현재는 "secure"만 허용.
        db_path: SQLite 파일 경로. DAY 2부터 사용(테스트는 임시 경로를 넘긴다).
    """
    if mode not in SUPPORTED_MODES:
        raise ValueError(f"지원하지 않는 모드입니다: {mode!r}")

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
    app.include_router(router)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        """서버 생존 확인. DB 초기화 여부와 무관하게 동작해야 한다(명세 6.1)."""
        return {"status": "ok", "service": SERVICE_NAME}

    return app
