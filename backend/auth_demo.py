"""X-Demo-Token 처리와 요청별 DB 연결 (공통 의존성).

토큰은 학습용 가상 사용자 식별자일 뿐 실제 은행 인증과 동등하지 않다.
클라이언트가 보내는 사용자 ID는 신뢰하지 않고, 항상 토큰에 연결된 user_id만 사용한다.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Iterator

from fastapi import Depends, Header, HTTPException, Request

from backend import audit, repository, throttle
from backend.db import connect, init_db


def ensure_db(app) -> None:
    """첫 DB 사용 시점에 한 번만 스키마·시드를 만든다. /health는 DB를 건드리지 않는다."""
    if app.state.db_ready:
        return
    with app.state.db_lock:
        if not app.state.db_ready:
            init_db(app.state.db_path)
            app.state.db_ready = True


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    ensure_db(request.app)
    conn = connect(request.app.state.db_path)
    try:
        yield conn
    finally:
        conn.close()


@dataclass(frozen=True)
class AuthUser:
    user_id: int
    token_fp: str
    role: str


def current_user(
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
    x_demo_token: str | None = Header(default=None),
) -> AuthUser:
    fp = audit.token_fingerprint(x_demo_token)
    # SC-07: 잠긴 클라이언트는 토큰을 검사하지 않는다(맞는 토큰이어도 추측 결과를 알려 주지 않음).
    attempt = throttle.reserve_attempt(conn, throttle.client_key(request))
    if attempt.locked:
        audit.record(conn, audit.AUTH_LOCKED, 429, token_fp=fp, detail="인증 실패 누적으로 잠긴 클라이언트")
        raise HTTPException(
            status_code=429,
            detail="인증 실패가 너무 많습니다. 잠시 후 다시 시도하세요.",
            headers={"Retry-After": str(attempt.retry_after)},
        )
    user = repository.get_user_by_token(conn, x_demo_token) if x_demo_token else None
    if user is None:
        audit.record(
            conn,
            audit.AUTH_FAIL,
            401,
            token_fp=fp,
            detail="토큰 없음" if not x_demo_token else "토큰 불일치",
        )
        raise HTTPException(status_code=401, detail="인증 토큰이 없거나 올바르지 않습니다.")
    throttle.release_attempt(conn, attempt)
    return AuthUser(user_id=user["id"], token_fp=fp, role=user["role"])


def require_admin(
    request: Request,
    user: AuthUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
) -> AuthUser:
    """관리 기능 전용 역할 검사(SC-05). 관리 라우터 전체에 기본값으로 걸어 '기본 거부'를 만든다.

    화면에 버튼이 안 보이는 것은 통제가 아니므로 role은 항상 서버에서 확인한다.
    """
    if user.role != "admin":
        raw = request.path_params.get("account_id")
        audit.record(
            conn,
            audit.ACCESS_DENIED,
            403,
            actor_user_id=user.user_id,
            token_fp=user.token_fp,
            target_account_id=int(raw) if isinstance(raw, str) and raw.isdigit() else None,
            detail="관리자 전용 기능 호출 시도",
        )
        raise HTTPException(status_code=403, detail="관리자만 사용할 수 있는 기능입니다.")
    return user
