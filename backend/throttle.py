"""SC-07 인증 시도 횟수 제한 (OWASP API2:2023, CWE-307).

같은 클라이언트가 최근 AUTH_WINDOW_SECONDS 안에 인증에 AUTH_MAX_FAILURES번 실패하면, 그 뒤 요청은
토큰을 검사하지 않고 429로 거절한다(잠금 중에는 맞는 토큰도 검사하지 않아야 추측이 멈춘다).

설계 결정
- 시도를 '먼저 예약'한다. "잠금 확인 → (토큰 검사) → 실패 기록" 순서면 동시에 들어온 요청들이 모두
  잠금 확인을 통과해 제한보다 많이 추측할 수 있다(확인-사용 경쟁 조건). 그래서 BEGIN IMMEDIATE 안에서
  횟수 확인과 시도 행 INSERT를 한 번에 하고, 인증에 성공하면 그 행을 지운다. 남은 행 = 실패 횟수.
- 인증 성공이 이전 실패 기록을 초기화하지 않는다. 초기화하면 공격자가 자기 정상 토큰을 섞어 제한을 우회한다.
- 클라이언트 식별은 연결 주소(request.client.host)만 쓴다. X-Forwarded-For 같은 헤더는 요청자가 바꿀 수 있어
  신뢰하지 않는다(프록시 뒤 배포는 이 실습 범위 밖).
"""
from __future__ import annotations

import math
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Request

from backend.config import AUTH_MAX_FAILURES, AUTH_WINDOW_SECONDS


@dataclass(frozen=True)
class Attempt:
    """예약된 시도(attempt_id) 또는 잠금 상태(retry_after초 뒤 다시 시도 가능)."""

    attempt_id: int | None
    retry_after: int | None = None

    @property
    def locked(self) -> bool:
        return self.retry_after is not None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="microseconds")


def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def reserve_attempt(conn: sqlite3.Connection, key: str) -> Attempt:
    """잠겨 있으면 Attempt(None, retry_after), 아니면 시도 1건을 예약하고 그 ID를 돌려준다."""
    now = _now()
    cutoff = _iso(now - timedelta(seconds=AUTH_WINDOW_SECONDS))
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM auth_attempts WHERE created_at <= ?", (cutoff,))  # 창 밖 기록 정리
        recent = [
            row["created_at"]
            for row in conn.execute(
                "SELECT created_at FROM auth_attempts WHERE client_key = ? ORDER BY created_at", (key,)
            )
        ]
        if len(recent) >= AUTH_MAX_FAILURES:
            # 남은 실패가 제한보다 하나 적어지는 시점(= 이 행이 창 밖으로 나가는 시점)까지 잠긴다.
            unlock_at = datetime.fromisoformat(recent[len(recent) - AUTH_MAX_FAILURES]) \
                + timedelta(seconds=AUTH_WINDOW_SECONDS)
            conn.execute("COMMIT")
            return Attempt(None, max(1, math.ceil((unlock_at - now).total_seconds())))
        cursor = conn.execute(
            "INSERT INTO auth_attempts (client_key, created_at) VALUES (?, ?)", (key, _iso(now))
        )
        conn.execute("COMMIT")
        return Attempt(cursor.lastrowid)
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def release_attempt(conn: sqlite3.Connection, attempt: Attempt) -> None:
    """인증에 성공한 시도의 예약을 지운다(실패 횟수에 넣지 않는다)."""
    conn.execute("DELETE FROM auth_attempts WHERE id = ?", (attempt.attempt_id,))
