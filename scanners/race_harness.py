"""동시 요청 경쟁 구간을 결정적으로 만드는 검사용 하네스 (SC-03).

취약 코드에는 sleep·훅을 넣지 않는다. 대신 검사 쪽에서 FastAPI `dependency_overrides[get_conn]`으로
요청별 DB 연결을 감싸, "송금인 계좌 행을 읽은 직후" 두 요청이 Barrier에서 만나도록 한다.
- 취약 구현: 두 요청이 같은 (읽어 둔) 잔액을 들고 다음 단계로 가므로 lost update가 매번 재현된다.
- 안전 구현: 이 지점은 BEGIN IMMEDIATE 이전이라 두 요청이 만난 뒤 쓰기 잠금에서 직렬화된다.
같은 하네스를 두 모드에 똑같이 적용하므로 판정 기준은 동일하다.
"""
from __future__ import annotations

import sqlite3
import threading
from typing import Any, Iterator

from fastapi import Request

from backend.auth_demo import ensure_db
from backend.db import connect

BARRIER_TIMEOUT_SEC = 10


class _FetchedRows:
    """이미 읽어 온 행을 fetchone/fetchall로 돌려주는 최소 커서(읽기 잠금을 쥔 채 기다리지 않기 위함)."""

    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class RacingConnection:
    """sqlite3.Connection을 감싸 대상 계좌 행을 처음 읽은 직후 한 번만 Barrier에서 기다린다."""

    def __init__(self, real: sqlite3.Connection, gate: threading.Barrier, target_account_id: int) -> None:
        self._real = real
        self._gate = gate
        self._target = target_account_id
        self._waited = False

    def execute(self, sql: str, parameters: tuple = ()):
        cursor = self._real.execute(sql, parameters)
        if (
            not self._waited
            and "FROM accounts WHERE id = ?" in sql
            and "balance_krw" in sql
            and tuple(parameters) == (self._target,)
        ):
            self._waited = True
            rows = cursor.fetchall()
            self._gate.wait(timeout=BARRIER_TIMEOUT_SEC)
            return _FetchedRows(rows)
        return cursor

    def __getattr__(self, name: str):
        return getattr(self._real, name)


def make_racing_get_conn(gate: threading.Barrier, target_account_id: int):
    """auth_demo.get_conn 대신 꽂을 의존성. 요청마다 독립 연결을 열고 RacingConnection으로 감싼다."""

    def racing_get_conn(request: Request) -> Iterator[RacingConnection]:
        ensure_db(request.app)
        real = connect(request.app.state.db_path)
        try:
            yield RacingConnection(real, gate, target_account_id)
        finally:
            real.close()

    return racing_get_conn
