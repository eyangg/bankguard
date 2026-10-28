"""SQLite 연결·스키마 (명세 5장).

연결은 autocommit(isolation_level=None)으로 열고 트랜잭션 경계는 코드에서 명시한다
(BEGIN IMMEDIATE / COMMIT / ROLLBACK). 연결마다 외래키를 켠다.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from backend.seed import seed_database

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL,
    demo_token   TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    account_no    TEXT NOT NULL UNIQUE,
    balance_krw   INTEGER NOT NULL CHECK (balance_krw >= 0)
);

CREATE TABLE IF NOT EXISTS transfers (
    id                   INTEGER PRIMARY KEY,
    request_id           TEXT NOT NULL UNIQUE,
    sender_account_id    INTEGER NOT NULL REFERENCES accounts(id),
    recipient_account_id INTEGER NOT NULL REFERENCES accounts(id),
    amount_krw           INTEGER NOT NULL CHECK (amount_krw > 0),
    payload_fingerprint  TEXT NOT NULL,
    created_at           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id                INTEGER PRIMARY KEY,
    created_at        TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    actor_user_id     INTEGER NULL,
    token_fingerprint TEXT NULL,
    target_account_id INTEGER NULL,
    http_status       INTEGER NOT NULL,
    detail            TEXT NULL
);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    """연결을 새로 연다. 요청마다 새 연결을 쓰고 요청 간에 공유하지 않는다.

    FastAPI는 같은 요청의 의존성과 엔드포인트를 서로 다른 워커 스레드에서 실행할 수 있어
    check_same_thread=False로 연다(한 연결을 한 요청 안에서 순차 사용).
    """
    conn = sqlite3.connect(str(db_path), timeout=10, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)


def init_db(db_path: str | Path) -> None:
    """상위 폴더를 만들고 스키마를 생성한 뒤, 비어 있으면 시드를 넣는다. 여러 번 호출해도 안전하다."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        init_schema(conn)
        seed_database(conn)
    finally:
        conn.close()
