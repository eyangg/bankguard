"""허구의 시드 데이터 상수와 시드 함수 (명세 5장).

모든 이름·계좌번호·토큰은 실재하지 않는 데모 값이다. 토큰은 학습용 사용자 식별자일 뿐
실제 인증 수단이 아니다. 대시보드도 이 상수를 직접 import한다(공개 API로 토큰을 노출하지 않음, 명세 6.2).
"""
from __future__ import annotations

import sqlite3
from typing import NamedTuple


class SeedUser(NamedTuple):
    user_id: int
    display_name: str
    demo_token: str


class SeedAccount(NamedTuple):
    account_id: int
    owner_user_id: int
    account_no: str
    balance_krw: int


SEED_USERS: tuple[SeedUser, ...] = (
    SeedUser(1, "가상 고객 A", "demo-token-a"),
    SeedUser(2, "가상 고객 B", "demo-token-b"),
    SeedUser(3, "가상 고객 C", "demo-token-c"),
)

SEED_ACCOUNTS: tuple[SeedAccount, ...] = (
    SeedAccount(101, 1, "DEMO-101", 1_000_000),
    SeedAccount(102, 2, "DEMO-102", 500_000),
    SeedAccount(103, 3, "DEMO-103", 2_000_000),
)


def seed_database(conn: sqlite3.Connection) -> bool:
    """users가 비어 있을 때만 시드를 넣는다. 넣었으면 True, 이미 있으면 False.

    이미 데이터가 있는 DB의 잔액을 시드 값으로 되돌리지 않기 위해 덮어쓰지 않는다.
    """
    if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        return False

    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.executemany(
            "INSERT INTO users (id, display_name, demo_token) VALUES (?, ?, ?)",
            SEED_USERS,
        )
        conn.executemany(
            "INSERT INTO accounts (id, owner_user_id, account_no, balance_krw) VALUES (?, ?, ?, ?)",
            SEED_ACCOUNTS,
        )
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return True
