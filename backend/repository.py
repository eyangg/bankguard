"""읽기 전용 조회 쿼리. 모든 SQL은 파라미터 바인딩(?)만 사용한다."""
from __future__ import annotations

import sqlite3


def get_user_by_token(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, display_name, role FROM users WHERE demo_token = ?", (token,)
    ).fetchone()


def list_accounts_for_user(conn: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, account_no, balance_krw FROM accounts WHERE owner_user_id = ? ORDER BY id",
        (user_id,),
    ).fetchall()


def get_account(conn: sqlite3.Connection, account_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, owner_user_id, account_no, balance_krw, status, nickname FROM accounts WHERE id = ?",
        (account_id,),
    ).fetchone()


def list_transactions(conn: sqlite3.Connection, account_id: int) -> list[dict]:
    """계좌 기준 입출금 내역. 자기 계좌 송금은 금지이므로 한 송금이 IN과 OUT에 동시에 잡히지 않는다."""
    rows = conn.execute(
        "SELECT id, sender_account_id, amount_krw, created_at FROM transfers"
        " WHERE sender_account_id = ? OR recipient_account_id = ? ORDER BY id",
        (account_id, account_id),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "type": "OUT" if r["sender_account_id"] == account_id else "IN",
            "amount_krw": r["amount_krw"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]
