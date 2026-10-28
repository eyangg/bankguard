"""스키마 제약과 시드 데이터 검증 (DAY 2 + v1.2 role/status/nickname)."""
from __future__ import annotations

import sqlite3

import pytest

from backend.db import connect, init_db
from backend.seed import SEED_ACCOUNTS, SEED_USERS


@pytest.fixture()
def conn(db_path):
    init_db(db_path)
    c = connect(db_path)
    yield c
    c.close()


def test_seed_matches_spec(conn):
    users = conn.execute("SELECT id, display_name, demo_token, role FROM users ORDER BY id").fetchall()
    assert [tuple(u) for u in users] == [
        (1, "가상 고객 A", "demo-token-a", "customer"),
        (2, "가상 고객 B", "demo-token-b", "customer"),
        (3, "가상 고객 C", "demo-token-c", "customer"),
        (9, "가상 운영자", "demo-token-admin", "admin"),
    ]
    accounts = conn.execute(
        "SELECT id, owner_user_id, account_no, balance_krw, status, nickname FROM accounts ORDER BY id"
    ).fetchall()
    assert [tuple(a) for a in accounts] == [
        (101, 1, "DEMO-101", 1_000_000, "ACTIVE", None),
        (102, 2, "DEMO-102", 500_000, "ACTIVE", None),
        (103, 3, "DEMO-103", 2_000_000, "ACTIVE", None),
    ]
    assert [tuple(a)[:4] for a in accounts] == [tuple(a) for a in SEED_ACCOUNTS]
    assert len(SEED_USERS) == 4


def test_admin_user_has_no_account(conn):
    assert conn.execute("SELECT COUNT(*) FROM accounts WHERE owner_user_id = 9").fetchone()[0] == 0


def test_all_four_tables_exist(conn):
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "accounts", "transfers", "audit_log"} <= names


def test_init_db_is_idempotent_and_keeps_existing_balances(db_path):
    init_db(db_path)
    c = connect(db_path)
    c.execute("UPDATE accounts SET balance_krw = 777 WHERE id = 101")
    c.close()

    init_db(db_path)  # 다시 호출해도 시드로 덮어쓰지 않는다
    c = connect(db_path)
    try:
        assert c.execute("SELECT balance_krw FROM accounts WHERE id = 101").fetchone()[0] == 777
        assert c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 4
    finally:
        c.close()


def test_foreign_keys_enabled_per_connection(conn):
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_negative_balance_rejected_by_check(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE accounts SET balance_krw = -1 WHERE id = 101")


@pytest.mark.parametrize("amount", [0, -10_000])
def test_non_positive_transfer_amount_rejected_by_check(conn, amount):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO transfers (request_id, sender_account_id, recipient_account_id,"
            " amount_krw, payload_fingerprint, created_at) VALUES (?, 101, 102, ?, 'fp', 'now')",
            ("req-1", amount),
        )


def test_duplicate_request_id_rejected_by_unique(conn):
    sql = (
        "INSERT INTO transfers (request_id, sender_account_id, recipient_account_id,"
        " amount_krw, payload_fingerprint, created_at) VALUES ('dup', 101, 102, 1000, 'fp', 'now')"
    )
    conn.execute(sql)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(sql)


def test_transfer_to_missing_account_rejected_by_foreign_key(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO transfers (request_id, sender_account_id, recipient_account_id,"
            " amount_krw, payload_fingerprint, created_at) VALUES ('fk', 101, 999, 1000, 'fp', 'now')"
        )


def test_audit_log_columns_match_spec(conn):
    cols = [r[1] for r in conn.execute("PRAGMA table_info(audit_log)")]
    assert cols == [
        "id", "created_at", "event_type", "actor_user_id",
        "token_fingerprint", "target_account_id", "http_status", "detail",
    ]


def test_invalid_role_rejected_by_check(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE users SET role = 'superuser' WHERE id = 1")


def test_invalid_account_status_rejected_by_check(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE accounts SET status = 'CLOSED' WHERE id = 101")
