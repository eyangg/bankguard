"""DAY 2 감사 로그 테스트: 기록 여부, 마스킹, 롤백과의 분리 (T17 포함)."""
from __future__ import annotations

import uuid

from backend.db import connect

TOKEN_A = {"X-Demo-Token": "demo-token-a"}
TOKEN_B = {"X-Demo-Token": "demo-token-b"}
RAW_TOKEN_A = "demo-token-a"


def logs(db_path):
    conn = connect(db_path)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY id")]
    finally:
        conn.close()


def transfer(client, headers, from_id=101, to_id=102, amount=20_000, request_id=None):
    return client.post(
        "/api/transfers",
        json={
            "from_account_id": from_id,
            "to_account_id": to_id,
            "amount_krw": amount,
            "request_id": request_id or str(uuid.uuid4()),
        },
        headers=headers,
    )


def test_t17_forbidden_transactions_access_is_logged_without_secrets(secure_client, db_path):
    assert secure_client.get("/api/accounts/102/transactions", headers=TOKEN_A).status_code == 403
    rows = [r for r in logs(db_path) if r["event_type"] == "ACCESS_DENIED"]
    assert len(rows) == 1
    row = rows[0]
    assert row["http_status"] == 403
    assert row["actor_user_id"] == 1
    assert row["target_account_id"] == 102
    assert row["detail"] and "DEMO-1**" in row["detail"]
    # 토큰 원문·전체 계좌번호는 어떤 컬럼에도 없어야 한다.
    joined = " ".join(str(v) for v in row.values())
    assert RAW_TOKEN_A not in joined
    assert "DEMO-102" not in joined
    assert len(row["token_fingerprint"]) == 12


def test_auth_failures_are_logged_with_fingerprint_not_raw_token(secure_client, db_path):
    secure_client.get("/api/accounts", headers={"X-Demo-Token": "wrong-token"})
    secure_client.get("/api/accounts")
    rows = [r for r in logs(db_path) if r["event_type"] == "AUTH_FAIL"]
    assert len(rows) == 2
    assert all(r["http_status"] == 401 and r["actor_user_id"] is None for r in rows)
    assert len(rows[0]["token_fingerprint"]) == 12 and rows[1]["token_fingerprint"] is None
    assert "wrong-token" not in " ".join(str(v) for r in rows for v in r.values())


def test_missing_account_is_logged_as_not_found(secure_client, db_path):
    secure_client.get("/api/accounts/999/transactions", headers=TOKEN_A)
    rows = [r for r in logs(db_path) if r["event_type"] == "NOT_FOUND"]
    assert len(rows) == 1 and rows[0]["target_account_id"] == 999


def test_successful_transfer_and_replay_are_logged(secure_client, db_path):
    req = str(uuid.uuid4())
    assert transfer(secure_client, TOKEN_A, request_id=req).status_code == 201
    assert transfer(secure_client, TOKEN_A, request_id=req).status_code == 200
    events = [(r["event_type"], r["http_status"]) for r in logs(db_path)]
    assert events == [("TRANSFER_OK", 201), ("IDEMPOTENT_REPLAY", 200)]


def test_rejected_transfer_is_logged_even_though_transaction_rolled_back(secure_client, db_path):
    assert transfer(secure_client, TOKEN_A, amount=1_200_000).status_code == 409
    rows = logs(db_path)
    assert [(r["event_type"], r["http_status"]) for r in rows] == [("TRANSFER_REJECTED", 409)]
    conn = connect(db_path)
    try:
        assert conn.execute("SELECT balance_krw FROM accounts WHERE id = 101").fetchone()[0] == 1_000_000
        assert conn.execute("SELECT COUNT(*) FROM transfers").fetchone()[0] == 0
    finally:
        conn.close()


def test_forbidden_and_self_transfer_attempts_are_logged(secure_client, db_path):
    assert transfer(secure_client, TOKEN_A, from_id=102, to_id=101).status_code == 403
    assert transfer(secure_client, TOKEN_A, from_id=101, to_id=101).status_code == 400
    events = [(r["event_type"], r["http_status"]) for r in logs(db_path)]
    assert events == [("ACCESS_DENIED", 403), ("TRANSFER_REJECTED", 400)]


def test_no_audit_row_contains_full_account_number_or_raw_token(secure_client, db_path):
    secure_client.get("/api/accounts/102/transactions", headers=TOKEN_A)
    transfer(secure_client, TOKEN_A)
    transfer(secure_client, TOKEN_B, from_id=102, to_id=101)
    transfer(secure_client, TOKEN_A, from_id=102, to_id=101)
    secure_client.get("/api/accounts", headers={"X-Demo-Token": "demo-token-zzz"})
    dump = " ".join(str(v) for r in logs(db_path) for v in r.values())
    for secret in ("DEMO-101", "DEMO-102", "DEMO-103", "demo-token-a", "demo-token-b", "demo-token-zzz"):
        assert secret not in dump
