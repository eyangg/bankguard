"""DAY 2 API 계약 테스트: 계좌 조회, 거래내역 소유권, 송금(정상/중복/거절/입력 검증)."""
from __future__ import annotations

import uuid

import pytest

from backend.db import connect

TOKEN_A = {"X-Demo-Token": "demo-token-a"}
TOKEN_B = {"X-Demo-Token": "demo-token-b"}


def new_id() -> str:
    return str(uuid.uuid4())


def body(from_id=101, to_id=102, amount=20_000, request_id=None):
    return {
        "from_account_id": from_id,
        "to_account_id": to_id,
        "amount_krw": amount,
        "request_id": request_id or new_id(),
    }


def snapshot(db_path):
    """(잔액 dict, 송금 기록 수) — API가 아니라 DB를 직접 읽어 검증한다."""
    conn = connect(db_path)
    try:
        balances = {r["id"]: r["balance_krw"] for r in conn.execute("SELECT id, balance_krw FROM accounts")}
        count = conn.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
        return balances, count
    finally:
        conn.close()


SEED_BALANCES = {101: 1_000_000, 102: 500_000, 103: 2_000_000}


# --- 인증 / 계좌 조회 -------------------------------------------------------

def test_db_is_created_lazily_on_first_api_call(secure_client, db_path):
    assert not db_path.exists()
    assert secure_client.get("/api/accounts", headers=TOKEN_A).status_code == 200
    assert db_path.exists()


def test_list_accounts_returns_only_own_account(secure_client):
    resp = secure_client.get("/api/accounts", headers=TOKEN_A)
    assert resp.status_code == 200
    assert resp.json() == [{"id": 101, "account_no": "DEMO-101", "balance_krw": 1_000_000}]


@pytest.mark.parametrize("headers", [{}, {"X-Demo-Token": "wrong-token"}, {"X-Demo-Token": ""}])
def test_t04_t05_missing_or_wrong_token_is_401(secure_client, headers):
    assert secure_client.get("/api/accounts", headers=headers).status_code == 401
    assert secure_client.get("/api/accounts/101/transactions", headers=headers).status_code == 401
    assert secure_client.post("/api/transfers", json=body(), headers=headers).status_code == 401


def test_auth_is_checked_before_body_validation(secure_client):
    # 토큰이 없으면 본문이 잘못돼도 422가 아니라 401이어야 한다.
    assert secure_client.post("/api/transfers", json={"amount_krw": -1}).status_code == 401


# --- 거래내역 소유권 --------------------------------------------------------

def test_t02_owner_can_read_own_transactions(secure_client):
    resp = secure_client.get("/api/accounts/101/transactions", headers=TOKEN_A)
    assert resp.status_code == 200
    assert resp.json() == []


def test_t03_reading_other_users_transactions_is_403(secure_client):
    resp = secure_client.get("/api/accounts/102/transactions", headers=TOKEN_A)
    assert resp.status_code == 403


def test_t13_transactions_of_missing_account_is_404(secure_client):
    assert secure_client.get("/api/accounts/999/transactions", headers=TOKEN_A).status_code == 404


def test_403_does_not_leak_other_users_data(secure_client):
    secure_client.post("/api/transfers", json=body(from_id=102, to_id=101, amount=1_000), headers=TOKEN_B)
    resp = secure_client.get("/api/accounts/102/transactions", headers=TOKEN_A)
    assert resp.status_code == 403
    assert "1000" not in resp.text and "amount_krw" not in resp.text


def test_transactions_show_in_and_out_after_transfer(secure_client):
    secure_client.post("/api/transfers", json=body(amount=20_000), headers=TOKEN_A)
    out = secure_client.get("/api/accounts/101/transactions", headers=TOKEN_A).json()
    inn = secure_client.get("/api/accounts/102/transactions", headers=TOKEN_B).json()
    assert [(t["type"], t["amount_krw"]) for t in out] == [("OUT", 20_000)]
    assert [(t["type"], t["amount_krw"]) for t in inn] == [("IN", 20_000)]
    assert set(out[0]) == {"id", "type", "amount_krw", "created_at"}


# --- 송금: 정상 / 멱등성 -----------------------------------------------------

def test_t01_normal_transfer_updates_balances_and_conserves_total(secure_client, db_path):
    req = new_id()
    resp = secure_client.post("/api/transfers", json=body(request_id=req), headers=TOKEN_A)
    assert resp.status_code == 201
    data = resp.json()
    assert data == {
        "transfer_id": data["transfer_id"],
        "request_id": req,
        "from_account_id": 101,
        "to_account_id": 102,
        "amount_krw": 20_000,
        "idempotent_replay": False,
    }
    balances, count = snapshot(db_path)
    assert balances == {101: 980_000, 102: 520_000, 103: 2_000_000}
    assert sum(balances.values()) == sum(SEED_BALANCES.values())
    assert count == 1


def test_t09_same_request_twice_withdraws_once_and_returns_same_transfer_id(secure_client, db_path):
    payload = body()
    first = secure_client.post("/api/transfers", json=payload, headers=TOKEN_A)
    second = secure_client.post("/api/transfers", json=payload, headers=TOKEN_A)
    assert (first.status_code, second.status_code) == (201, 200)
    assert second.json()["transfer_id"] == first.json()["transfer_id"]
    assert first.json()["idempotent_replay"] is False
    assert second.json()["idempotent_replay"] is True
    balances, count = snapshot(db_path)
    assert balances == {101: 980_000, 102: 520_000, 103: 2_000_000}
    assert count == 1


def test_t10_same_request_id_with_different_amount_is_409_and_no_extra_debit(secure_client, db_path):
    req = new_id()
    assert secure_client.post("/api/transfers", json=body(request_id=req), headers=TOKEN_A).status_code == 201
    resp = secure_client.post("/api/transfers", json=body(amount=30_000, request_id=req), headers=TOKEN_A)
    assert resp.status_code == 409
    balances, count = snapshot(db_path)
    assert balances == {101: 980_000, 102: 520_000, 103: 2_000_000}
    assert count == 1


def test_request_id_is_normalized_so_uppercase_replay_is_still_idempotent(secure_client, db_path):
    req = new_id()
    assert secure_client.post("/api/transfers", json=body(request_id=req), headers=TOKEN_A).status_code == 201
    replay = secure_client.post("/api/transfers", json=body(request_id=req.upper()), headers=TOKEN_A)
    assert replay.status_code == 200
    assert snapshot(db_path)[1] == 1


# --- 송금: 거절(DB 불변) ------------------------------------------------------

def test_t08_amount_over_balance_is_409_and_db_unchanged(secure_client, db_path):
    resp = secure_client.post("/api/transfers", json=body(amount=1_200_000), headers=TOKEN_A)
    assert resp.status_code == 409
    assert snapshot(db_path) == (SEED_BALANCES, 0)


def test_t11_withdrawing_from_other_users_account_is_403(secure_client, db_path):
    resp = secure_client.post("/api/transfers", json=body(from_id=102, to_id=101), headers=TOKEN_A)
    assert resp.status_code == 403
    assert snapshot(db_path) == (SEED_BALANCES, 0)


def test_t12_self_transfer_is_400_and_db_unchanged(secure_client, db_path):
    resp = secure_client.post("/api/transfers", json=body(from_id=101, to_id=101), headers=TOKEN_A)
    assert resp.status_code == 400
    assert snapshot(db_path) == (SEED_BALANCES, 0)


@pytest.mark.parametrize("from_id,to_id", [(101, 999), (999, 102)])
def test_t13_missing_account_is_404(secure_client, db_path, from_id, to_id):
    resp = secure_client.post("/api/transfers", json=body(from_id=from_id, to_id=to_id), headers=TOKEN_A)
    assert resp.status_code == 404
    assert snapshot(db_path) == (SEED_BALANCES, 0)


# --- 송금: 입력 검증(422, DB 불변) -------------------------------------------

@pytest.mark.parametrize("amount", [-10_000, 0, 10_000_001, 100.5, 100.0, True, "20000", None])
def test_t06_t07_t15_invalid_amount_is_422_and_db_unchanged(secure_client, db_path, amount):
    resp = secure_client.post("/api/transfers", json=body(amount=amount), headers=TOKEN_A)
    assert resp.status_code == 422
    assert snapshot(db_path) == (SEED_BALANCES, 0)


def test_upper_limit_amount_is_accepted_boundary(secure_client):
    # 상한 경계값: 10,000,000원은 형식상 허용(잔액 부족으로 409가 될 뿐 422가 아니다).
    assert secure_client.post("/api/transfers", json=body(amount=10_000_000), headers=TOKEN_A).status_code == 409


@pytest.mark.parametrize("request_id", ["not-a-uuid", "", 123, None])
def test_invalid_request_id_is_422(secure_client, request_id):
    payload = body()
    payload["request_id"] = request_id
    assert secure_client.post("/api/transfers", json=payload, headers=TOKEN_A).status_code == 422


@pytest.mark.parametrize("field,value", [("from_account_id", "101"), ("to_account_id", 102.0), ("from_account_id", True)])
def test_non_integer_account_ids_are_422(secure_client, field, value):
    payload = body()
    payload[field] = value
    assert secure_client.post("/api/transfers", json=payload, headers=TOKEN_A).status_code == 422


def test_unknown_field_is_422(secure_client):
    payload = body()
    payload["owner_user_id"] = 2
    assert secure_client.post("/api/transfers", json=payload, headers=TOKEN_A).status_code == 422


# --- 계약 ---------------------------------------------------------------------

def test_t19_demo_users_endpoint_does_not_exist(secure_client):
    assert secure_client.get("/api/demo/users").status_code == 404
    assert "/api/demo/users" not in secure_client.get("/openapi.json").json()["paths"]
