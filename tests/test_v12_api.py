"""v1.2 안전 모드 API 테스트: 지급정지(T20), 지급정지 계좌 출금(T21), 별칭 변경(T22)."""
from __future__ import annotations

import uuid

import pytest

from backend.db import connect

TOKEN_A = {"X-Demo-Token": "demo-token-a"}
TOKEN_B = {"X-Demo-Token": "demo-token-b"}
TOKEN_ADMIN = {"X-Demo-Token": "demo-token-admin"}
FREEZE_102 = "/api/admin/accounts/102/freeze"


def account_row(db_path, account_id):
    conn = connect(db_path)
    try:
        return dict(conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone())
    finally:
        conn.close()


def audit_rows(db_path, event_type):
    conn = connect(db_path)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log WHERE event_type = ?", (event_type,))]
    finally:
        conn.close()


def transfer_payload(from_id=101, to_id=102, amount=20_000):
    return {
        "from_account_id": from_id,
        "to_account_id": to_id,
        "amount_krw": amount,
        "request_id": str(uuid.uuid4()),
    }


# --- T20: 지급정지 (BFLA 안전 기준) -------------------------------------------

def test_t20_admin_can_freeze_account(secure_client, db_path):
    resp = secure_client.post(FREEZE_102, headers=TOKEN_ADMIN)
    assert resp.status_code == 200
    assert resp.json() == {"account_id": 102, "status": "FROZEN"}
    assert account_row(db_path, 102)["status"] == "FROZEN"
    assert len(audit_rows(db_path, "ACCOUNT_FROZEN")) == 1


def test_freeze_is_idempotent(secure_client, db_path):
    first = secure_client.post(FREEZE_102, headers=TOKEN_ADMIN)
    second = secure_client.post(FREEZE_102, headers=TOKEN_ADMIN)
    assert first.json() == second.json() == {"account_id": 102, "status": "FROZEN"}
    assert account_row(db_path, 102)["status"] == "FROZEN"


def test_t20_customer_token_cannot_freeze_and_state_is_unchanged(secure_client, db_path):
    resp = secure_client.post(FREEZE_102, headers=TOKEN_A)
    assert resp.status_code == 403
    assert account_row(db_path, 102)["status"] == "ACTIVE"
    denied = audit_rows(db_path, "ACCESS_DENIED")
    assert len(denied) == 1 and denied[0]["target_account_id"] == 102 and denied[0]["actor_user_id"] == 1


def test_customer_cannot_freeze_own_account_either(secure_client, db_path):
    assert secure_client.post("/api/admin/accounts/101/freeze", headers=TOKEN_A).status_code == 403
    assert account_row(db_path, 101)["status"] == "ACTIVE"


@pytest.mark.parametrize("headers", [{}, {"X-Demo-Token": "wrong-token"}])
def test_freeze_without_valid_token_is_401(secure_client, db_path, headers):
    assert secure_client.post(FREEZE_102, headers=headers).status_code == 401
    assert account_row(db_path, 102)["status"] == "ACTIVE"


def test_freeze_missing_account_is_404_only_for_admin(secure_client):
    # 없는 계좌 여부는 admin에게만 알려 준다(고객에게는 존재 여부와 무관하게 403).
    assert secure_client.post("/api/admin/accounts/999/freeze", headers=TOKEN_ADMIN).status_code == 404
    assert secure_client.post("/api/admin/accounts/999/freeze", headers=TOKEN_A).status_code == 403


def test_every_admin_route_requires_admin_by_default(secure_client):
    # 기본 거부: /api/admin 아래의 모든 라우트가 고객 토큰에 403이어야 한다.
    # 라우트 객체 구조는 FastAPI 버전에 따라 달라서 /openapi.json에서 경로·메서드를 읽는다.
    paths = secure_client.get("/openapi.json").json()["paths"]
    admin_paths = {p: ops for p, ops in paths.items() if p.startswith("/api/admin")}
    assert admin_paths, "관리 라우트가 하나도 없으면 이 테스트는 의미가 없다"
    for path, ops in admin_paths.items():
        for method in ops:
            resp = secure_client.request(method.upper(), path.replace("{account_id}", "102"), headers=TOKEN_A)
            assert resp.status_code == 403, f"{method.upper()} {path}"


# --- T21: 지급정지 계좌 출금 ---------------------------------------------------

def test_t21_transfer_from_frozen_account_is_409_and_db_unchanged(secure_client, db_path):
    secure_client.post("/api/admin/accounts/101/freeze", headers=TOKEN_ADMIN)
    resp = secure_client.post("/api/transfers", json=transfer_payload(), headers=TOKEN_A)
    assert resp.status_code == 409
    assert "지급정지" in resp.json()["detail"]
    assert account_row(db_path, 101)["balance_krw"] == 1_000_000
    assert account_row(db_path, 102)["balance_krw"] == 500_000
    conn = connect(db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM transfers").fetchone()[0] == 0
    finally:
        conn.close()
    rejected = audit_rows(db_path, "TRANSFER_REJECTED")
    assert len(rejected) == 1 and rejected[0]["http_status"] == 409


def test_unfrozen_neighbor_account_can_still_transfer(secure_client):
    secure_client.post("/api/admin/accounts/101/freeze", headers=TOKEN_ADMIN)  # A만 정지
    resp = secure_client.post("/api/transfers", json=transfer_payload(102, 103, 1_000), headers=TOKEN_B)
    assert resp.status_code == 201


# --- T22: 별칭 변경 (Mass Assignment 안전 기준) --------------------------------

def test_t22_owner_can_change_nickname(secure_client, db_path):
    resp = secure_client.patch("/api/accounts/101", json={"nickname": "생활비"}, headers=TOKEN_A)
    assert resp.status_code == 200
    assert resp.json() == {"id": 101, "account_no": "DEMO-101", "nickname": "생활비"}
    row = account_row(db_path, 101)
    assert (row["nickname"], row["balance_krw"], row["owner_user_id"], row["status"]) == (
        "생활비", 1_000_000, 1, "ACTIVE",
    )


def test_t22_changing_other_users_nickname_is_403_and_db_unchanged(secure_client, db_path):
    resp = secure_client.patch("/api/accounts/102", json={"nickname": "해킹"}, headers=TOKEN_A)
    assert resp.status_code == 403
    assert account_row(db_path, 102)["nickname"] is None


def test_nickname_change_missing_account_is_404_and_bad_token_is_401(secure_client):
    assert secure_client.patch("/api/accounts/999", json={"nickname": "x"}, headers=TOKEN_A).status_code == 404
    assert secure_client.patch("/api/accounts/101", json={"nickname": "x"}).status_code == 401
    assert secure_client.patch(
        "/api/accounts/101", json={"nickname": "x"}, headers={"X-Demo-Token": "wrong"}
    ).status_code == 401


@pytest.mark.parametrize(
    "extra",
    [
        {"balance_krw": 99_999_999},
        {"owner_user_id": 2},
        {"status": "ACTIVE"},
        {"account_no": "DEMO-999"},
        {"id": 5},
        {"role": "admin"},
    ],
)
def test_t22_extra_field_is_422_and_nothing_changes(secure_client, db_path, extra):
    secure_client.get("/api/accounts", headers=TOKEN_A)  # DB 초기화
    before = account_row(db_path, 101)
    resp = secure_client.patch("/api/accounts/101", json={"nickname": "생활비", **extra}, headers=TOKEN_A)
    assert resp.status_code == 422
    assert account_row(db_path, 101) == before


@pytest.mark.parametrize("nickname", ["", "x" * 21, 123, None, ["a"]])
def test_invalid_nickname_is_422(secure_client, db_path, nickname):
    secure_client.get("/api/accounts", headers=TOKEN_A)
    before = account_row(db_path, 101)
    resp = secure_client.patch("/api/accounts/101", json={"nickname": nickname}, headers=TOKEN_A)
    assert resp.status_code == 422
    assert account_row(db_path, 101) == before


def test_nickname_boundary_20_chars_is_accepted(secure_client):
    assert secure_client.patch("/api/accounts/101", json={"nickname": "가" * 20}, headers=TOKEN_A).status_code == 200


def test_empty_body_is_422(secure_client):
    assert secure_client.patch("/api/accounts/101", json={}, headers=TOKEN_A).status_code == 422
