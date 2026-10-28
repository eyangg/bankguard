"""DET-01 계좌 열거 의심 탐지 테스트 (T18 포함). 경보는 실제 audit_log 행으로만 만들어진다."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.audit import record
from backend.db import connect, init_db
from backend.detection import detect_account_enumeration

TOKEN_A = {"X-Demo-Token": "demo-token-a"}
TOKEN_B = {"X-Demo-Token": "demo-token-b"}
NOW = datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)


def alerts(db_path, **kwargs):
    conn = connect(db_path)
    try:
        return detect_account_enumeration(conn, **kwargs)
    finally:
        conn.close()


@pytest.fixture()
def conn(db_path):
    init_db(db_path)
    c = connect(db_path)
    yield c
    c.close()


def insert(conn, minutes_ago, target, actor=1, fp="fpA", event="ACCESS_DENIED"):
    """감사 로그 1행을 지정한 시각으로 직접 넣는다(창 경계 검증용). 실제 API 경로는 아래 T18 테스트가 검증."""
    created = (NOW - timedelta(minutes=minutes_ago)).isoformat(timespec="seconds").replace("+00:00", "Z")
    conn.execute(
        "INSERT INTO audit_log (created_at, event_type, actor_user_id, token_fingerprint, target_account_id,"
        " http_status, detail) VALUES (?, ?, ?, ?, ?, 403, 'test')",
        (created, event, actor, fp, target),
    )


# --- T18: 실제 API 호출 → 감사 로그 → 경보 -----------------------------------------------

def test_t18_two_distinct_accounts_do_not_alert_third_one_does(secure_client, db_path):
    secure_client.get("/api/accounts/102/transactions", headers=TOKEN_A)  # 403
    secure_client.get("/api/accounts/103/transactions", headers=TOKEN_A)  # 403
    assert alerts(db_path) == []  # 2회까지는 경보 없음

    secure_client.get("/api/accounts/999/transactions", headers=TOKEN_A)  # 404
    found = alerts(db_path)
    assert len(found) == 1  # 3번째에 경보 1건
    alert = found[0]
    assert (alert["rule_id"], alert["actor_user_id"], alert["distinct_accounts"]) == ("DET-01", 1, 3)
    assert alert["target_account_ids"] == [102, 103, 999]
    assert alert["event_count"] == 3


def test_alert_carries_token_fingerprint_not_raw_token(secure_client, db_path):
    for account in (102, 103, 999):
        secure_client.get(f"/api/accounts/{account}/transactions", headers=TOKEN_A)
    alert = alerts(db_path)[0]
    assert len(alert["token_fingerprint"]) == 12
    assert "demo-token-a" not in str(alert)


def test_normal_use_of_own_account_never_alerts(secure_client, db_path):
    for _ in range(10):
        secure_client.get("/api/accounts/101/transactions", headers=TOKEN_A)
        secure_client.get("/api/accounts", headers=TOKEN_A)
    assert alerts(db_path) == []


def test_repeating_the_same_foreign_account_is_not_enumeration(secure_client, db_path):
    for _ in range(6):
        secure_client.get("/api/accounts/102/transactions", headers=TOKEN_A)
    assert alerts(db_path) == []  # 서로 다른 계좌가 아니므로 경보 없음(재시도 오탐 완화)


def test_alerts_are_per_actor(secure_client, db_path):
    for account in (102, 103, 999):
        secure_client.get(f"/api/accounts/{account}/transactions", headers=TOKEN_A)
    secure_client.get("/api/accounts/101/transactions", headers=TOKEN_B)  # B: 403 한 번
    secure_client.get("/api/accounts/103/transactions", headers=TOKEN_B)  # B: 403 두 번째(서로 다른 계좌 2개)
    found = alerts(db_path)
    assert [a["actor_user_id"] for a in found] == [1]  # B는 임계값 미만


def test_failed_logins_alone_do_not_trigger_det01(secure_client, db_path):
    for _ in range(5):
        secure_client.get("/api/accounts", headers={"X-Demo-Token": "wrong"})  # AUTH_FAIL (계좌 ID 없음)
    assert alerts(db_path) == []


def test_transfer_attempts_from_foreign_accounts_count_too(secure_client, db_path):
    import uuid

    for account in (102, 103, 999):
        secure_client.post(
            "/api/transfers",
            json={"from_account_id": account, "to_account_id": 101, "amount_krw": 1000,
                  "request_id": str(uuid.uuid4())},
            headers=TOKEN_A,
        )
    assert len(alerts(db_path)) == 1


# --- 시간 창·임계값 (감사 로그에 시각을 지정해 넣어 검증) -----------------------------------------

def test_events_outside_the_window_are_ignored(conn):
    insert(conn, 10, 102)  # 창(5분) 밖
    insert(conn, 9, 103)  # 창 밖
    insert(conn, 1, 999)
    assert detect_account_enumeration(conn, now=NOW) == []  # 창 안에는 1개뿐


def test_window_boundary_is_inclusive_of_exactly_n_minutes(conn):
    insert(conn, 5, 102)
    insert(conn, 3, 103)
    insert(conn, 0, 999)
    assert len(detect_account_enumeration(conn, now=NOW)) == 1


def test_thresholds_are_configurable_parameters(conn):
    insert(conn, 1, 102)
    insert(conn, 1, 103)
    assert detect_account_enumeration(conn, now=NOW) == []
    assert len(detect_account_enumeration(conn, now=NOW, min_distinct_accounts=2)) == 1
    insert(conn, 30, 999)
    assert detect_account_enumeration(conn, now=NOW, window_minutes=60, min_distinct_accounts=3)[0]["distinct_accounts"] == 3


def test_alert_is_derived_only_from_audit_log_rows(conn):
    assert detect_account_enumeration(conn, now=NOW) == []  # 로그가 비어 있으면 경보도 없다
    record(conn, "TRANSFER_OK", 201, actor_user_id=1, token_fp="fpA", target_account_id=101)
    assert detect_account_enumeration(conn, now=NOW) == []  # 관련 없는 이벤트는 세지 않는다
