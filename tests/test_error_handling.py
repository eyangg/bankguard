"""오류 상황 대응 테스트 (T16, DB 잠김 — 명세 15장).

서버 응답에는 일반화된 메시지만 있어야 하고, 스택트레이스·로컬 경로·SQL·예외 메시지는 나가면 안 된다.
"""
from __future__ import annotations

import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from backend import repository
from backend.db import connect
from backend.factory import create_app

TOKEN_A = {"X-Demo-Token": "demo-token-a"}
SECRET_PATH = "C:\\Users\\aicam\\secret_dir\\bankguard.db"
LEAKY_MESSAGE = f"unable to open {SECRET_PATH}: SELECT * FROM users WHERE demo_token='demo-token-a' Traceback"
FORBIDDEN = ("Traceback", "secret_dir", "SELECT", "demo_token", "RuntimeError", "OperationalError", "File \"")


@pytest.fixture()
def crash_client(db_path):
    # 서버 예외를 응답으로 확인하려면 예외를 테스트로 다시 던지지 않는 클라이언트가 필요하다.
    app = create_app(mode="secure", db_path=db_path)
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


def assert_no_internal_details(response):
    text = response.text
    for forbidden in FORBIDDEN:
        assert forbidden not in text, f"응답에 내부 정보 노출: {forbidden}"


def test_t16_unexpected_exception_returns_generic_500_without_internals(crash_client, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError(LEAKY_MESSAGE)

    monkeypatch.setattr(repository, "list_accounts_for_user", explode)
    response = crash_client.get("/api/accounts", headers=TOKEN_A)
    assert response.status_code == 500
    assert response.json() == {"detail": "서버 내부 오류가 발생했습니다."}
    assert_no_internal_details(response)


def test_t16_database_error_other_than_lock_is_generic_500(crash_client, monkeypatch):
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError(f"no such table: accounts ({SECRET_PATH})")

    monkeypatch.setattr(repository, "list_accounts_for_user", broken)
    response = crash_client.get("/api/accounts", headers=TOKEN_A)
    assert response.status_code == 500
    assert "accounts" not in response.text  # 테이블 이름도 새지 않는다
    assert_no_internal_details(response)


def test_t16_error_details_go_to_server_log_not_to_client(crash_client, monkeypatch, caplog):
    monkeypatch.setattr(repository, "list_accounts_for_user", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(LEAKY_MESSAGE)))
    with caplog.at_level("ERROR", logger="bankguard.api"):
        response = crash_client.get("/api/accounts", headers=TOKEN_A)
    assert_no_internal_details(response)
    assert any("secret_dir" in (r.exc_text or "") for r in caplog.records)  # 개발자가 볼 수 있게 서버 로그에는 남는다


def test_error_response_has_no_server_header_with_traceback(crash_client, monkeypatch):
    monkeypatch.setattr(repository, "list_accounts_for_user", lambda *a, **k: (_ for _ in ()).throw(RuntimeError(LEAKY_MESSAGE)))
    response = crash_client.get("/api/accounts", headers=TOKEN_A)
    assert all("Traceback" not in v and "secret_dir" not in v for v in response.headers.values())


def test_database_lock_is_reported_as_503_retry_later_and_changes_nothing(db_path, monkeypatch):
    import backend.auth_demo as auth_demo

    app = create_app(mode="secure", db_path=db_path)
    real_connect = auth_demo.connect

    def short_timeout_connect(path):
        conn = real_connect(path)
        conn.execute("PRAGMA busy_timeout = 150")  # 잠금 대기를 0.15초로 줄여 테스트를 빠르게
        return conn

    monkeypatch.setattr(auth_demo, "connect", short_timeout_connect)
    with TestClient(app, raise_server_exceptions=False) as client:
        client.get("/api/accounts", headers=TOKEN_A)  # DB 초기화
        holder = connect(db_path)
        holder.execute("BEGIN IMMEDIATE")  # 다른 프로세스가 쓰기 잠금을 쥐고 있는 상황
        try:
            response = client.post(
                "/api/transfers",
                json={"from_account_id": 101, "to_account_id": 102, "amount_krw": 20_000,
                      "request_id": str(uuid.uuid4())},
                headers=TOKEN_A,
            )
        finally:
            holder.execute("ROLLBACK")
            holder.close()

    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert "일시적으로 사용 중" in response.json()["detail"]
    assert "locked" not in response.text.lower()
    verify = connect(db_path)
    try:
        assert verify.execute("SELECT balance_krw FROM accounts WHERE id = 101").fetchone()[0] == 1_000_000
        assert verify.execute("SELECT COUNT(*) FROM transfers").fetchone()[0] == 0
    finally:
        verify.close()


def test_normal_http_errors_are_not_swallowed_by_generic_handler(secure_client):
    assert secure_client.get("/api/accounts").status_code == 401
    assert secure_client.get("/api/accounts/999/transactions", headers=TOKEN_A).status_code == 404
    assert secure_client.post("/api/transfers", json={}, headers=TOKEN_A).status_code == 422
