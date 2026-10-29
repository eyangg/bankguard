"""SC-07 인증 시도 횟수 제한 테스트.

안전 구현의 동작(잠금·만료·우회 시도·동시 요청)과 시나리오 판정 무결성을 실제 요청과 DB로 확인한다.
클라이언트 주소는 문서용 예약 대역(RFC 5737)이라 실제 주소가 아니다.
"""
from __future__ import annotations

import threading
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from backend import throttle
from backend.config import AUTH_MAX_FAILURES, AUTH_WINDOW_SECONDS
from scanners import api_runner
from scanners.api_runner import IsolatedEnv, run_api_scenarios
from scanners.models import ERROR, FAIL, PASS

ATTACKER = ("203.0.113.10", 50000)
OTHER = ("198.51.100.20", 50000)
WRONG = {"X-Demo-Token": "demo-token-wrong"}
VALID_A = {"X-Demo-Token": "demo-token-a"}


@pytest.fixture
def env():
    with IsolatedEnv("secure") as e:
        yield e


def client(env, address=ATTACKER) -> TestClient:
    return TestClient(env.app, raise_server_exceptions=False, client=address)


def fail_times(c: TestClient, n: int) -> list[int]:
    return [c.get("/api/accounts", headers=WRONG).status_code for _ in range(n)]


@pytest.fixture
def clock(monkeypatch):
    """throttle의 현재 시각을 테스트가 움직일 수 있게 한다."""
    state = {"now": throttle._now()}
    monkeypatch.setattr(throttle, "_now", lambda: state["now"])

    def advance(seconds: float) -> None:
        state["now"] += timedelta(seconds=seconds)

    return advance


# --- 안전 구현 동작 --------------------------------------------------------------------------

def test_locks_after_max_failures_and_rejects_even_the_valid_token(env):
    c = client(env)
    assert fail_times(c, AUTH_MAX_FAILURES) == [401] * AUTH_MAX_FAILURES
    locked = c.get("/api/accounts", headers=VALID_A)
    assert locked.status_code == 429  # 맞는 토큰이어도 잠금 중에는 검사하지 않는다
    assert int(locked.headers["Retry-After"]) == AUTH_WINDOW_SECONDS
    assert "demo-token" not in locked.text and "DEMO-101" not in locked.text  # 계좌 정보 미노출


def test_lock_is_per_client_address(env):
    fail_times(client(env), AUTH_MAX_FAILURES)
    assert client(env, OTHER).get("/api/accounts", headers=VALID_A).status_code == 200


def test_forwarded_for_header_cannot_dodge_the_lock(env):
    c = client(env)
    codes = [c.get("/api/accounts", headers={**WRONG, "X-Forwarded-For": f"10.0.0.{i}"}).status_code
             for i in range(AUTH_MAX_FAILURES + 2)]
    assert codes == [401] * AUTH_MAX_FAILURES + [429, 429]  # 요청자가 바꿀 수 있는 헤더는 신뢰하지 않는다


def test_successful_login_does_not_reset_the_failure_count(env):
    c = client(env)
    fail_times(c, AUTH_MAX_FAILURES - 1)
    assert c.get("/api/accounts", headers=VALID_A).status_code == 200  # 공격자의 '자기 정상 토큰' 섞기
    assert fail_times(c, 1) == [401]
    assert c.get("/api/accounts", headers=WRONG).status_code == 429  # 섞어도 5번째 실패에서 잠긴다


def test_successful_requests_are_not_counted(env):
    c = client(env)
    for _ in range(AUTH_MAX_FAILURES * 2):
        assert c.get("/api/accounts", headers=VALID_A).status_code == 200
    assert env.query("SELECT COUNT(*) AS n FROM auth_attempts")[0]["n"] == 0  # 성공한 예약은 지워진다


def test_lock_expires_after_the_window(env, clock):
    c = client(env)
    fail_times(c, AUTH_MAX_FAILURES)
    clock(100)
    assert c.get("/api/accounts", headers=VALID_A).headers["Retry-After"] == str(AUTH_WINDOW_SECONDS - 100)
    clock(AUTH_WINDOW_SECONDS - 100 + 1)
    assert c.get("/api/accounts", headers=VALID_A).status_code == 200
    assert env.query("SELECT COUNT(*) AS n FROM auth_attempts")[0]["n"] == 0  # 창 밖 기록은 정리된다


def test_lock_and_failures_are_audited_without_raw_token(env):
    c = client(env)
    fail_times(c, AUTH_MAX_FAILURES)
    c.get("/api/accounts", headers=VALID_A)
    rows = env.query("SELECT event_type, http_status, token_fingerprint FROM audit_log ORDER BY id")
    assert [(r["event_type"], r["http_status"]) for r in rows] == \
        [("AUTH_FAIL", 401)] * AUTH_MAX_FAILURES + [("AUTH_LOCKED", 429)]
    assert all(r["token_fingerprint"] and "demo-token" not in r["token_fingerprint"] for r in rows)


def test_concurrent_guesses_cannot_exceed_the_limit(env):
    """동시에 몰아 보내도 토큰이 실제로 검사되는(401) 횟수는 제한을 넘지 않는다(시도 선예약)."""
    threads_n = 20
    barrier = threading.Barrier(threads_n, timeout=10)
    codes: list[int] = []
    lock = threading.Lock()

    def worker() -> None:
        c = client(env)
        barrier.wait()
        status = c.get("/api/accounts", headers=WRONG).status_code
        with lock:
            codes.append(status)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(threads_n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert len(codes) == threads_n
    assert codes.count(401) == AUTH_MAX_FAILURES
    assert codes.count(429) == threads_n - AUTH_MAX_FAILURES


def test_vulnerable_lab_has_no_limit():
    with IsolatedEnv("vulnerable", "SC-07") as lab:
        c = client(lab)
        assert fail_times(c, AUTH_MAX_FAILURES * 2) == [401] * (AUTH_MAX_FAILURES * 2)
        assert c.get("/api/accounts", headers=VALID_A).status_code == 200


# --- 시나리오 판정 무결성 ------------------------------------------------------------------------

def test_scenario_verdicts_from_real_responses():
    secure = run_api_scenarios("secure", ["SC-07"]).items[0]
    vulnerable = run_api_scenarios("vulnerable", ["SC-07"]).items[0]
    assert secure.status == PASS and "[401, 401, 401, 401, 401, 429, 429, 429]" in secure.evidence
    assert vulnerable.status == FAIL and "8번째 추측(실제 토큰)이 200으로 통과" in vulnerable.observed
    assert (secure.owasp, secure.cwe, secure.tier) == ("API2:2023", "CWE-307", "core")


def test_scenario_is_error_when_the_limit_wrongly_locks_normal_users(monkeypatch):
    monkeypatch.setattr(throttle, "AUTH_MAX_FAILURES", 1)  # 너무 엄격한 제한: 2번 틀린 정상 사용자가 잠김
    item = run_api_scenarios("secure", ["SC-07"]).items[0]
    assert item.status == ERROR and "양성 대조" in item.observed


def test_scenario_is_error_when_other_clients_are_locked_too(monkeypatch):
    monkeypatch.setattr(throttle, "client_key", lambda request: "everyone")  # 클라이언트 구분이 고장난 제한
    item = run_api_scenarios("secure", ["SC-07"]).items[0]
    assert item.status == ERROR  # 다른 사용자까지 막는 것은 '안전'이 아니라 고장이므로 PASS로 세지 않는다


def test_scenario_is_error_on_server_errors(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("내부 오류")

    monkeypatch.setattr(api_runner, "_SC07_GUESSES", ("demo-token-x",) * 8)
    monkeypatch.setattr(throttle, "release_attempt", boom)
    item = run_api_scenarios("secure", ["SC-07"]).items[0]
    assert item.status == ERROR
