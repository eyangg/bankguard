"""시나리오 판정 테스트 (DAY 3 + DAY 4 + SC-07): 핵심 5종 + SC-07 + 세부 SC-02(T06·T07).

취약 비교 모드가 안전 기준을 어겨 FAIL이 나오는 것은 시연의 정상 기대치다(명세 12장).
여기서는 '러너가 실제 응답/DB 상태로 올바르게 FAIL·PASS·ERROR를 판정하는가'를 검증한다.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

import scanners.api_runner as api_runner
from backend.auth_demo import require_admin
from scanners.api_runner import IsolatedEnv, run_api_scenarios
from scanners.models import ERROR, FAIL, PASS

ALL_IDS = ["SC-01", "SC-03", "SC-04", "SC-05", "SC-06", "SC-07", "SC-02"]
CORE_IDS = ["SC-01", "SC-03", "SC-04", "SC-05", "SC-06", "SC-07"]


def statuses(result):
    return {item.id: item.status for item in result.items}


class FakeResponse:
    """서버 500 응답을 흉내 내는 최소 응답 객체."""

    status_code = 500

    def json(self):
        return {}


# --- 전체 판정 ---------------------------------------------------------------------

def test_secure_mode_passes_every_scenario():
    result = run_api_scenarios("secure")
    assert [i.id for i in result.items] == ALL_IDS
    assert set(statuses(result).values()) == {PASS}


def test_vulnerable_mode_fails_every_scenario():
    result = run_api_scenarios("vulnerable")
    assert [i.id for i in result.items] == ALL_IDS
    assert set(statuses(result).values()) == {FAIL}


def test_core_and_detail_tiers_follow_v12():
    tiers = {i.id: i.tier for i in run_api_scenarios("secure").items}
    assert [sid for sid, t in tiers.items() if t == "core"] == CORE_IDS
    assert [sid for sid, t in tiers.items() if t == "detail"] == ["SC-02"]


def test_result_dict_follows_common_model():
    data = run_api_scenarios("secure").to_dict()
    assert {"run_id", "run_at", "target", "mode", "total", "pass", "fail", "error", "skip", "items"} <= set(data)
    assert (data["mode"], data["total"], data["pass"], data["fail"], data["error"], data["skip"]) == (
        "secure", 7, 7, 0, 0, 0,
    )
    item = data["items"][0]
    for key in ("id", "name", "risk", "status", "expected", "observed", "description", "fix_guide",
                "evidence", "likelihood", "impact", "owasp", "cwe", "kr_weakness", "tier"):
        assert key in item
    assert (item["owasp"], item["cwe"]) == ("API1:2023", "CWE-639")


def test_each_result_has_evidence_from_observed_behavior():
    for mode in ("secure", "vulnerable"):
        for item in run_api_scenarios(mode).items:
            assert item.observed and item.evidence
            assert "HTTP" in item.evidence  # 실제 응답 코드가 근거에 들어 있다


def test_vulnerable_failures_are_explained_by_observed_state():
    items = {i.id: i for i in run_api_scenarios("vulnerable").items}
    assert "3,500,000→3,800,000" in items["SC-03"].observed  # 잔액 합 불일치
    assert "[201, 201]" in items["SC-03"].observed  # 두 요청 모두 201
    assert "재전송 HTTP 201" in items["SC-04"].observed  # 재전송이 새 거래
    assert "[-10000]" in items["SC-02"].evidence  # 음수 금액 송금 기록이 실제로 남음


# --- 판정이 모드 이름이 아니라 동작에 기반하는지 -------------------------------------------

def test_verdict_depends_on_behavior_not_on_mode_name(monkeypatch):
    # 모드 이름이 'secure'여도 실제 동작이 취약하면 FAIL이어야 한다(모드명으로 결과를 정하지 않는다는 증거).
    real_create_app = api_runner.create_app
    current = {"flaw": None}

    def secure_name_with_lab_behavior(mode, db_path, flaw=None):
        app = real_create_app("vulnerable", db_path, flaw=current["flaw"])
        app.state.mode = "secure"
        return app

    monkeypatch.setattr(api_runner, "create_app", secure_name_with_lab_behavior)
    for sid in ALL_IDS:
        current["flaw"] = sid
        assert statuses(run_api_scenarios("secure", [sid])) == {sid: FAIL}


def test_vulnerable_flaw_is_one_per_scenario():
    # SC-01 시나리오는 SC-01 결함만 붙은 앱에서 실행된다: 다른 결함이 섞이면 SC-05 같은 판정이 오염된다.
    with IsolatedEnv("vulnerable", "SC-01") as env:
        env.client.get("/api/accounts", headers=api_runner.TOKEN_A)  # DB 초기화
        # SC-01 결함 앱에서도 BFLA는 막혀 있어야 한다.
        assert env.client.post("/api/admin/accounts/102/freeze", headers=api_runner.TOKEN_A).status_code == 403
        # 그리고 Mass Assignment도 막혀 있어야 한다.
        resp = env.client.patch("/api/accounts/101", json={"nickname": "x", "balance_krw": 1}, headers=api_runner.TOKEN_A)
        assert resp.status_code == 422


# --- ERROR 분리: 결함 때문이 아닌 오류는 FAIL이 아니다 ---------------------------------------

def test_broken_positive_control_is_error_not_pass(monkeypatch):
    # 운영자 지급정지 기능 자체가 고장 나면 고객 403이 '권한 검사 덕분'이라고 말할 수 없다 → ERROR.
    real_create_app = api_runner.create_app

    def app_with_broken_admin_feature(mode, db_path, flaw=None):
        app = real_create_app(mode, db_path, flaw=flaw)

        def broken():
            raise HTTPException(status_code=503, detail="관리 기능 고장(테스트용)")

        app.dependency_overrides[require_admin] = broken  # 운영자 요청도 실패하는 상태
        return app

    monkeypatch.setattr(api_runner, "create_app", app_with_broken_admin_feature)
    result = run_api_scenarios("secure", ["SC-05"])
    assert statuses(result) == {"SC-05": ERROR}
    assert "양성 대조" in result.items[0].observed


@pytest.mark.parametrize("sid", ["SC-03", "SC-04", "SC-02"])
def test_failing_first_transfer_is_control_failure_error(monkeypatch, sid):
    monkeypatch.setattr(IsolatedEnv, "post_transfer", lambda self, *a, **k: FakeResponse())
    result = run_api_scenarios("vulnerable", [sid])
    assert statuses(result) == {sid: ERROR}
    assert "양성 대조" in result.items[0].observed


def test_sc04_server_error_on_replay_is_error_not_fail(monkeypatch):
    real = IsolatedEnv.post_transfer
    calls = {"n": 0}

    def flaky(self, *args, **kwargs):
        calls["n"] += 1
        return real(self, *args, **kwargs) if calls["n"] == 1 else FakeResponse()  # 첫 요청만 정상

    monkeypatch.setattr(IsolatedEnv, "post_transfer", flaky)
    result = run_api_scenarios("vulnerable", ["SC-04"])
    assert statuses(result) == {"SC-04": ERROR}
    assert "서버 오류" in result.items[0].observed


def test_sc02_server_error_is_error_not_fail(monkeypatch):
    real = IsolatedEnv.post_transfer

    def negative_crashes(self, token, from_id, to_id, amount, request_id=None):
        if amount < 0:
            return FakeResponse()  # 음수 요청은 500
        return real(self, token, from_id, to_id, amount, request_id)

    monkeypatch.setattr(IsolatedEnv, "post_transfer", negative_crashes)
    result = run_api_scenarios("secure", ["SC-02"])
    assert statuses(result) == {"SC-02": ERROR}


def test_sc03_server_errors_during_race_are_error_not_fail(monkeypatch):
    # 경쟁 구간에서 서버가 500을 내면(결함이 아닌 오류) FAIL로 단정하지 않고 ERROR로 분리한다.
    def always_crash(gate, target):
        def get_conn_that_crashes():
            raise RuntimeError("DB 연결 장애(테스트용)")

        return get_conn_that_crashes

    monkeypatch.setattr(api_runner, "make_racing_get_conn", always_crash)
    for mode in ("secure", "vulnerable"):
        result = run_api_scenarios(mode, ["SC-03"])
        assert statuses(result) == {"SC-03": ERROR}, mode
        assert "서버 오류" in result.items[0].observed


def test_unexpected_exception_becomes_error_without_stacktrace(monkeypatch):
    def boom(mode, db_path, flaw=None):
        raise RuntimeError("C:\\secret\\path\\leak.py 내부 오류")

    monkeypatch.setattr(api_runner, "create_app", boom)
    result = run_api_scenarios("secure", ["SC-01"])
    item = result.items[0]
    assert item.status == ERROR
    assert "leak.py" not in item.observed + item.evidence  # 로컬 경로·메시지 비노출
    assert "Traceback" not in item.observed + item.evidence


# --- 실행기 기본 동작 -----------------------------------------------------------------

def test_runner_can_select_scenarios():
    assert [i.id for i in run_api_scenarios("secure", ["SC-06"]).items] == ["SC-06"]


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        run_api_scenarios("both")


def test_runs_are_repeatable():
    first = [statuses(run_api_scenarios("vulnerable")) for _ in range(2)]
    second = [statuses(run_api_scenarios("secure")) for _ in range(2)]
    assert all(s == first[0] for s in first) and all(s == second[0] for s in second)


# --- SC-03: 20회 반복해도 결과가 같다 ---------------------------------------------------------

def _sc03_signature(mode: str):
    item = run_api_scenarios(mode, ["SC-03"]).items[0]
    return item.status, item.observed  # 응답 순서([201,409]/[409,201])는 스레드 도착 순서라 observed에 넣지 않는다


@pytest.mark.parametrize("mode,expected_status", [("secure", PASS), ("vulnerable", FAIL)])
def test_sc03_is_deterministic_over_20_runs(mode, expected_status):
    signatures = {_sc03_signature(mode) for _ in range(20)}
    assert len(signatures) == 1, f"20회 결과가 달라짐: {signatures}"
    assert next(iter(signatures))[0] == expected_status
