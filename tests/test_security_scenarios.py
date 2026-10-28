"""SC-01·SC-05·SC-06 시나리오 판정 테스트 (DAY 3).

취약 비교 모드가 안전 기준을 어겨 FAIL이 나오는 것은 시연의 정상 기대치다(명세 12장).
여기서는 '러너가 실제 응답/DB 상태로 올바르게 FAIL·PASS·ERROR를 판정하는가'를 검증한다.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

import scanners.api_runner as api_runner
from backend.auth_demo import require_admin
from scanners.api_runner import run_api_scenarios
from scanners.models import ERROR, FAIL, PASS

DAY3_IDS = ["SC-01", "SC-05", "SC-06"]


def statuses(result):
    return {item.id: item.status for item in result.items}


def test_secure_mode_passes_all_day3_scenarios():
    result = run_api_scenarios("secure")
    assert [i.id for i in result.items] == DAY3_IDS
    assert statuses(result) == {"SC-01": PASS, "SC-05": PASS, "SC-06": PASS}


def test_vulnerable_mode_fails_all_day3_scenarios():
    result = run_api_scenarios("vulnerable")
    assert statuses(result) == {"SC-01": FAIL, "SC-05": FAIL, "SC-06": FAIL}


def test_result_dict_follows_common_model():
    data = run_api_scenarios("secure").to_dict()
    assert {"run_id", "run_at", "target", "mode", "total", "pass", "fail", "error", "skip", "items"} <= set(data)
    assert (data["mode"], data["total"], data["pass"], data["fail"], data["error"], data["skip"]) == (
        "secure", 3, 3, 0, 0, 0,
    )
    item = data["items"][0]
    for key in ("id", "name", "risk", "status", "expected", "observed", "description", "fix_guide",
                "evidence", "likelihood", "impact", "owasp", "cwe", "kr_weakness"):
        assert key in item
    assert data["items"][0]["owasp"] == "API1:2023" and data["items"][0]["cwe"] == "CWE-639"


def test_each_result_has_evidence_from_observed_behavior():
    for mode in ("secure", "vulnerable"):
        for item in run_api_scenarios(mode).items:
            assert item.observed and item.evidence
            assert "HTTP" in item.evidence  # 실제 응답 코드가 근거에 들어 있다


def test_verdict_depends_on_behavior_not_on_mode_name(monkeypatch):
    # 모드 이름이 'secure'여도 실제 동작이 취약하면 FAIL이어야 한다(모드명으로 결과를 정하지 않는다는 증거).
    real_create_app = api_runner.create_app

    def secure_name_with_lab_behavior(mode, db_path):
        app = real_create_app("vulnerable", db_path)
        app.state.mode = "secure"
        return app

    monkeypatch.setattr(api_runner, "create_app", secure_name_with_lab_behavior)
    result = run_api_scenarios("secure")
    assert statuses(result) == {"SC-01": FAIL, "SC-05": FAIL, "SC-06": FAIL}


def test_broken_positive_control_is_error_not_pass(monkeypatch):
    # 운영자 지급정지 기능 자체를 없애면(기능 고장) 고객 403이 '권한 검사 덕분'이라고 말할 수 없다 → ERROR.
    real_create_app = api_runner.create_app

    def app_with_broken_admin_feature(mode, db_path):
        app = real_create_app(mode, db_path)

        def broken():
            raise HTTPException(status_code=503, detail="관리 기능 고장(테스트용)")

        app.dependency_overrides[require_admin] = broken  # 운영자 요청도 실패하는 상태
        return app

    monkeypatch.setattr(api_runner, "create_app", app_with_broken_admin_feature)
    result = run_api_scenarios("secure", ["SC-05"])
    assert statuses(result) == {"SC-05": ERROR}
    assert "양성 대조" in result.items[0].observed


def test_unexpected_exception_becomes_error_without_stacktrace(monkeypatch):
    def boom(mode, db_path):
        raise RuntimeError("C:\\secret\\path\\leak.py 내부 오류")

    monkeypatch.setattr(api_runner, "create_app", boom)
    result = run_api_scenarios("secure", ["SC-01"])
    item = result.items[0]
    assert item.status == ERROR
    assert "leak.py" not in item.observed + item.evidence  # 로컬 경로·메시지 비노출
    assert "Traceback" not in item.observed + item.evidence


def test_runner_can_select_scenarios():
    assert [i.id for i in run_api_scenarios("secure", ["SC-06"]).items] == ["SC-06"]


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        run_api_scenarios("both")


def test_runs_are_repeatable():
    first = [statuses(run_api_scenarios("vulnerable")) for _ in range(3)]
    second = [statuses(run_api_scenarios("secure")) for _ in range(3)]
    assert all(s == first[0] for s in first) and all(s == second[0] for s in second)
