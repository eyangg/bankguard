"""DET-01 시연 러너와 artifacts 저장소 테스트."""
from __future__ import annotations

import json

import pytest

from scanners import artifacts, det_runner


# --- DET-01 러너 (실제 격리 앱 + 실제 감사 로그) ----------------------------------------------------

def test_det01_runner_reproduces_t18_on_real_audit_log():
    result = det_runner.run_det01_check()
    assert result["status"] == "PASS"
    assert [s["http_status"] for s in result["steps"]] == [403, 403, 404]
    assert [s["alerts_after"] for s in result["steps"]] == [0, 0, 1]  # 2회까지 무경보, 3번째에 1건
    assert len(result["alerts"]) == 1 and result["alerts"][0]["distinct_accounts"] == 3
    assert result["controls"]["본인 계좌 조회"] == {"status": 200, "alerts": 0}
    assert result["controls"]["같은 계좌 5회 반복"]["alerts"] == 0
    assert "demo-token" not in json.dumps(result)  # 결과에 토큰 원문이 없다


def test_det01_runner_reports_fail_when_the_rule_does_not_fire(monkeypatch):
    monkeypatch.setattr(det_runner, "detect_account_enumeration", lambda *a, **k: [])
    result = det_runner.run_det01_check()
    assert result["status"] == "FAIL"  # 규칙이 안 울리면 PASS로 위장하지 않는다
    assert result["alerts"] == []


def test_det01_runner_reports_fail_when_the_rule_fires_too_early(monkeypatch):
    real = det_runner.detect_account_enumeration
    monkeypatch.setattr(det_runner, "detect_account_enumeration",
                        lambda conn, **k: real(conn, min_distinct_accounts=2))  # 임계값을 일부러 낮춘 규칙
    assert det_runner.run_det01_check()["status"] == "FAIL"


def test_det01_runner_turns_exceptions_into_error_without_leaking_details(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("C:\\secret\\path\\leak.py 내부 오류")

    monkeypatch.setattr(det_runner, "detect_account_enumeration", boom)
    result = det_runner.run_det01_check()
    assert result["status"] == "ERROR"
    assert "leak.py" not in json.dumps(result, ensure_ascii=False)


# --- artifacts 저장소 ---------------------------------------------------------------------------

def test_artifacts_roundtrip_uses_overridable_directory(tmp_path):
    saved = artifacts.save_json("sast", {"a": "한글", "n": 1}, tmp_path)
    assert saved.name == "latest_sast.json" and saved.parent == tmp_path
    assert artifacts.load_json("sast", tmp_path) == {"a": "한글", "n": 1}
    assert artifacts.load_json("det01", tmp_path) is None  # 없으면 None, 이전 결과를 꾸며내지 않는다


def test_default_directory_comes_from_environment_not_the_real_artifacts_folder(monkeypatch, tmp_path):
    assert artifacts.default_dir() != artifacts.ARTIFACTS_DIR  # 테스트는 실제 artifacts/를 건드리지 않는다
    monkeypatch.delenv(artifacts.ENV_DIR)
    assert artifacts.default_dir() == artifacts.ARTIFACTS_DIR


def test_artifacts_reject_unknown_kind_and_path_traversal(tmp_path):
    with pytest.raises(ValueError):
        artifacts.save_json("../evil", {}, tmp_path)
    for bad_name in ("../x.md", "a/b.md", "a\\b.md", ".hidden"):
        with pytest.raises(ValueError):
            artifacts.save_text(bad_name, "x", tmp_path)


def test_corrupted_json_is_treated_as_missing(tmp_path):
    (tmp_path / "latest_sast.json").write_text("{깨진 json", encoding="utf-8")
    assert artifacts.load_json("sast", tmp_path) is None


def test_load_bundle_marks_missing_kinds_as_none(tmp_path):
    artifacts.save_json("sast", {"x": 1}, tmp_path)
    bundle = artifacts.load_bundle(tmp_path)
    assert bundle["sast"] == {"x": 1} and bundle["api_secure"] is None
