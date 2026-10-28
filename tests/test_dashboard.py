"""대시보드 테스트: 표시용 순수 함수 + Streamlit AppTest로 실제 버튼 동작 확인.

원칙: 화면의 PASS/FAIL 숫자는 코드에 박아 두지 않고, 실제 실행 결과(세션 상태)와 화면이 일치하는지 대조한다.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from frontend import helpers, services
from scanners import sast_runner as sr

APP = str(Path(__file__).resolve().parent.parent / "frontend" / "app.py")
SECURE_LABEL = helpers.MODE_LABELS["secure"]
VULNERABLE_LABEL = helpers.MODE_LABELS["vulnerable"]
NEEDS_SEMGREP = pytest.mark.skipif(
    sr.find_semgrep_bin()[0] is None, reason="Semgrep 미설치 — 대시보드 정적 분석 통합 테스트 미실행"
)


# --- 표시용 순수 함수 ----------------------------------------------------------------------

def test_format_krw():
    assert helpers.format_krw(1_000_000) == "1,000,000원"
    assert helpers.format_krw(0) == "0원"


def test_format_kst_converts_utc_to_korean_time():
    assert helpers.format_kst("2026-10-28T07:22:59Z") == "2026년 10월 28일 16:22:59 (KST)"
    assert helpers.format_kst("2026-10-28T20:00:00Z") == "2026년 10월 29일 05:00:00 (KST)"  # 날짜가 넘어가는 경우
    assert helpers.format_kst(None) == "-"


def test_status_labels_distinguish_fail_from_error():
    assert "FAIL" in helpers.status_label("FAIL") and "ERROR" not in helpers.status_label("FAIL")
    assert "ERROR" in helpers.status_label("ERROR")
    assert helpers.status_label("PASS") != helpers.status_label("FAIL")


def test_risk_text_shows_level_and_matrix_values():
    text = helpers.risk_text("HIGH", "L3", "I2")
    assert "HIGH" in text and "L3" in text and "I2" in text


def test_summarize_counts_only_present_items():
    items = [{"status": "PASS"}, {"status": "FAIL"}, {"status": "FAIL"}, {"status": "ERROR"}]
    assert helpers.summarize(items) == {"total": 4, "PASS": 1, "FAIL": 2, "ERROR": 1, "SKIP": 0}
    assert helpers.summarize([])["total"] == 0  # 항목이 없으면 '통과'로 보이지 않는다


def test_tier_items_defaults_to_core():
    items = [{"id": "a"}, {"id": "b", "tier": "detail"}, {"id": "c", "tier": "core"}]
    assert [i["id"] for i in helpers.tier_items(items, "core")] == ["a", "c"]
    assert [i["id"] for i in helpers.tier_items(items, "detail")] == ["b"]


def test_matrix_table_shows_korean_labels_for_detected_and_not_found():
    rows = [
        {"rule_id": "R1", "file": "d/a.py", "status": "DETECTED", "count": 2, "lines": [1, 2]},
        {"rule_id": "R1", "file": "d/b.py", "status": "NOT_FOUND", "count": 0, "lines": []},
    ]
    assert helpers.matrix_table(rows) == [{"규칙": "R1", "a.py": "탐지(2건)", "b.py": "미탐지(패턴 없음)"}]


def test_finding_rows_marks_every_row_as_needs_review():
    target = {"findings": [{"rule_id": "R1", "file": "f.py", "line": 3, "severity": "WARNING", "message": "m"}]}
    assert helpers.finding_rows(target) == [
        {"규칙": "R1", "파일": "f.py", "줄": 3, "심각도": "WARNING", "위험 설명": "m", "상태": "검토 필요"}
    ]


# --- 화면 (AppTest) --------------------------------------------------------------------------

@pytest.fixture()
def app(monkeypatch):
    # API 서버 실행 여부와 무관하게 같은 화면이 나오도록 실시간 조회를 고정한다.
    monkeypatch.setattr(services, "fetch_live_accounts", lambda *a, **k: None)
    at = AppTest.from_file(APP, default_timeout=120)
    at.run()
    assert not at.exception
    return at


def labels(at):
    return [e.label for e in at.expander]


def metric_value(at, label):
    return next(m.value for m in at.metric if m.label == label)


def test_four_tabs_are_present(app):
    assert [t.label for t in app.tabs] == ["① 개요", "② API 보안 테스트", "③ 정적 코드 분석", "④ 개선 비교·보고서"]
    assert "BANKGUARD" in app.title[0].value


def test_nothing_is_shown_as_pass_or_fail_before_running(app):
    # 실행 전에는 결과 카드가 하나도 없고(사이드바 도움말 제외) '미실행'을 알린다.
    assert labels(app) == ["결과 상태 읽는 법"]
    assert len([i for i in app.info if "아직 검사를 실행하지 않았습니다" in i.value]) >= 3
    assert not app.metric  # 숫자 카드도 없다


def test_overview_shows_seed_accounts_in_krw_when_api_is_off(app):
    table = app.dataframe[0].value.to_string()
    for expected in ("1,000,000원", "500,000원", "2,000,000원", "DEMO-101", "가상 운영자", "시드 초기값"):
        assert expected in table


def test_overview_uses_live_balances_when_api_answers(monkeypatch):
    monkeypatch.setattr(
        services, "fetch_live_accounts",
        lambda *a, **k: {1: [{"id": 101, "account_no": "DEMO-101", "balance_krw": 980_000}],
                         2: [{"id": 102, "account_no": "DEMO-102", "balance_krw": 520_000}],
                         3: [{"id": 103, "account_no": "DEMO-103", "balance_krw": 2_000_000}]},
    )
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    table = at.dataframe[0].value.to_string()
    assert "980,000원" in table and "520,000원" in table and "실시간(API)" in table


def test_compare_tab_is_honest_that_it_is_not_built_yet(app):
    assert any("DAY 7" in i.value for i in app.info)


def test_secure_run_shows_all_pass_matching_session_data(app):
    app.radio(key="api_mode").set_value(SECURE_LABEL).run()
    app.button(key="run_api").click().run()
    assert not app.exception
    result = app.session_state["api_results"]["secure"]
    assert [i["status"] for i in result["items"]] == ["PASS"] * 6
    assert metric_value(app, "핵심 검사") == "5"
    # 회귀 방지: ②탭에서 실행한 '그 클릭'에서 ①개요 요약도 바로 갱신돼야 한다(예전에는 한 번 늦게 갱신됨).
    assert [m.value for m in app.metric if m.label == "핵심"] == ["5"]
    assert metric_value(app, "보안 기준 통과") == "5"
    assert metric_value(app, "취약 동작 확인") == "0"
    cards = [l for l in labels(app) if l.startswith("SC-")]
    assert len(cards) == 6 and all("PASS" in c for c in cards)


def test_vulnerable_run_shows_fail_cards_expanded_with_evidence(app):
    app.radio(key="api_mode").set_value(VULNERABLE_LABEL).run()
    app.button(key="run_api").click().run()
    assert not app.exception
    result = app.session_state["api_results"]["vulnerable"]
    assert [i["status"] for i in result["items"]] == ["FAIL"] * 6
    assert metric_value(app, "취약 동작 확인") == "5"
    cards = [e for e in app.expander if e.label.startswith("SC-")]
    assert len(cards) == 6 and all("FAIL" in c.label for c in cards)
    assert all(c.proto.expanded for c in cards)  # FAIL 카드는 처음부터 펼쳐 보여 준다
    assert any("3,500,000→3,800,000" in e.value for e in app.error)  # 실제 관측 근거가 그대로 표시됨


def test_both_modes_are_kept_and_summarized_in_overview(app):
    for label in (VULNERABLE_LABEL, SECURE_LABEL):
        app.radio(key="api_mode").set_value(label).run()
        app.button(key="run_api").click().run()
    assert set(app.session_state["api_results"]) == {"vulnerable", "secure"}
    # 개요 탭: 모드별 요약 카드가 둘 다 생기고, 각각 실제 결과 건수와 일치한다(취약 5건 FAIL / 안전 5건 PASS).
    core_cards = [m for m in app.metric if m.label == "핵심"]
    assert [m.value for m in core_cards] == ["5", "5"]
    assert [m.value for m in app.metric if m.label == "취약"] == ["5", "0"]
    assert [m.value for m in app.metric if m.label == "통과"] == ["0", "5"]


def test_engine_exception_is_shown_as_error_not_as_fail_or_pass(app, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("C:\\secret\\path\\leak.py 내부 오류")

    monkeypatch.setattr(services, "run_api_checks", boom)
    app.button(key="run_api").click().run()
    assert not app.exception  # 앱이 죽지 않는다
    shown = " ".join(e.value for e in app.error)
    assert "ERROR" in shown and "보안 위반(FAIL)이 아닙니다" in shown
    assert "leak.py" not in shown  # 로컬 경로·내부 메시지는 화면에 노출하지 않는다
    assert not [l for l in labels(app) if l.startswith("SC-")]  # 가짜 결과 카드가 없다


def test_sast_not_installed_shows_scan_error_without_fake_results(app, monkeypatch, tmp_path):
    monkeypatch.setenv(sr.ENV_BIN, str(tmp_path / "missing-semgrep.exe"))
    app.button(key="run_sast").click().run()
    assert not app.exception
    errors = " ".join(e.value for e in app.error)
    assert "SCAN_ERROR" in errors and "NOT_INSTALLED" in errors and "requirements-sast.txt" in errors
    assert metric_value(app, "스캔 오류(SCAN_ERROR)") == "3"
    assert metric_value(app, "탐지(검토 필요)") == "0"
    assert len(app.dataframe) == 1  # 개요의 계좌 표뿐 — 탐지 표를 만들지 않는다


@NEEDS_SEMGREP
def test_sast_run_matches_session_data_and_shows_comparison(app):
    app.button(key="run_sast").click().run()
    assert not app.exception
    run = app.session_state["sast_run"]
    assert run["scan_errors"] == 0
    assert metric_value(app, "탐지(검토 필요)") == str(run["total_findings"])
    assert metric_value(app, "적용 규칙") == str(run["rules_count"]) == "4"
    finding_tables = [df for df in app.dataframe if "위험 설명" in df.value.columns]
    assert sum(len(df.value) for df in finding_tables) == run["total_findings"]  # 화면 행 수 = 실제 탐지 수
    shown = "\n".join(df.value.to_string() for df in finding_tables)
    assert "BG-SAST-001" in shown and "검토 필요" in shown
    matrix = next(df for df in app.dataframe if "vulnerable_example.py" in df.value.columns)
    assert set(matrix.value["fixed_example.py"]) == {"미탐지(패턴 없음)"}  # 수정 샘플은 전부 미탐지
    assert all(v.startswith("탐지(") for v in matrix.value["vulnerable_example.py"])
    assert any("0 findings" in i.value for i in app.info)  # backend(안전 코드)는 0건
