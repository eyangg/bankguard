"""수정 전후 비교(FAIL→PASS 집계)와 SAST ↔ 동적 테스트 비교표 테스트."""
from __future__ import annotations

import pytest

from scanners import compare
from scanners.compare import (
    CHECK_INEFFECTIVE, IMPROVED, MISSING, NOT_IMPROVED, REGRESSED, UNDETERMINED, classify, compare_runs, coverage_rows,
)


def item(sid, status, tier="core"):
    return {"id": sid, "name": f"{sid} 이름", "tier": tier, "risk": "HIGH", "status": status}


def run(*items):
    return {"items": list(items)}


# --- 개선 판정 ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "vulnerable,secure,expected",
    [
        ("FAIL", "PASS", IMPROVED),
        ("FAIL", "FAIL", NOT_IMPROVED),
        ("PASS", "PASS", CHECK_INEFFECTIVE),
        ("PASS", "FAIL", REGRESSED),
        ("ERROR", "PASS", UNDETERMINED),
        ("FAIL", "ERROR", UNDETERMINED),
        ("ERROR", "ERROR", UNDETERMINED),
        ("SKIP", "PASS", UNDETERMINED),
        (None, "PASS", MISSING),
        ("FAIL", None, MISSING),
        (None, None, MISSING),
    ],
)
def test_classify_counts_improvement_only_when_both_results_are_real(vulnerable, secure, expected):
    assert classify(vulnerable, secure) == expected


def test_compare_counts_only_real_fail_to_pass_in_core():
    comparison = compare_runs(
        run(item("SC-01", "FAIL"), item("SC-03", "FAIL"), item("SC-04", "ERROR"), item("SC-05", "FAIL"),
            item("SC-02", "FAIL", "detail")),
        run(item("SC-01", "PASS"), item("SC-03", "FAIL"), item("SC-04", "PASS"), item("SC-05", "PASS"),
            item("SC-02", "PASS", "detail")),
    )
    core = comparison["core"]
    assert core["total"] == 4
    assert core[IMPROVED] == 2  # SC-01, SC-05
    assert core[NOT_IMPROVED] == 1  # SC-03
    assert core[UNDETERMINED] == 1  # SC-04: 취약 버전이 ERROR면 개선으로 세지 않는다
    assert comparison["detail"]["total"] == 1 and comparison["detail"][IMPROVED] == 1  # 세부 테스트는 따로 집계
    assert comparison["has_both_runs"] is True


def test_missing_run_never_produces_improvement():
    only_vulnerable = compare_runs(run(item("SC-01", "FAIL")), None)
    assert only_vulnerable["core"][IMPROVED] == 0
    assert only_vulnerable["rows"][0]["outcome"] == MISSING
    assert only_vulnerable["has_both_runs"] is False
    assert compare_runs(None, None)["rows"] == []


def test_scenario_present_in_only_one_run_is_missing_not_improved():
    comparison = compare_runs(run(item("SC-01", "FAIL"), item("SC-03", "FAIL")), run(item("SC-01", "PASS")))
    outcomes = {r["id"]: r["outcome"] for r in comparison["rows"]}
    assert outcomes == {"SC-01": IMPROVED, "SC-03": MISSING}


# --- 좌표: 소스 위치 -----------------------------------------------------------------------

def test_symbol_line_ranges_finds_real_definitions_in_insecure_lab():
    path = compare.PROJECT_ROOT / compare.LAB_FILE
    ranges = compare.symbol_line_ranges(path, ("lab_list_account_transactions", "TransferInLoose"))
    assert len(ranges) == 2 and all(lo < hi for lo, hi in ranges)
    assert compare.symbol_line_ranges(path, ("no_such_symbol",)) == []


# --- SAST ↔ 동적 비교표 -------------------------------------------------------------------

def sast(lab_findings=(), fixture_findings=(), lab_status="COMPLETED", fixture_status="COMPLETED"):
    def finding(file, rule, line):
        return {"file": file, "rule_id": rule, "line": line}

    return {
        "targets": [
            {"target": "backend/services/insecure_lab.py", "scan_status": lab_status,
             "findings": [finding("backend/services/insecure_lab.py", r, l) for r, l in lab_findings]},
            {"target": "fixtures/code", "scan_status": fixture_status,
             "findings": [finding("fixtures/code/vulnerable_example.py", r, l) for r, l in fixture_findings]},
        ]
    }


def vuln_run(status="FAIL"):
    return run(*(item(s, status, "detail" if s == "SC-02" else "core")
                 for s in ("SC-01", "SC-02", "SC-03", "SC-04", "SC-05", "SC-06", "SC-07")))


def by_flaw(rows):
    return {r["flaw"]: r for r in rows}


def test_coverage_table_has_the_spec_rows_plus_sc07():
    rows = coverage_rows(vuln_run(), vuln_run("PASS"), sast())
    assert [r["flaw"] for r in rows] == [
        "BOLA(소유권 검사 누락)", "음수/0 금액 허용", "경쟁 조건(비원자적 차감)", "멱등성 미처리",
        "BFLA(역할 검사 누락)", "Mass Assignment(요청 키 그대로 반영)", "인증 시도 횟수 제한 없음",
        "SQL 문자열 조립", "금액 float",
    ]


def test_business_logic_flaws_are_dynamic_only_when_semgrep_finds_nothing_there():
    rows = by_flaw(coverage_rows(vuln_run(), vuln_run("PASS"), sast()))
    row = rows["경쟁 조건(비원자적 차감)"]
    assert row["dynamic"]["state"] == "REPRODUCED" and row["dynamic"]["label"] == "SC-03 · 취약 FAIL / 안전 PASS"
    assert row["semgrep"]["status"] == "NOT_DETECTED_NO_RULE"
    assert "동적 테스트만 탐지" in row["interpretation"]


def test_sc07_auth_limit_is_a_business_logic_flaw_without_a_rule():
    row = by_flaw(coverage_rows(vuln_run(), vuln_run("PASS"), sast()))["인증 시도 횟수 제한 없음"]
    assert row["dynamic"]["label"] == "SC-07 · 취약 FAIL / 안전 PASS"
    assert row["semgrep"]["status"] == "NOT_DETECTED_NO_RULE"


def test_unrelated_semgrep_finding_in_flaw_code_is_not_counted_as_detecting_the_flaw():
    # Mass Assignment 코드 안에서 SQL 조립(BG-SAST-001)이 탐지돼도 '이 결함을 탐지'한 것이 아니다.
    path = compare.PROJECT_ROOT / compare.LAB_FILE
    (lo, hi), *_ = compare.symbol_line_ranges(path, ("lab_update_account_nickname",))
    rows = by_flaw(coverage_rows(vuln_run(), vuln_run("PASS"), sast(lab_findings=[("BG-SAST-001", lo + 5)])))
    mass = rows["Mass Assignment(요청 키 그대로 반영)"]
    assert mass["semgrep"]["status"] == "UNRELATED_FINDING" and mass["semgrep"]["rules"] == ["BG-SAST-001"]
    assert "이 결함 자체는 잡지 못함" in mass["interpretation"]
    sql = rows["SQL 문자열 조립"]
    assert sql["semgrep"]["status"] == "DETECTED" and "정적 분석만 탐지" in sql["interpretation"]


def test_finding_outside_the_flaw_code_does_not_count():
    rows = by_flaw(coverage_rows(vuln_run(), vuln_run("PASS"), sast(lab_findings=[("BG-SAST-001", 1)])))
    assert rows["BOLA(소유권 검사 누락)"]["semgrep"]["status"] == "NOT_DETECTED_NO_RULE"
    assert rows["SQL 문자열 조립"]["semgrep"]["status"] == "NOT_DETECTED"  # 줄 1은 SQL 조립 코드 밖


def test_fixture_rules_are_detected_from_vulnerable_sample_only():
    rows = by_flaw(coverage_rows(None, None, sast(fixture_findings=[("BG-SAST-002", 46), ("BG-SAST-002", 47)])))
    assert rows["금액 float"]["semgrep"]["status"] == "DETECTED"
    assert "2건" in rows["금액 float"]["semgrep"]["label"]
    assert rows["금액 float"]["dynamic"]["state"] == "NO_SCENARIO"


def test_nothing_is_claimed_when_runs_are_missing():
    rows = by_flaw(coverage_rows(None, None, None))
    for row in rows.values():
        assert row["semgrep"]["status"] == "NOT_RUN"
    assert rows["BOLA(소유권 검사 누락)"]["dynamic"]["state"] == "NOT_RUN"
    assert "미실행" in rows["BOLA(소유권 검사 누락)"]["interpretation"]


def test_scan_error_is_not_reported_as_not_detected():
    rows = by_flaw(coverage_rows(vuln_run(), vuln_run("PASS"), sast(lab_status="SCAN_ERROR", fixture_status="SCAN_ERROR")))
    for row in rows.values():
        assert row["semgrep"]["status"] == "SCAN_ERROR"


def test_dynamic_check_that_passes_on_vulnerable_version_is_flagged_ineffective():
    rows = by_flaw(coverage_rows(vuln_run("PASS"), vuln_run("PASS"), sast()))
    assert rows["BOLA(소유권 검사 누락)"]["dynamic"]["state"] == "NOT_EFFECTIVE"
    assert "재현하지 못함" in rows["BOLA(소유권 검사 누락)"]["interpretation"]


def test_dynamic_error_is_undetermined():
    rows = by_flaw(coverage_rows(vuln_run("ERROR"), vuln_run("PASS"), sast()))
    assert rows["BOLA(소유권 검사 누락)"]["dynamic"]["state"] == "UNDETERMINED"
