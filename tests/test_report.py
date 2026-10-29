"""진단 보고서(Markdown) 생성 테스트. 입력은 실제 결과 dict이며, 실행하지 않은 부분은 '미실행'이어야 한다."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from scanners import artifacts, compare, report

FIXED_NOW = datetime(2026, 10, 28, 8, 0, 0, tzinfo=timezone.utc)


def item(sid, status, observed="관측", evidence="HTTP 근거", tier="core", **extra):
    base = {
        "id": sid, "name": f"{sid} 이름", "risk": "HIGH", "status": status, "expected": "기대", "observed": observed,
        "description": "설명", "fix_guide": "조치 방법", "evidence": evidence, "likelihood": "L3", "impact": "I3",
        "owasp": "API1:2023", "cwe": "CWE-639", "kr_weakness": "", "tier": tier,
    }
    base.update(extra)
    return base


def api(mode, *items):
    return {"mode": mode, "run_id": "r", "run_at": "2026-10-28T07:00:00Z", "items": list(items)}


def sast(findings=(), status="COMPLETED"):
    target = {"target": "backend/services/insecure_lab.py", "scan_status": status, "finding_count": len(findings),
              "findings": list(findings), "files_scanned": ["backend/services/insecure_lab.py"],
              "error_kind": None if status == "COMPLETED" else "NOT_INSTALLED",
              "error_message": None if status == "COMPLETED" else "설치 필요"}
    return {"semgrep_version": "1.182.1", "rules_count": 4, "rule_ids": ["BG-SAST-001"], "targets": [target],
            "total_findings": len(findings), "scan_errors": 0 if status == "COMPLETED" else 1}


def det01(status="PASS"):
    return {"rule_id": "DET-01", "status": status, "observed": "관측 문구", "expected": "기대 문구",
            "evidence": "근거 문구", "steps": [{"step": 1, "request": "GET /x", "http_status": 403, "alerts_after": 0}],
            "alerts": [], "controls": {}, "run_at": "2026-10-28T07:00:00Z"}


def full_bundle():
    return {
        "api_vulnerable": api("vulnerable", item("SC-01", "FAIL", observed="200 데이터 반환"), item("SC-03", "FAIL"),
                              item("SC-02", "FAIL", tier="detail")),
        "api_secure": api("secure", item("SC-01", "PASS", observed="403"), item("SC-03", "ERROR"),
                          item("SC-02", "PASS", tier="detail")),
        "sast": sast([{"rule_id": "BG-SAST-001", "file": "backend/services/insecure_lab.py", "line": 140,
                       "severity": "WARNING", "message": "SQL 조립 | 검토 필요"}]),
        "det01": det01(),
    }


def test_report_contains_required_columns_and_sections():
    text = report.build_report(full_bundle(), FIXED_NOW)
    assert text.startswith("# BankGuard 보안 진단 보고서")
    for heading in ("## 0. 진단 개요", "## 1. 요약", "## 2. 점검 항목 결과", "## 3. 항목별 상세",
                    "## 4. 정적 분석(Semgrep) 결과", "## 5. SAST ↔ 동적 테스트 탐지 범위 비교",
                    "## 6. 감사 로그 기반 탐지", "## 7. 의존성 취약점 점검(SCA", "## 8. 한계와 주의"):
        assert heading in text
    for column in ("점검 항목", "위험도(L×I)", "취약 여부(취약 버전)", "이행점검(안전 버전 재검증)", "개선 판정", "매핑"):
        assert column in text
    assert "2026-10-28 17:00:00 KST" in text  # KST 변환


def test_report_counts_improvement_only_for_real_fail_to_pass():
    text = report.build_report(full_bundle(), FIXED_NOW)
    # SC-01만 FAIL→PASS, SC-03은 안전 버전이 ERROR라서 개선으로 세지 않는다.
    assert "핵심 시나리오 2개 중 **1개에서 개선 확인" in text
    assert "판정 불가 1개" in text
    row = next(l for l in text.splitlines() if l.startswith("| SC-03 "))
    assert "취약(재현됨)" in row and "판정 불가(ERROR)" in row
    assert compare.OUTCOME_LABELS[compare.UNDETERMINED] in row  # 개선으로 세지 않고 '판정 불가'로 둔다


def test_report_separates_detail_tests_from_core_summary():
    text = report.build_report(full_bundle(), FIXED_NOW)
    assert "### SC-02 · SC-02 이름 (세부 테스트)" in text
    table_rows = [l for l in text.split("## 3.")[0].splitlines() if l.startswith("| SC-")]
    assert not any(l.startswith("| SC-02") for l in table_rows)  # 핵심 표에는 SC-02가 없다


def test_report_escapes_pipes_and_newlines_in_table_cells():
    text = report.build_report(full_bundle(), FIXED_NOW)
    line = next(l for l in text.splitlines() if "BG-SAST-001" in l and "insecure_lab.py:140" in l)
    assert "SQL 조립 \\| 검토 필요" in line  # 파이프가 표를 깨지 않는다
    assert report._cell("a\nb | c") == "a b \\| c"


def test_report_with_nothing_run_says_not_run_and_invents_nothing():
    text = report.build_report({"api_vulnerable": None, "api_secure": None, "sast": None, "det01": None}, FIXED_NOW)
    assert "결과가 없어 수정 전후를 비교할 수 없습니다" in text
    assert text.count("미실행") >= 4
    assert "개선 확인(FAIL→PASS)" not in text
    assert "PASS" not in text.split("## 7.")[0].replace("FAIL→PASS", "")  # 실행 안 했는데 PASS/FAIL 문구가 없다


def test_report_with_only_vulnerable_run_does_not_claim_remediation():
    bundle = {"api_vulnerable": api("vulnerable", item("SC-01", "FAIL")), "api_secure": None, "sast": None, "det01": None}
    text = report.build_report(bundle, FIXED_NOW)
    assert "안전 버전 결과가 없어" in text
    row = next(l for l in text.splitlines() if l.startswith("| SC-01 "))
    assert "취약(재현됨)" in row and "미실행" in row and "비교 불가(결과 없음)" in row


def test_report_states_limits_and_does_not_overclaim():
    text = report.build_report(full_bundle(), FIXED_NOW)
    assert "정의된 검사 범위 내" in text and "CVSS 인증 점수가 아님" in text
    assert "모든 취약점이 제거" not in text.replace("제거되었다는 뜻이 아닙니다", "")
    assert "검토 필요" in text


def test_report_shows_sast_scan_error_instead_of_zero_findings():
    bundle = full_bundle()
    bundle["sast"] = sast(status="SCAN_ERROR")
    text = report.build_report(bundle, FIXED_NOW)
    assert "스캔 오류(NOT_INSTALLED)" in text and "설치 필요" in text


# --- CLI --------------------------------------------------------------------------------------

def test_cli_from_artifacts_requires_saved_results(capsys):
    assert report.main(["--from-artifacts"]) == 2  # 저장된 결과가 없으면 가짜 보고서를 만들지 않는다
    assert "저장된 검사 결과가 없습니다" in capsys.readouterr().err


def test_cli_from_artifacts_builds_report_from_saved_json(capsys):
    for kind, data in zip(artifacts.KINDS, (full_bundle()[k] for k in ("api_vulnerable", "api_secure", "sast", "det01"))):
        artifacts.save_json(kind, data)
    assert report.main(["--from-artifacts"]) == 0
    saved = artifacts.default_dir() / "diagnosis_report.md"
    assert saved.is_file() and "개선 확인" in saved.read_text(encoding="utf-8")
    assert json.loads((artifacts.default_dir() / "coverage_matrix.json").read_text(encoding="utf-8"))  # 비교표 JSON도 저장


def test_cli_full_run_saves_every_result_then_builds_report(monkeypatch):
    from scanners import pipeline

    bundle = full_bundle()
    monkeypatch.setattr(pipeline, "run_full_check", lambda progress=None: (progress and progress(1, 1, "완료")) or bundle)
    assert report.main([]) == 0
    directory = artifacts.default_dir()
    assert {p.name for p in directory.iterdir()} >= {
        "latest_api_vulnerable.json", "latest_api_secure.json", "latest_sast.json", "latest_det01.json",
        "diagnosis_report.md", "coverage_matrix.json",
    }
