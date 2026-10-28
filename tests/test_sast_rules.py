"""실제 Semgrep을 실행하는 통합 테스트 (규칙 유효성, 탐지/미탐지 샘플, 대상 3곳).

Semgrep이 없으면 이 파일의 테스트는 '통과'가 아니라 '건너뜀(미실행)'으로 보고된다.
기대값은 코드에 숫자로 박아 두지 않고 fixtures의 `# EXPECT: <규칙ID>` 표시와 대조한다.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

from backend.config import PROJECT_ROOT
from scanners import sast_runner as sr

SEMGREP_BIN, _NOTE = sr.find_semgrep_bin()
pytestmark = pytest.mark.skipif(SEMGREP_BIN is None, reason=f"Semgrep 미설치 — 통합 테스트 미실행 ({_NOTE})")

FIXTURES = PROJECT_ROOT / "fixtures" / "code"
LAB = PROJECT_ROOT / "backend" / "services" / "insecure_lab.py"


@pytest.fixture(scope="module")
def run():
    """고정 대상 3곳을 실제로 한 번 스캔한 결과(모듈 안에서 재사용)."""
    return sr.run_sast()


def target(run, name_prefix):
    return next(t for t in run["targets"] if t["target"].startswith(name_prefix))


def expect_markers(path: Path) -> set[tuple[str, str, int]]:
    markers = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        for rule in re.findall(r"# EXPECT: (BG-SAST-\d+)", line):
            markers.add((path.name, rule, number))
    return markers


# --- 규칙 파일 -----------------------------------------------------------------------------

def test_rules_file_is_valid_for_installed_semgrep_version():
    proc = subprocess.run(
        [str(SEMGREP_BIN), "scan", "--validate", "--config", str(sr.RULES_FILE), "--metrics=off", "--disable-version-check"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=120, shell=False, env={**os.environ, "PYTHONUTF8": "1"},
    )
    assert proc.returncode == 0, proc.stderr[-500:]
    assert "0 configuration error" in (proc.stdout + proc.stderr)


def test_at_least_four_finance_rules_are_defined(run):
    assert run["rules_count"] >= 4
    assert run["rule_ids"] == ["BG-SAST-001", "BG-SAST-002", "BG-SAST-003", "BG-SAST-004"]


def test_every_rule_has_a_must_detect_sample():
    covered = {rule for _, rule, _ in expect_markers(FIXTURES / "vulnerable_example.py")}
    assert covered == set(sr.rule_ids_in())


# --- 샘플: 탐지돼야 함 / 탐지되면 안 됨 ----------------------------------------------------------------

def test_scan_completed_without_errors(run):
    assert run["scan_errors"] == 0
    assert run["semgrep_version"]
    assert all(t["scan_status"] == sr.COMPLETED for t in run["targets"])


def test_fixture_findings_match_expect_markers_exactly(run):
    found = {
        (Path(f["file"]).name, f["rule_id"], f["line"]) for f in target(run, "fixtures")["findings"]
    }
    expected = expect_markers(FIXTURES / "vulnerable_example.py") | expect_markers(FIXTURES / "fixed_example.py")
    assert found == expected, f"놓침={sorted(expected - found)} 예상 밖={sorted(found - expected)}"


def test_fixed_sample_has_no_findings_for_any_rule(run):
    fixed = [f for f in target(run, "fixtures")["findings"] if f["file"].endswith("fixed_example.py")]
    assert fixed == []
    assert not expect_markers(FIXTURES / "fixed_example.py")  # 수정 샘플에는 EXPECT 표시가 없다


def test_both_fixture_files_were_actually_scanned(run):
    assert target(run, "fixtures")["files_scanned"] == [
        "fixtures/code/fixed_example.py", "fixtures/code/vulnerable_example.py",
    ]


def test_vulnerable_sample_is_reduced_to_zero_by_fixed_sample(run):
    matrix = sr.rule_matrix(target(run, "fixtures"), run["rule_ids"])
    detected = {(r["file"], r["rule_id"]) for r in matrix if r["status"] == sr.DETECTED}
    assert {rule for f, rule in detected if f.endswith("vulnerable_example.py")} == set(run["rule_ids"])
    assert not any(f.endswith("fixed_example.py") for f, _ in detected)


# --- 대상: 취약 구현 모듈 / 안전 코드 -------------------------------------------------------------------

def test_insecure_lab_only_sql_assembly_is_detected(run):
    lab = target(run, "backend/services/insecure_lab.py")
    lab_lines = LAB.read_text(encoding="utf-8").splitlines()
    assert [f["rule_id"] for f in lab["findings"]] == ["BG-SAST-001"]
    line = lab["findings"][0]["line"]
    assert 'f"UPDATE accounts SET {set_clause}' in lab_lines[line - 1]  # 탐지 위치가 실제 파일의 그 줄이다


def test_sast_does_not_detect_business_logic_flaws_in_insecure_lab(run):
    # 명세 8.1/8.6: 업무 로직 결함(BOLA·BFLA·경쟁 조건·멱등성·금액 검증 누락)은 소스 패턴 규칙으로 잡히지 않는다.
    # Semgrep 탐지는 SC-06의 동적 UPDATE 한 줄뿐이다. 이 사실이 SAST↔동적 테스트 비교표(DAY 7)의 근거가 된다.
    lab = target(run, "backend/services/insecure_lab.py")
    assert lab["finding_count"] == 1
    flagged_text = LAB.read_text(encoding="utf-8").splitlines()[lab["findings"][0]["line"] - 1]
    for flaw_marker in ("owner_user_id", "require_admin", "BEGIN IMMEDIATE", "uuid4", "amount_krw: int"):
        assert flaw_marker not in flagged_text


def test_secure_backend_has_no_findings_and_excludes_lab(run):
    backend = target(run, "backend (")
    assert backend["finding_count"] == 0 and backend["scan_status"] == sr.COMPLETED
    assert "backend/services/insecure_lab.py" not in backend["files_scanned"]
    assert {"backend/services/transfers.py", "backend/routes.py", "backend/db.py"} <= set(backend["files_scanned"])


# --- 출력 계약 ------------------------------------------------------------------------------------

def test_every_finding_has_location_rule_message_and_review_status(run):
    for t in run["targets"]:
        for f in t["findings"]:
            assert f["rule_id"].startswith("BG-SAST-")
            assert isinstance(f["line"], int) and f["line"] >= 1
            assert (PROJECT_ROOT / f["file"]).is_file()
            assert f["severity"] in {"INFO", "WARNING", "ERROR"}
            assert "검토 필요" in f["message"]
            assert f["cwe"] and f["cwe"][0].startswith("CWE-")
            assert f["review_status"] == "NEEDS_REVIEW"


def test_total_findings_is_sum_of_targets(run):
    assert run["total_findings"] == sum(t["finding_count"] for t in run["targets"])
    assert run["total_findings"] == len(
        [f for t in run["targets"] for f in t["findings"]]
    )


def test_scan_works_when_default_console_encoding_is_not_utf8(monkeypatch):
    # 한국어 Windows(cp949)에서 UTF-8 규칙 파일을 읽다 실패하던 문제의 회귀 방지:
    # 부모 프로세스에 PYTHONUTF8이 없어도 runner가 자식 프로세스에 설정해 준다.
    monkeypatch.delenv("PYTHONUTF8", raising=False)
    result = sr.scan_target(sr.TARGETS[1], SEMGREP_BIN)
    assert result["scan_status"] == sr.COMPLETED, result["error_message"]
