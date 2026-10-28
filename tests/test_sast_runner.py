"""sast_runner 파서·경계 조건 단위 테스트 (Semgrep 없이 실행).

주의: 여기서 쓰는 Semgrep 출력은 파서를 검증하려는 '모양만 같은 가짜 입력'이다. 화면·보고서의 결과가 아니며,
실제 Semgrep을 돌린 결과는 tests/test_sast_rules.py(통합 테스트)에서 검증한다.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from backend.config import PROJECT_ROOT
from scanners import sast_runner as sr

TARGET = sr.SastTarget("t", ("fixtures/code",), ("insecure_lab.py",))
FAKE_BIN = Path("semgrep-fake")


class FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def semgrep_json(results=None, errors=None, scanned=("fixtures/code/a.py",), version="9.9.9"):
    return json.dumps(
        {"version": version, "results": results or [], "errors": errors or [], "paths": {"scanned": list(scanned)}}
    )


def raw_result(check_id="rules.BG-SAST-001", path="fixtures\\code\\a.py", line=7, end=8, message="  메시지\n  두 줄  ",
               severity="WARNING", cwe=("CWE-89: x",)):
    return {
        "check_id": check_id, "path": path, "start": {"line": line}, "end": {"line": end},
        "extra": {"message": message, "severity": severity, "metadata": {"cwe": list(cwe)}, "lines": "requires login"},
    }


@pytest.fixture()
def run_returns(monkeypatch):
    """subprocess.run을 가짜로 바꾸고 호출 인자를 기록한다."""
    calls = []

    def install(proc_or_exc):
        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if isinstance(proc_or_exc, BaseException):
                raise proc_or_exc
            return proc_or_exc

        monkeypatch.setattr(sr.subprocess, "run", fake_run)
        return calls

    return install


# --- 정상 파싱 -----------------------------------------------------------------------

def test_findings_are_normalized_from_semgrep_json(run_returns):
    run_returns(FakeProc(semgrep_json([raw_result()])))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert result["scan_status"] == sr.COMPLETED
    assert result["finding_count"] == 1
    finding = result["findings"][0]
    assert finding == {
        "rule_id": "BG-SAST-001",  # 경로 접두어 제거
        "file": "fixtures/code/a.py",  # 역슬래시 → 슬래시
        "line": 7,
        "end_line": 8,
        "severity": "WARNING",
        "message": "메시지 두 줄",  # 공백·개행 정리
        "cwe": ["CWE-89: x"],
        "review_status": "NEEDS_REVIEW",
    }
    assert result["semgrep_version"] == "9.9.9"


def test_absolute_path_inside_project_is_made_relative(run_returns):
    absolute = str(PROJECT_ROOT / "backend" / "x.py")
    run_returns(FakeProc(semgrep_json([raw_result(path=absolute)], scanned=[absolute])))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert result["findings"][0]["file"] == "backend/x.py"
    assert result["files_scanned"] == ["backend/x.py"]


def test_path_outside_project_exposes_only_file_name(run_returns):
    outside = str(Path(PROJECT_ROOT.anchor) / "elsewhere" / "secret_dir" / "leak.py")
    run_returns(FakeProc(semgrep_json([raw_result(path=outside)], scanned=[outside])))
    assert sr.scan_target(TARGET, FAKE_BIN)["findings"][0]["file"] == "leak.py"


def test_zero_findings_is_completed_not_error(run_returns):
    run_returns(FakeProc(semgrep_json([])))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert (result["scan_status"], result["finding_count"], result["error_kind"]) == (sr.COMPLETED, 0, None)


def test_findings_are_sorted_by_file_line_rule(run_returns):
    run_returns(FakeProc(semgrep_json([
        raw_result(line=9), raw_result(line=2, check_id="x.BG-SAST-003"), raw_result(line=2),
    ])))
    got = [(f["line"], f["rule_id"]) for f in sr.scan_target(TARGET, FAKE_BIN)["findings"]]
    assert got == [(2, "BG-SAST-001"), (2, "BG-SAST-003"), (9, "BG-SAST-001")]


def test_warning_level_errors_do_not_fail_the_scan(run_returns):
    run_returns(FakeProc(semgrep_json([], errors=[{"level": "warn", "type": "PartialParsing"}])))
    assert sr.scan_target(TARGET, FAKE_BIN)["scan_status"] == sr.COMPLETED


# --- SCAN_ERROR 경계 조건 --------------------------------------------------------------

def test_not_installed_is_scan_error_with_install_hint():
    result = sr.scan_target(TARGET, None, bin_note="찾지 못함")
    assert result["scan_status"] == sr.SCAN_ERROR
    assert result["error_kind"] == sr.NOT_INSTALLED
    assert "requirements-sast.txt" in result["error_message"]
    assert result["findings"] == [] and result["finding_count"] == 0


def test_timeout_is_scan_error(run_returns):
    run_returns(subprocess.TimeoutExpired(cmd="semgrep", timeout=120))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert (result["scan_status"], result["error_kind"]) == (sr.SCAN_ERROR, sr.TIMEOUT)


def test_os_error_is_scan_error_without_leaking_paths(run_returns):
    run_returns(PermissionError(13, "차단됨", str(PROJECT_ROOT / "secret" / "semgrep.exe")))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert (result["scan_status"], result["error_kind"]) == (sr.SCAN_ERROR, sr.EXEC_FAILED)
    assert str(PROJECT_ROOT) not in result["error_message"]
    assert "PermissionError" in result["error_message"]


def test_invalid_json_with_zero_exit_is_bad_json(run_returns):
    run_returns(FakeProc("이건 JSON이 아님", returncode=0))
    assert sr.scan_target(TARGET, FAKE_BIN)["error_kind"] == sr.BAD_JSON


def test_non_object_json_is_bad_json(run_returns):
    run_returns(FakeProc("[1, 2, 3]", returncode=0))
    assert sr.scan_target(TARGET, FAKE_BIN)["error_kind"] == sr.BAD_JSON


def test_empty_stdout_with_failure_exit_is_semgrep_error_and_stderr_is_sanitized(run_returns):
    stderr = f"\x1b[31mTraceback\x1b[0m File '{PROJECT_ROOT}\\.venv-semgrep\\x.py' UnicodeDecodeError cp949"
    run_returns(FakeProc("", stderr=stderr, returncode=2))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert (result["scan_status"], result["error_kind"]) == (sr.SCAN_ERROR, sr.SEMGREP_ERROR)
    assert str(PROJECT_ROOT) not in result["error_message"]
    assert "\x1b" not in result["error_message"]
    assert "<project>" in result["error_message"]


def test_nonzero_exit_with_valid_json_is_error_not_findings(run_returns):
    run_returns(FakeProc(semgrep_json([raw_result()]), returncode=2))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert result["scan_status"] == sr.SCAN_ERROR and result["findings"] == []


def test_error_level_entries_make_the_scan_an_error(run_returns):
    run_returns(FakeProc(semgrep_json([], errors=[{"level": "error", "message": "Invalid rule schema"}])))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert (result["scan_status"], result["error_kind"]) == (sr.SCAN_ERROR, sr.SEMGREP_ERROR)
    assert "Invalid rule schema" in result["error_message"]


def test_zero_scanned_files_is_error_not_clean(run_returns):
    run_returns(FakeProc(semgrep_json([], scanned=[])))
    result = sr.scan_target(TARGET, FAKE_BIN)
    assert (result["scan_status"], result["error_kind"]) == (sr.SCAN_ERROR, sr.NO_FILES)


def test_missing_rules_file_is_scan_error(tmp_path):
    result = sr.scan_target(TARGET, FAKE_BIN, rules_file=tmp_path / "nope.yml")
    assert (result["scan_status"], result["error_kind"]) == (sr.SCAN_ERROR, sr.RULES_MISSING)


# --- 실행 방식(보안 계약) -----------------------------------------------------------------

def test_command_is_a_list_without_shell_and_with_fixed_cwd_timeout(run_returns):
    calls = run_returns(FakeProc(semgrep_json([])))
    sr.scan_target(TARGET, FAKE_BIN)
    cmd, kwargs = calls[0]
    assert isinstance(cmd, list) and cmd[0] == str(FAKE_BIN)
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == PROJECT_ROOT
    assert kwargs["timeout"] == sr.TIMEOUT_SEC == 120
    assert kwargs["env"]["PYTHONUTF8"] == "1"  # UTF-8 규칙 파일을 cp949로 읽다 실패하는 문제 방지
    assert cmd[cmd.index("--config") + 1] == str(sr.RULES_FILE)
    assert "--json" in cmd and "--metrics=off" in cmd
    assert cmd[cmd.index("--exclude") + 1] == "insecure_lab.py"
    assert cmd[-1] == "fixtures/code"


def test_targets_are_fixed_constants():
    assert [t.name for t in sr.TARGETS] == [
        "fixtures/code", "backend/services/insecure_lab.py", "backend (insecure_lab.py 제외)",
    ]
    assert sr.TARGETS[2].excludes == ("insecure_lab.py",)
    # 이 모듈의 공개 함수는 경로 인자를 받지 않는다(사용자 입력을 셸·경로에 연결하지 않는다).
    import inspect

    assert list(inspect.signature(sr.run_sast).parameters) == ["target_names"]


# --- 실행 파일 탐색 순서 ----------------------------------------------------------------

def test_env_var_binary_has_priority(monkeypatch, tmp_path):
    fake = tmp_path / "semgrep-custom.exe"
    fake.write_text("")
    monkeypatch.setenv(sr.ENV_BIN, str(fake))
    path, note = sr.find_semgrep_bin()
    assert path == fake and sr.ENV_BIN in note


def test_env_var_pointing_to_missing_file_does_not_silently_fall_back(monkeypatch, tmp_path):
    monkeypatch.setenv(sr.ENV_BIN, str(tmp_path / "missing.exe"))
    path, note = sr.find_semgrep_bin()
    assert path is None and sr.ENV_BIN in note


def test_run_sast_reports_not_installed_for_every_target(monkeypatch, tmp_path):
    monkeypatch.setenv(sr.ENV_BIN, str(tmp_path / "missing.exe"))
    run = sr.run_sast()
    assert [t["scan_status"] for t in run["targets"]] == [sr.SCAN_ERROR] * 3
    assert {t["error_kind"] for t in run["targets"]} == {sr.NOT_INSTALLED}
    assert run["scan_errors"] == 3 and run["total_findings"] == 0


def test_run_sast_can_select_targets_by_name(run_returns, monkeypatch):
    run_returns(FakeProc(semgrep_json([])))
    monkeypatch.setattr(sr, "find_semgrep_bin", lambda: (FAKE_BIN, "test"))
    run = sr.run_sast(["fixtures/code"])
    assert [t["target"] for t in run["targets"]] == ["fixtures/code"]


def test_one_failing_target_does_not_stop_the_others(monkeypatch):
    monkeypatch.setattr(sr, "find_semgrep_bin", lambda: (FAKE_BIN, "test"))
    outcomes = iter([FakeProc(semgrep_json([raw_result()])), subprocess.TimeoutExpired("semgrep", 120), FakeProc(semgrep_json([]))])

    def fake_run(cmd, **kwargs):
        outcome = next(outcomes)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(sr.subprocess, "run", fake_run)
    run = sr.run_sast()
    assert [t["scan_status"] for t in run["targets"]] == [sr.COMPLETED, sr.SCAN_ERROR, sr.COMPLETED]
    assert (run["total_findings"], run["scan_errors"]) == (1, 1)


# --- 규칙 × 파일 표 ---------------------------------------------------------------------

def test_rule_matrix_marks_detected_and_not_found():
    result = {
        "scan_status": sr.COMPLETED,
        "files_scanned": ["fixtures/code/a.py", "fixtures/code/b.py"],
        "findings": [{"file": "fixtures/code/a.py", "rule_id": "BG-SAST-001", "line": 4}],
    }
    rows = sr.rule_matrix(result, ["BG-SAST-001", "BG-SAST-002"])
    got = {(r["file"], r["rule_id"]): (r["status"], r["lines"]) for r in rows}
    assert got[("fixtures/code/a.py", "BG-SAST-001")] == (sr.DETECTED, [4])
    assert got[("fixtures/code/a.py", "BG-SAST-002")] == (sr.NOT_FOUND, [])
    assert got[("fixtures/code/b.py", "BG-SAST-001")] == (sr.NOT_FOUND, [])


def test_rule_matrix_does_not_claim_not_found_when_scan_failed():
    rows = sr.rule_matrix({"scan_status": sr.SCAN_ERROR}, ["BG-SAST-001"])
    assert [r["status"] for r in rows] == [sr.SCAN_ERROR]


def test_rule_ids_are_read_from_the_rules_file():
    assert sr.rule_ids_in() == ["BG-SAST-001", "BG-SAST-002", "BG-SAST-003", "BG-SAST-004"]
