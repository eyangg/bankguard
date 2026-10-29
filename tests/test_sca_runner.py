"""SCA(pip-audit) 실행기 테스트.

단위 테스트의 pip-audit 출력은 파서를 검증하려는 '모양만 같은 가짜 입력'이다(화면·보고서 결과 아님).
실제 pip-audit은 인터넷이 필요해 기본 테스트에서는 돌리지 않는다. 실제 실행 기록은 README 검증 기록에 있다.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scanners import artifacts, report
from scanners import sca_runner as sca
from scanners.sast_runner import COMPLETED, SCAN_ERROR

FAKE_BIN = Path("pip-audit-fake")


class FakeProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def audit_json(*deps):
    return json.dumps({"dependencies": list(deps), "fixes": []})


def dep(name="fastapi", version="1.0", vulns=(), skip_reason=None):
    d = {"name": name, "version": version, "vulns": list(vulns)}
    if skip_reason:
        d = {"name": name, "skip_reason": skip_reason}
    return d


def vuln(vid, fix=("2.0",), aliases=()):
    return {"id": vid, "fix_versions": list(fix), "aliases": list(aliases), "description": "설명"}


@pytest.fixture()
def fake_audit(monkeypatch):
    """pip-audit 실행 파일과 subprocess.run을 가짜로 바꾸고 호출 인자를 기록한다."""
    calls = []
    monkeypatch.setattr(sca, "find_pip_audit_bin", lambda: (FAKE_BIN, "test"))

    def install(main_proc, version_proc=FakeProc("pip-audit 9.9.9\n")):
        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if isinstance(main_proc, BaseException) and "--version" not in cmd:
                raise main_proc
            return version_proc if "--version" in cmd else main_proc

        monkeypatch.setattr(sca.subprocess, "run", fake_run)
        return calls

    return install


def test_vulnerabilities_are_parsed_and_duplicate_ids_counted_once(fake_audit):
    fake_audit(FakeProc(audit_json(
        dep("pip", "25.0.1", [vuln("PYSEC-1", ("25.3",)), vuln("PYSEC-1", ("25.3",)), vuln("PYSEC-2", ("26.0",))]),
        dep("fastapi", "0.162.0"),
    ), returncode=1))
    result = sca.run_sca()
    assert result["scan_status"] == COMPLETED and result["tool_version"] == "9.9.9"
    assert result["dependency_count"] == 2 and result["vulnerability_count"] == 2
    assert result["vulnerable_packages"] == [{"name": "pip", "version": "25.0.1", "vulns": [
        {"id": "PYSEC-1", "fix_versions": ["25.3"], "aliases": []},
        {"id": "PYSEC-2", "fix_versions": ["26.0"], "aliases": []},
    ]}]


def test_zero_vulnerabilities_is_completed_not_error(fake_audit):
    fake_audit(FakeProc(audit_json(dep("fastapi"), dep("local-pkg", skip_reason="PyPI에 없음"))))
    result = sca.run_sca()
    assert (result["scan_status"], result["vulnerability_count"]) == (COMPLETED, 0)
    assert result["skipped"] == [{"name": "local-pkg", "reason": "PyPI에 없음"}]  # 건너뛴 패키지를 숨기지 않는다


def test_runs_with_fixed_args_without_shell_and_targets_the_app_interpreter(fake_audit):
    calls = fake_audit(FakeProc(audit_json()))
    sca.run_sca()
    cmd, kwargs = calls[-1]
    assert cmd == [str(FAKE_BIN), "--format", "json", "--progress-spinner", "off", "--skip-editable"]
    assert kwargs["shell"] is False and kwargs["timeout"] == sca.TIMEOUT_SEC
    assert kwargs["env"]["PIPAPI_PYTHON_LOCATION"] == sys.executable  # pip-audit 자신이 아니라 앱 환경을 점검


def test_offline_failure_is_scan_error_with_hint_not_zero_findings(fake_audit):
    fake_audit(FakeProc("", stderr="requests.exceptions.ConnectionError: pypi.org", returncode=1))
    result = sca.run_sca()
    assert result["scan_status"] == SCAN_ERROR and result["error_kind"] == "BAD_JSON"
    assert "인터넷 연결" in result["error_message"]
    assert result["vulnerability_count"] == 0 and result["vulnerable_packages"] == []


@pytest.mark.parametrize("proc, kind", [
    (subprocess.TimeoutExpired(cmd="pip-audit", timeout=1), "TIMEOUT"),
    (OSError("차단됨"), "EXEC_FAILED"),
    (FakeProc(audit_json(), returncode=2), "EXEC_FAILED"),
    (FakeProc("{깨진 json", returncode=0), "BAD_JSON"),
])
def test_tool_failures_are_scan_errors(fake_audit, proc, kind):
    fake_audit(proc)
    result = sca.run_sca()
    assert (result["scan_status"], result["error_kind"]) == (SCAN_ERROR, kind)


def test_not_installed_is_scan_error_with_install_hint(monkeypatch):
    monkeypatch.setattr(sca, "find_pip_audit_bin", lambda: (None, "찾지 못함"))
    result = sca.run_sca()
    assert result["error_kind"] == "NOT_INSTALLED" and "requirements-sca.txt" in result["error_message"]


def test_explicit_env_path_that_does_not_exist_is_not_silently_replaced(monkeypatch, tmp_path):
    monkeypatch.setenv(sca.ENV_BIN, str(tmp_path / "없음.exe"))
    assert sca.find_pip_audit_bin()[0] is None


@pytest.mark.parametrize("payload, code", [
    (audit_json(dep("pip", "1", [vuln("PYSEC-1")])), 1),
    (audit_json(dep("fastapi")), 0),
])
def test_cli_exit_codes_and_saved_result(fake_audit, capsys, payload, code):
    fake_audit(FakeProc(payload, returncode=code))
    assert sca.main() == code
    assert artifacts.load_json("sca")["scan_status"] == COMPLETED
    assert "SCA(pip-audit 9.9.9)" in capsys.readouterr().out


def test_cli_returns_2_when_scan_is_impossible(monkeypatch):
    monkeypatch.setattr(sca, "find_pip_audit_bin", lambda: (None, "찾지 못함"))
    assert sca.main() == 2


def test_sca_is_not_part_of_the_offline_full_check():
    import inspect

    from scanners import pipeline

    assert "sca_runner" not in inspect.getsource(pipeline)  # 대시보드 전체 검사는 인터넷 없이 동작해야 한다


# --- 보고서 ------------------------------------------------------------------------------

def _report_with(sca_result):
    bundle = {"api_vulnerable": None, "api_secure": None, "sast": None, "det01": None, "sca": sca_result}
    return report.build_report(bundle)


def test_report_shows_sca_findings_with_fix_versions():
    text = _report_with({"scan_status": COMPLETED, "tool": "pip-audit", "tool_version": "9.9.9", "run_at": "2026-10-29T01:00:00Z",
                         "target": sca.TARGET_LABEL, "dependency_count": 54, "vulnerability_count": 1, "skipped": [],
                         "vulnerable_packages": [{"name": "pip", "version": "25.0.1",
                                                  "vulns": [{"id": "PYSEC-1", "fix_versions": ["25.3"], "aliases": []}]}]})
    section = text.split("의존성 취약점 점검(SCA, pip-audit)")[1].split("## ")[0]
    assert "| pip | 25.0.1 | PYSEC-1 | 25.3 |" in section
    assert "패키지 54개 점검, 알려진 취약점 **1건**" in section


def test_report_says_not_run_when_sca_was_not_run():
    text = _report_with(None)
    section = text.split("의존성 취약점 점검(SCA, pip-audit)")[1].split("## ")[0]
    assert "미실행" in section and "scanners.sca_runner" in section
