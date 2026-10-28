"""CI 보안 게이트 테스트: 판정 로직(단위), 실제 Semgrep으로 의도적 실패 재현(통합), 워크플로 구조."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from backend.config import PROJECT_ROOT
from scanners import ci_gate, sast_runner as sr

SEMGREP_BIN, _NOTE = sr.find_semgrep_bin()
needs_semgrep = pytest.mark.skipif(SEMGREP_BIN is None, reason=f"Semgrep 미설치 — 통합 테스트 미실행 ({_NOTE})")

RULES = ["BG-SAST-001", "BG-SAST-002"]


def finding(file, rule, line=1):
    return {"file": file, "rule_id": rule, "line": line, "message": "검토 필요"}


def target(name, findings=(), status="COMPLETED"):
    return {"target": name, "scan_status": status, "finding_count": len(findings), "findings": list(findings),
            "error_message": None if status == "COMPLETED" else "원인"}


def good_sast():
    return {
        "rule_ids": RULES,
        "targets": [
            target("fixtures/code", [finding("fixtures/code/vulnerable_example.py", r) for r in RULES]),
            target("backend/services/insecure_lab.py"),
            target(ci_gate.BACKEND_TARGET),
        ],
    }


def secure_run(*statuses):
    return {"items": [{"id": f"SC-0{i}", "status": s, "observed": "관측", "tier": "core"} for i, s in enumerate(statuses, 1)]}


# --- 판정 로직 ---------------------------------------------------------------------------------

def test_gate_passes_when_everything_is_clean():
    ok, problems = ci_gate.evaluate_gate(good_sast(), secure_run("PASS", "PASS"))
    assert ok and problems == []


def test_gate_fails_on_new_finding_in_secure_code():
    sast = good_sast()
    sast["targets"][2] = target(ci_gate.BACKEND_TARGET, [finding("backend/routes.py", "BG-SAST-004", 12)])
    ok, problems = ci_gate.evaluate_gate(sast, secure_run("PASS"))
    assert not ok and any("BG-SAST-004" in p and "backend/routes.py:12" in p for p in problems)


def test_gate_fails_when_secure_code_scan_errored_instead_of_passing_silently():
    sast = good_sast()
    sast["targets"][2] = target(ci_gate.BACKEND_TARGET, status="SCAN_ERROR")
    ok, problems = ci_gate.evaluate_gate(sast, secure_run("PASS"))
    assert not ok and any("SCAN_ERROR" in p for p in problems)


def test_gate_fails_when_a_rule_stopped_detecting_the_vulnerable_sample():
    sast = good_sast()
    sast["targets"][0] = target("fixtures/code", [finding("fixtures/code/vulnerable_example.py", "BG-SAST-001")])
    ok, problems = ci_gate.evaluate_gate(sast, secure_run("PASS"))
    assert not ok and any("BG-SAST-002" in p and "망가졌을 수" in p for p in problems)


def test_gate_fails_on_false_positive_in_fixed_sample():
    sast = good_sast()
    sast["targets"][0]["findings"].append(finding("fixtures/code/fixed_example.py", "BG-SAST-001", 9))
    ok, problems = ci_gate.evaluate_gate(sast, secure_run("PASS"))
    assert not ok and any("오탐" in p for p in problems)


@pytest.mark.parametrize("bad_status", ["FAIL", "ERROR", "SKIP"])
def test_gate_fails_unless_every_secure_scenario_passes(bad_status):
    ok, problems = ci_gate.evaluate_gate(good_sast(), secure_run("PASS", bad_status))
    assert not ok and any(bad_status in p for p in problems)


def test_gate_fails_when_there_are_no_secure_results():
    ok, problems = ci_gate.evaluate_gate(good_sast(), {"items": []})
    assert not ok and any("결과가 없습니다" in p for p in problems)


def test_main_returns_nonzero_and_prints_reasons_on_failure(monkeypatch, capsys):
    sast = good_sast()
    sast.update({"rules_count": 2, "total_findings": 1, "scan_errors": 0})
    sast["targets"][2] = target(ci_gate.BACKEND_TARGET, [finding("backend/x.py", "BG-SAST-004")])
    monkeypatch.setattr(ci_gate.sast_runner, "run_sast", lambda: sast)
    monkeypatch.setattr(ci_gate, "run_api_checks", lambda mode: secure_run("PASS"))
    assert ci_gate.main() == 1
    out = capsys.readouterr().out
    assert "GATE FAIL" in out and "BG-SAST-004" in out


def test_main_returns_zero_on_success(monkeypatch, capsys):
    sast = good_sast()
    sast.update({"rules_count": 2, "total_findings": 2, "scan_errors": 0})
    monkeypatch.setattr(ci_gate.sast_runner, "run_sast", lambda: sast)
    monkeypatch.setattr(ci_gate, "run_api_checks", lambda mode: secure_run("PASS"))
    assert ci_gate.main() == 0
    assert "GATE PASS" in capsys.readouterr().out


# --- 실제 Semgrep으로 '의도적 실패'와 '실제 저장소 통과' ------------------------------------------------

@needs_semgrep
def test_gate_really_fails_when_a_bad_pattern_is_added_to_secure_code(tmp_path):
    bad = tmp_path / "bad_module.py"
    bad.write_text('API_SECRET = "DEMO_ONLY_NOT_A_REAL_SECRET"\n', encoding="utf-8")
    scanned = sr.scan_target(sr.SastTarget(ci_gate.BACKEND_TARGET, (str(tmp_path),)), SEMGREP_BIN)
    assert scanned["scan_status"] == sr.COMPLETED and scanned["finding_count"] == 1  # 실제 Semgrep이 탐지

    sast = good_sast()
    sast["targets"][2] = scanned
    ok, problems = ci_gate.evaluate_gate(sast, secure_run("PASS"))
    assert not ok and any("BG-SAST-004" in p for p in problems)


@needs_semgrep
def test_gate_passes_on_the_real_repository():
    assert ci_gate.main() == 0


# --- 워크플로 파일 구조 -----------------------------------------------------------------------------

@pytest.fixture(scope="module")
def workflow():
    path = PROJECT_ROOT / ".github" / "workflows" / "security-check.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_workflow_runs_on_push_and_pull_request_with_read_only_permissions(workflow):
    triggers = workflow.get("on", workflow.get(True))  # YAML 1.1에서 `on`이 True로 읽히는 경우 대비
    assert set(triggers) == {"push", "pull_request"}
    assert workflow["permissions"] == {"contents": "read"}


def test_workflow_installs_semgrep_in_a_separate_venv_and_points_the_runner_to_it(workflow):
    job = workflow["jobs"]["security-gate"]
    assert job["env"]["PYTHONUTF8"] == "1"
    assert job["env"]["BANKGUARD_SEMGREP_BIN"].endswith("/.venv-semgrep/bin/semgrep")
    runs = "\n".join(step.get("run", "") for step in job["steps"])
    assert "python -m venv .venv-semgrep" in runs and "requirements-sast.txt" in runs
    assert "pip install -r requirements.txt" in runs
    assert "semgrep" not in Path(PROJECT_ROOT / "requirements.txt").read_text(encoding="utf-8").replace("semgrep은", "")


def test_workflow_runs_pytest_then_the_gate(workflow):
    steps = workflow["jobs"]["security-gate"]["steps"]
    commands = [s["run"] for s in steps if "run" in s]
    assert commands.index("python -m pytest -q") < commands.index("python -m scanners.ci_gate")
    uses = [s["uses"] for s in steps if "uses" in s]
    assert any(u.startswith("actions/checkout@") for u in uses) and any(u.startswith("actions/setup-python@") for u in uses)
    python_step = next(s for s in steps if s.get("uses", "").startswith("actions/setup-python@"))
    assert python_step["with"]["python-version"] == "3.12"
