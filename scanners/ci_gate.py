"""CI 보안 게이트 (명세 DAY 7): `python -m scanners.ci_gate`

통과 조건(모두 만족해야 종료 코드 0)
1. 안전 코드(backend/, insecure_lab.py 제외)에서 Semgrep 탐지 0건이고 스캔이 정상 완료(SCAN_ERROR 아님).
2. 규칙이 조용히 망가지지 않았는지: 취약 샘플(fixtures)에서 모든 규칙이 실제로 탐지되고, 수정 샘플은 0건.
3. 안전 모드의 모든 핵심 시나리오가 PASS (FAIL/ERROR 하나라도 있으면 실패).
pytest는 워크플로의 별도 단계에서 실행한다. 도구가 없거나 오류가 나면 '통과'가 아니라 실패다.
"""
from __future__ import annotations

import sys

from scanners import sast_runner
from scanners.models import PASS
from scanners.pipeline import run_api_checks

BACKEND_TARGET = "backend (insecure_lab.py 제외)"
FIXTURE_TARGET = "fixtures/code"


def evaluate_gate(sast_run: dict, secure_run: dict) -> tuple[bool, list[str]]:
    """(통과 여부, 메시지 목록). 입력은 실제 실행 결과이고 이 함수는 판정만 한다."""
    problems: list[str] = []
    targets = {t["target"]: t for t in sast_run["targets"]}

    backend = targets.get(BACKEND_TARGET)
    if backend is None or backend["scan_status"] != sast_runner.COMPLETED:
        reason = backend["error_message"] if backend else "대상이 결과에 없음"
        problems.append(f"[SAST] 안전 코드 스캔이 정상 완료되지 않았습니다(SCAN_ERROR): {reason}")
    elif backend["finding_count"] > 0:
        for f in backend["findings"]:
            problems.append(f"[SAST] 안전 코드에서 신규 탐지: {f['rule_id']} {f['file']}:{f['line']} — {f['message']}")

    fixtures = targets.get(FIXTURE_TARGET)
    if fixtures is None or fixtures["scan_status"] != sast_runner.COMPLETED:
        problems.append("[SAST] 샘플 스캔이 정상 완료되지 않아 규칙이 동작하는지 확인할 수 없습니다.")
    else:
        detected = {f["rule_id"] for f in fixtures["findings"] if f["file"].endswith("vulnerable_example.py")}
        for rule_id in sast_run["rule_ids"]:
            if rule_id not in detected:
                problems.append(f"[SAST] 규칙 {rule_id}가 취약 샘플에서 탐지되지 않습니다(규칙이 망가졌을 수 있음).")
        for f in fixtures["findings"]:
            if f["file"].endswith("fixed_example.py"):
                problems.append(f"[SAST] 수정 샘플에서 오탐: {f['rule_id']} {f['file']}:{f['line']}")

    core = [i for i in secure_run["items"] if i.get("tier", "core") == "core"]
    if not core:
        problems.append("[동적] 안전 모드 핵심 시나리오 결과가 없습니다.")
    for item in core:
        if item["status"] != PASS:
            problems.append(f"[동적] 안전 모드 {item['id']} {item['status']}: {item['observed']}")

    return not problems, problems


def main() -> int:
    print("== BankGuard CI 보안 게이트 ==", flush=True)
    sast_run = sast_runner.run_sast()
    print(f"- 정적 분석: 규칙 {sast_run['rules_count']}개, 탐지 {sast_run['total_findings']}건, 스캔 오류 {sast_run['scan_errors']}건", flush=True)
    secure_run = run_api_checks("secure")
    counts = {s: sum(1 for i in secure_run["items"] if i["status"] == s) for s in ("PASS", "FAIL", "ERROR")}
    print(f"- 안전 모드 시나리오: PASS {counts['PASS']} / FAIL {counts['FAIL']} / ERROR {counts['ERROR']}", flush=True)

    ok, problems = evaluate_gate(sast_run, secure_run)
    if ok:
        print("GATE PASS")
        return 0
    print("GATE FAIL")
    for problem in problems:
        print(f"  - {problem}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
