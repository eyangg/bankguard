"""의존성 취약점 점검(SCA) — pip-audit 실행·파싱.

- 점검 대상은 '이 실행기를 돌리는 앱 가상환경(.venv)에 실제로 설치된 패키지'다(간접 의존성 포함).
  pip-audit은 별도 가상환경(.venv-sca)에 두고, PIPAPI_PYTHON_LOCATION으로 앱 환경을 바깥에서 점검한다
  (같은 환경에 설치하면 pip-audit의 의존성 20개가 점검 대상에 섞인다).
- 실행 시 PyPI 취약점 DB를 인터넷으로 조회한다(패키지 이름·버전 전송). 그래서 대시보드의 '전체 검사'에는
  넣지 않는다(명세: 로컬에서 인터넷 없이 완전 시연 가능). 별도 명령과 CI에서만 실행한다.
- subprocess는 고정된 리스트 인자(shell=False)와 타임아웃으로만 실행한다. 사용자 입력을 받지 않는다.
- 결과는 pip-audit이 실제로 낸 JSON에서만 만든다. 미설치·실행 실패·네트워크 오류·JSON 오류는 SCAN_ERROR로,
  정상 완료 후 0건은 COMPLETED + vulnerability_count 0으로 구분한다(0건 ≠ 안전 보증: 알려진 취약점만 대상).

실행: .\\.venv\\Scripts\\python.exe -m scanners.sca_runner
종료 코드: 0 = 알려진 취약점 없음, 1 = 취약점 발견, 2 = 점검 불가(SCAN_ERROR)
"""
from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from backend.config import PROJECT_ROOT
from scanners import artifacts
from scanners.sast_runner import (
    BAD_JSON,
    COMPLETED,
    EXEC_FAILED,
    NOT_INSTALLED,
    SCAN_ERROR,
    TIMEOUT,
    _sanitize,
    utc_now_iso,
)

TOOL_NAME = "pip-audit"
TIMEOUT_SEC = 300
ENV_BIN = "BANKGUARD_PIP_AUDIT_BIN"
INSTALL_HINT = (
    "pip-audit이 설치되어 있지 않습니다. 앱과 분리된 가상환경에 설치하세요: "
    "py -3.12 -m venv .venv-sca ; .\\.venv-sca\\Scripts\\python.exe -m pip install -r requirements-sca.txt"
)
TARGET_LABEL = "앱 가상환경에 설치된 패키지(간접 의존성 포함)"


def find_pip_audit_bin() -> tuple[Path | None, str]:
    """(실행 파일 경로 또는 None, 찾은 방법/실패 사유). 순서: 환경변수 → .venv-sca → PATH."""
    configured = os.environ.get(ENV_BIN)
    if configured:
        path = Path(configured)
        if path.is_file():
            return path, f"환경변수 {ENV_BIN}"
        return None, f"환경변수 {ENV_BIN}가 가리키는 파일이 없습니다"
    for candidate in (
        PROJECT_ROOT / ".venv-sca" / "Scripts" / "pip-audit.exe",
        PROJECT_ROOT / ".venv-sca" / "bin" / "pip-audit",
    ):
        if candidate.is_file():
            return candidate, ".venv-sca"
    found = shutil.which("pip-audit")
    if found:
        return Path(found), "PATH"
    return None, "찾지 못함"


def _base(target_python: str) -> dict:
    return {
        "tool": TOOL_NAME,
        "tool_version": None,
        "target": TARGET_LABEL,
        "target_python": f"Python {platform.python_version()}" if target_python == sys.executable else "지정된 인터프리터",
        "run_at": utc_now_iso(),
        "scan_status": SCAN_ERROR,
        "error_kind": None,
        "error_message": None,
        "dependency_count": 0,
        "vulnerability_count": 0,
        "vulnerable_packages": [],
        "skipped": [],
    }


def _error(result: dict, kind: str, message: str) -> dict:
    result.update(scan_status=SCAN_ERROR, error_kind=kind, error_message=message)
    return result


def parse_report(raw: dict) -> tuple[int, list[dict], list[dict]]:
    """pip-audit JSON → (점검한 패키지 수, 취약 패키지 목록, 건너뛴 패키지 목록). 같은 ID 중복은 하나로 센다."""
    dependencies = raw["dependencies"]
    vulnerable, skipped = [], []
    for dep in dependencies:
        if dep.get("skip_reason"):
            skipped.append({"name": dep.get("name"), "reason": dep["skip_reason"]})
            continue
        seen, vulns = set(), []
        for vuln in dep.get("vulns") or []:
            if vuln["id"] in seen:
                continue
            seen.add(vuln["id"])
            vulns.append({
                "id": vuln["id"],
                "fix_versions": list(vuln.get("fix_versions") or []),
                "aliases": list(vuln.get("aliases") or []),
            })
        if vulns:
            vulnerable.append({"name": dep["name"], "version": dep.get("version"), "vulns": vulns})
    return len(dependencies), vulnerable, skipped


def run_sca(target_python: str | None = None) -> dict:
    target_python = target_python or sys.executable
    result = _base(target_python)
    binary, note = find_pip_audit_bin()
    if binary is None:
        return _error(result, NOT_INSTALLED, f"{INSTALL_HINT} ({note})")

    env = {**os.environ, "PIPAPI_PYTHON_LOCATION": target_python, "PYTHONUTF8": "1"}
    try:
        version = subprocess.run([str(binary), "--version"], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=60, env=env, shell=False)
        result["tool_version"] = version.stdout.strip().removeprefix("pip-audit").strip() or None
        proc = subprocess.run(
            [str(binary), "--format", "json", "--progress-spinner", "off", "--skip-editable"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=TIMEOUT_SEC, env=env, shell=False, cwd=str(PROJECT_ROOT),
        )
    except subprocess.TimeoutExpired:
        return _error(result, TIMEOUT, f"pip-audit이 {TIMEOUT_SEC}초 안에 끝나지 않았습니다.")
    except OSError as exc:
        return _error(result, EXEC_FAILED, _sanitize(f"pip-audit 실행 실패: {exc}"))

    # 종료 코드 0 = 취약점 없음, 1 = 취약점 발견(둘 다 JSON 출력). 그 밖이나 JSON이 없으면 점검 실패다.
    try:
        raw = json.loads(proc.stdout)
        count, vulnerable, skipped = parse_report(raw)
    except (ValueError, KeyError, TypeError):
        hint = " (인터넷 연결이 필요합니다: PyPI 취약점 DB 조회)" if proc.returncode == 1 else ""
        return _error(result, BAD_JSON if proc.returncode in (0, 1) else EXEC_FAILED,
                      _sanitize(f"pip-audit 결과를 읽지 못했습니다(종료 코드 {proc.returncode}){hint}: {proc.stderr}"))
    if proc.returncode not in (0, 1):
        return _error(result, EXEC_FAILED, _sanitize(f"pip-audit 종료 코드 {proc.returncode}: {proc.stderr}"))

    result.update(
        scan_status=COMPLETED,
        dependency_count=count,
        vulnerable_packages=vulnerable,
        vulnerability_count=sum(len(p["vulns"]) for p in vulnerable),
        skipped=skipped,
    )
    return result


def summary_lines(result: dict) -> list[str]:
    if result["scan_status"] != COMPLETED:
        return [f"SCA 점검 불가 ({result['error_kind']}): {result['error_message']}"]
    lines = [f"SCA({TOOL_NAME} {result['tool_version']}): 패키지 {result['dependency_count']}개 점검, "
             f"알려진 취약점 {result['vulnerability_count']}건"]
    for pkg in result["vulnerable_packages"]:
        ids = ", ".join(f"{v['id']}(수정: {', '.join(v['fix_versions']) or '없음'})" for v in pkg["vulns"])
        lines.append(f"  - {pkg['name']} {pkg['version']}: {ids}")
    return lines


def main() -> int:
    result = run_sca()
    saved = artifacts.save_json("sca", result)
    for line in summary_lines(result):
        print(line)
    print(f"저장: {saved}")
    if result["scan_status"] != COMPLETED:
        return 2
    return 1 if result["vulnerability_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
