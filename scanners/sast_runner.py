"""Semgrep CE 실행·파싱 (명세 8.4).

- 대상·규칙 파일·실행 디렉터리는 모두 이 모듈의 상수로 고정한다. 사용자 입력을 받지 않는다.
- subprocess는 리스트 인자(shell=False)로만 실행하고 타임아웃을 둔다.
- 결과는 Semgrep이 실제로 낸 JSON에서만 만든다. 실행 실패·미설치·JSON 오류·타임아웃은 SCAN_ERROR로,
  정상 완료 후 발견 0건은 COMPLETED + finding_count 0으로 구분한다(탐지 0건 ≠ 안전 보증).
- Semgrep 실행 파일 탐색 순서(명세 3장): 환경변수 BANKGUARD_SEMGREP_BIN → .venv-semgrep → PATH.
- 정적 분석 결과는 '검토가 필요한 의심 항목(NEEDS_REVIEW)'이며 확정 취약점이 아니다.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from backend.config import PROJECT_ROOT

SCANNER_NAME = "semgrep-ce"
RULES_FILE = PROJECT_ROOT / "rules" / "bankguard.yml"
TIMEOUT_SEC = 120
ENV_BIN = "BANKGUARD_SEMGREP_BIN"

COMPLETED = "COMPLETED"
SCAN_ERROR = "SCAN_ERROR"

# error_kind: SCAN_ERROR의 세부 원인(UI에서 안내 문구를 고르는 데 쓴다)
NOT_INSTALLED = "NOT_INSTALLED"
EXEC_FAILED = "EXEC_FAILED"
TIMEOUT = "TIMEOUT"
BAD_JSON = "BAD_JSON"
SEMGREP_ERROR = "SEMGREP_ERROR"
NO_FILES = "NO_FILES_SCANNED"
RULES_MISSING = "RULES_MISSING"

DETECTED = "DETECTED"
NOT_FOUND = "NOT_FOUND"

INSTALL_HINT = (
    "Semgrep CE가 설치되어 있지 않습니다. 앱과 분리된 가상환경에 설치하세요: "
    "py -3.12 -m venv .venv-semgrep ; "
    ".\\.venv-semgrep\\Scripts\\python.exe -m pip install -r requirements-sast.txt"
)


@dataclass(frozen=True)
class SastTarget:
    name: str
    paths: tuple[str, ...]
    excludes: tuple[str, ...] = ()


# 검사 대상 3곳(명세 8.2 v1.1). 상수로 고정하며 사용자 입력으로 바꿀 수 없다.
TARGETS: tuple[SastTarget, ...] = (
    SastTarget("fixtures/code", ("fixtures/code",)),
    SastTarget("backend/services/insecure_lab.py", ("backend/services/insecure_lab.py",)),
    SastTarget("backend (insecure_lab.py 제외)", ("backend",), ("insecure_lab.py",)),
)

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def find_semgrep_bin() -> tuple[Path | None, str]:
    """(실행 파일 경로 또는 None, 찾은 방법/실패 사유)."""
    configured = os.environ.get(ENV_BIN)
    if configured:
        path = Path(configured)
        if path.is_file():
            return path, f"환경변수 {ENV_BIN}"
        # 사용자가 명시한 경로가 틀린 경우 조용히 다른 것을 쓰지 않는다.
        return None, f"환경변수 {ENV_BIN}가 가리키는 파일이 없습니다"
    for candidate in (
        PROJECT_ROOT / ".venv-semgrep" / "Scripts" / "semgrep.exe",
        PROJECT_ROOT / ".venv-semgrep" / "bin" / "semgrep",
    ):
        if candidate.is_file():
            return candidate, ".venv-semgrep"
    found = shutil.which("semgrep")
    if found:
        return Path(found), "PATH"
    return None, "찾지 못함"


def rule_ids_in(rules_file: Path = RULES_FILE) -> list[str]:
    """규칙 파일의 `- id:` 줄에서 규칙 ID를 읽는다(YAML 라이브러리 없이)."""
    text = rules_file.read_text(encoding="utf-8")
    return re.findall(r"^\s*-\s+id:\s*(\S+)\s*$", text, flags=re.MULTILINE)


def rule_catalog(rules_file: Path = RULES_FILE) -> list[dict]:
    """화면용 규칙 설명(ID·심각도·메시지·CWE). 규칙 파일이 단일 출처라 따로 복사해 두지 않는다."""
    import yaml

    data = yaml.safe_load(rules_file.read_text(encoding="utf-8"))
    return [
        {
            "rule_id": rule["id"],
            "severity": rule.get("severity"),
            "message": " ".join(str(rule.get("message", "")).split()),
            "cwe": list((rule.get("metadata") or {}).get("cwe") or []),
        }
        for rule in data["rules"]
    ]


def _sanitize(text: str, limit: int = 600) -> str:
    """오류 메시지에서 색상 코드와 로컬 경로를 지우고 끝부분만 남긴다."""
    text = _ANSI.sub("", text)
    for raw, label in ((str(PROJECT_ROOT), "<project>"), (str(Path.home()), "<home>")):
        text = text.replace(raw, label)
    return text.strip()[-limit:]


def _relative_posix(raw_path: str) -> str:
    path = Path(raw_path)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(PROJECT_ROOT.resolve())
        except ValueError:
            return path.name  # 프로젝트 밖 경로는 파일 이름만 노출
    return path.as_posix()


def _error_result(target: SastTarget, kind: str, message: str, **extra) -> dict:
    return {
        "scanner": SCANNER_NAME,
        "scan_status": SCAN_ERROR,
        "target": target.name,
        "paths": list(target.paths),
        "excludes": list(target.excludes),
        "finding_count": 0,
        "findings": [],
        "files_scanned": [],
        "semgrep_version": extra.get("semgrep_version"),
        "error_kind": kind,
        "error_message": message,
        "run_at": utc_now_iso(),
    }


def _normalize_finding(raw: dict) -> dict:
    extra = raw.get("extra", {})
    metadata = extra.get("metadata") or {}
    cwe = metadata.get("cwe") or []
    return {
        # 로컬 규칙 파일은 check_id에 경로 접두어가 붙는다(예: rules.BG-SAST-001). 마지막 조각이 규칙 ID다.
        "rule_id": str(raw.get("check_id", "")).rsplit(".", 1)[-1],
        "file": _relative_posix(raw.get("path", "")),
        "line": raw.get("start", {}).get("line"),
        "end_line": raw.get("end", {}).get("line"),
        "severity": extra.get("severity"),
        "message": " ".join(str(extra.get("message", "")).split()),
        "cwe": [cwe] if isinstance(cwe, str) else list(cwe),
        "review_status": "NEEDS_REVIEW",
    }


def scan_target(
    target: SastTarget,
    semgrep_bin: Path | None,
    rules_file: Path = RULES_FILE,
    bin_note: str = "",
) -> dict:
    """대상 1곳을 스캔해 정규화된 결과 dict를 돌려준다. 어떤 실패도 예외 대신 SCAN_ERROR로 돌려준다."""
    if semgrep_bin is None:
        return _error_result(target, NOT_INSTALLED, f"{INSTALL_HINT} (탐색 결과: {bin_note})")
    if not rules_file.is_file():
        return _error_result(target, RULES_MISSING, "규칙 파일(rules/bankguard.yml)을 찾을 수 없습니다.")

    cmd = [
        str(semgrep_bin), "scan",
        "--config", str(rules_file),
        "--json", "--metrics=off", "--disable-version-check",
    ]
    for pattern in target.excludes:
        cmd += ["--exclude", pattern]
    cmd += list(target.paths)

    # 규칙 파일이 UTF-8(한글 메시지)이라 한국어 Windows 기본 인코딩(cp949)으로는 읽지 못한다.
    env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    try:
        proc = subprocess.run(
            cmd, cwd=PROJECT_ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=TIMEOUT_SEC, shell=False, env=env,
        )
    except subprocess.TimeoutExpired:
        return _error_result(target, TIMEOUT, f"Semgrep이 {TIMEOUT_SEC}초 안에 끝나지 않았습니다.")
    except OSError as exc:
        hint = ""
        if sys.platform == "win32":
            hint = " (Windows 스마트 앱 컨트롤/보안 프로그램이 서명 없는 semgrep.exe를 차단했는지 확인하세요)"
        return _error_result(target, EXEC_FAILED, f"Semgrep 실행 실패({type(exc).__name__}){hint}")

    try:
        data = json.loads(proc.stdout)
        if not isinstance(data, dict):
            raise ValueError("JSON 최상위가 객체가 아님")
    except ValueError:
        kind = BAD_JSON if proc.returncode == 0 else SEMGREP_ERROR
        return _error_result(
            target, kind, f"Semgrep 출력을 JSON으로 읽지 못했습니다(종료 코드 {proc.returncode}): {_sanitize(proc.stderr)}"
        )

    version = data.get("version")
    fatal = [e for e in data.get("errors", []) if e.get("level") == "error"]
    if proc.returncode != 0 or fatal:
        detail = _sanitize(
            "; ".join(str(e.get("message") or e.get("long_msg") or e.get("type")) for e in fatal) or proc.stderr
        )
        return _error_result(
            target, SEMGREP_ERROR, f"Semgrep이 오류를 보고했습니다(종료 코드 {proc.returncode}): {detail}",
            semgrep_version=version,
        )

    scanned = sorted(_relative_posix(p) for p in data.get("paths", {}).get("scanned", []))
    if not scanned:
        # 아무 파일도 안 읽고 '0건'이라고 하면 '깨끗함'으로 오해한다.
        return _error_result(target, NO_FILES, "스캔된 파일이 없습니다(대상 경로 확인 필요).", semgrep_version=version)

    findings = [_normalize_finding(r) for r in data.get("results", [])]
    findings.sort(key=lambda f: (f["file"], f["line"] or 0, f["rule_id"]))
    return {
        "scanner": SCANNER_NAME,
        "scan_status": COMPLETED,
        "target": target.name,
        "paths": list(target.paths),
        "excludes": list(target.excludes),
        "finding_count": len(findings),
        "findings": findings,
        "files_scanned": scanned,
        "semgrep_version": version,
        "error_kind": None,
        "error_message": None,
        "run_at": utc_now_iso(),
    }


def run_sast(target_names: list[str] | None = None) -> dict:
    """고정 대상 전부(또는 이름으로 고른 일부)를 스캔한다. 대상 하나가 실패해도 나머지는 계속한다."""
    semgrep_bin, bin_note = find_semgrep_bin()
    try:
        rule_ids = rule_ids_in()
    except OSError:
        rule_ids = []
    results = [
        scan_target(target, semgrep_bin, bin_note=bin_note)
        for target in TARGETS
        if target_names is None or target.name in target_names
    ]
    versions = {r["semgrep_version"] for r in results if r["semgrep_version"]}
    return {
        "scanner": SCANNER_NAME,
        "run_id": str(uuid.uuid4()),
        "run_at": utc_now_iso(),
        "semgrep_version": next(iter(versions)) if len(versions) == 1 else None,
        "semgrep_bin_source": bin_note,
        "rules_count": len(rule_ids),
        "rule_ids": rule_ids,
        "targets": results,
        "total_findings": sum(r["finding_count"] for r in results),
        "scan_errors": sum(1 for r in results if r["scan_status"] == SCAN_ERROR),
    }


def rule_matrix(target_result: dict, rule_ids: list[str]) -> list[dict]:
    """(규칙 × 스캔된 파일) 표. 탐지 없음은 'NOT_FOUND'(= 그 규칙의 패턴을 찾지 못함)이지 안전 보증이 아니다."""
    if target_result["scan_status"] != COMPLETED:
        return [
            {"rule_id": rule, "file": None, "status": SCAN_ERROR, "count": 0, "lines": []}
            for rule in rule_ids
        ]
    rows = []
    for file in target_result["files_scanned"]:
        for rule in rule_ids:
            lines = [f["line"] for f in target_result["findings"] if f["file"] == file and f["rule_id"] == rule]
            rows.append(
                {"rule_id": rule, "file": file, "status": DETECTED if lines else NOT_FOUND,
                 "count": len(lines), "lines": lines}
            )
    return rows
