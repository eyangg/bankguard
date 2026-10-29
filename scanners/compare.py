"""수정 전후 비교(FAIL→PASS 집계)와 SAST ↔ 동적 테스트 탐지 범위 비교표 (명세 8.6, DAY 7).

- 입력은 모두 실제 실행 결과 dict다. 이 모듈은 PASS/FAIL을 새로 만들거나 미리 써 넣지 않는다.
- '개선'은 취약 버전 FAIL **그리고** 안전 버전 PASS가 둘 다 실제로 있을 때만 센다.
  결과가 없거나 ERROR/SKIP이 끼면 개선 성공으로 집계하지 않는다.
"""
from __future__ import annotations

import ast
from pathlib import Path

from backend.config import PROJECT_ROOT
from scanners.models import ERROR, FAIL, PASS, SKIP

IMPROVED = "IMPROVED"
NOT_IMPROVED = "NOT_IMPROVED"
REGRESSED = "REGRESSED"
CHECK_INEFFECTIVE = "CHECK_INEFFECTIVE"
UNDETERMINED = "UNDETERMINED"
MISSING = "MISSING"

OUTCOME_LABELS = {
    IMPROVED: "개선 확인(FAIL→PASS)",
    NOT_IMPROVED: "개선 안 됨(안전 버전도 FAIL)",
    REGRESSED: "역전(안전 버전만 FAIL)",
    CHECK_INEFFECTIVE: "비교 무의미(취약 버전에서도 통과)",
    UNDETERMINED: "판정 불가(ERROR/SKIP 포함)",
    MISSING: "비교 불가(결과 없음)",
}


def _by_id(run: dict | None) -> dict[str, dict]:
    return {item["id"]: item for item in (run or {}).get("items", [])}


def classify(vulnerable_status: str | None, secure_status: str | None) -> str:
    if vulnerable_status is None or secure_status is None:
        return MISSING
    if vulnerable_status in (ERROR, SKIP) or secure_status in (ERROR, SKIP):
        return UNDETERMINED
    if vulnerable_status == FAIL and secure_status == PASS:
        return IMPROVED
    if vulnerable_status == FAIL and secure_status == FAIL:
        return NOT_IMPROVED
    if vulnerable_status == PASS and secure_status == PASS:
        return CHECK_INEFFECTIVE
    return REGRESSED  # 취약 PASS / 안전 FAIL


def compare_runs(vulnerable: dict | None, secure: dict | None) -> dict:
    """취약 버전과 안전 버전의 시나리오별 결과를 나란히 놓고 개선 여부를 판정한다."""
    v_items, s_items = _by_id(vulnerable), _by_id(secure)
    ids = list(dict.fromkeys([*v_items, *s_items]))  # 등장 순서 유지
    rows = []
    for scenario_id in ids:
        v, s = v_items.get(scenario_id), s_items.get(scenario_id)
        outcome = classify(v["status"] if v else None, s["status"] if s else None)
        base = v or s
        rows.append(
            {
                "id": scenario_id,
                "name": base["name"],
                "tier": base.get("tier", "core"),
                "risk": base["risk"],
                "vulnerable": v["status"] if v else None,
                "secure": s["status"] if s else None,
                "outcome": outcome,
                "outcome_label": OUTCOME_LABELS[outcome],
            }
        )

    def tally(tier: str) -> dict:
        tier_rows = [r for r in rows if r["tier"] == tier]
        counts = {"total": len(tier_rows)}
        for outcome in OUTCOME_LABELS:
            counts[outcome] = sum(1 for r in tier_rows if r["outcome"] == outcome)
        return counts

    return {
        "rows": rows,
        "core": tally("core"),
        "detail": tally("detail"),
        "has_both_runs": bool(vulnerable and secure),
    }


# ============================================================================================
# SAST ↔ 동적 테스트 탐지 범위 비교표 (8.6)
# ============================================================================================

LAB_FILE = "backend/services/insecure_lab.py"
FIXTURE_VULNERABLE_FILE = "fixtures/code/vulnerable_example.py"

# 결함 → 그 결함 코드가 있는 위치(심볼)와 그 결함을 '겨냥한' Semgrep 규칙.
# 이 표는 '어디를 볼지'를 정할 뿐이고 결과(탐지 여부)는 실제 실행 결과에서만 나온다.
# 업무 로직 결함(BOLA·BFLA·경쟁 조건·멱등성·금액 검증·Mass Assignment·시도 횟수 제한)은 겨냥한 규칙이 없다(명세 8.1).
FLAW_ROWS: tuple[dict, ...] = (
    {"flaw": "BOLA(소유권 검사 누락)", "scenario_id": "SC-01", "lab_symbols": ("lab_list_account_transactions",),
     "fixture_files": (), "relevant_rules": ()},
    {"flaw": "음수/0 금액 허용", "scenario_id": "SC-02", "lab_symbols": ("TransferInLoose",),
     "fixture_files": (), "relevant_rules": ()},
    {"flaw": "경쟁 조건(비원자적 차감)", "scenario_id": "SC-03", "lab_symbols": ("execute_transfer_lost_update",),
     "fixture_files": (), "relevant_rules": ()},
    {"flaw": "멱등성 미처리", "scenario_id": "SC-04", "lab_symbols": ("execute_transfer_no_idempotency",),
     "fixture_files": (), "relevant_rules": ()},
    {"flaw": "BFLA(역할 검사 누락)", "scenario_id": "SC-05", "lab_symbols": ("_setup_bfla",),
     "fixture_files": (), "relevant_rules": ()},
    {"flaw": "Mass Assignment(요청 키 그대로 반영)", "scenario_id": "SC-06",
     "lab_symbols": ("NicknameUpdateLoose", "lab_update_account_nickname"),
     "fixture_files": (), "relevant_rules": ()},
    {"flaw": "인증 시도 횟수 제한 없음", "scenario_id": "SC-07", "lab_symbols": ("lab_current_user",),
     "fixture_files": (), "relevant_rules": ()},
    {"flaw": "SQL 문자열 조립", "scenario_id": None, "lab_symbols": ("lab_update_account_nickname",),
     "fixture_files": (FIXTURE_VULNERABLE_FILE,), "relevant_rules": ("BG-SAST-001",)},
    {"flaw": "금액 float", "scenario_id": None, "lab_symbols": (),
     "fixture_files": (FIXTURE_VULNERABLE_FILE,), "relevant_rules": ("BG-SAST-002",)},
)


def symbol_line_ranges(source_path: Path, symbols: tuple[str, ...]) -> list[tuple[int, int]]:
    """소스 파일에서 함수/클래스 정의의 (시작줄, 끝줄)을 AST로 찾는다."""
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    ranges = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name in symbols:
            ranges.append((node.lineno, node.end_lineno or node.lineno))
    return ranges


def _target(sast_run: dict | None, name: str) -> dict | None:
    for target in (sast_run or {}).get("targets", []):
        if target["target"] == name:
            return target
    return None


def _semgrep_cell(row: dict, sast_run: dict | None, lab_path: Path) -> dict:
    if sast_run is None:
        return {"status": "NOT_RUN", "label": "미실행", "rules": [], "locations": []}

    needed = []
    if row["lab_symbols"]:
        needed.append(("lab", _target(sast_run, LAB_FILE)))
    if row["fixture_files"]:
        needed.append(("fixtures", _target(sast_run, "fixtures/code")))
    if any(target is None or target["scan_status"] != "COMPLETED" for _, target in needed):
        return {"status": "SCAN_ERROR", "label": "스캔 오류(SCAN_ERROR)", "rules": [], "locations": []}

    hits: list[dict] = []
    for kind, target in needed:
        if kind == "lab":
            ranges = symbol_line_ranges(lab_path, row["lab_symbols"])
            hits += [f for f in target["findings"]
                     if f["file"] == LAB_FILE and any(lo <= f["line"] <= hi for lo, hi in ranges)]
        else:
            hits += [f for f in target["findings"] if f["file"] in row["fixture_files"]]

    relevant = [f for f in hits if f["rule_id"] in row["relevant_rules"]]
    locations = [f"{Path(f['file']).name}:{f['line']}" for f in hits]
    if row["relevant_rules"]:
        if relevant:
            rules = sorted({f["rule_id"] for f in relevant})
            return {"status": "DETECTED", "label": f"탐지({', '.join(rules)} · {len(relevant)}건 · 검토 필요)",
                    "rules": rules, "locations": locations}
        return {"status": "NOT_DETECTED", "label": "미탐지", "rules": [], "locations": []}
    if hits:
        rules = sorted({f["rule_id"] for f in hits})
        return {"status": "UNRELATED_FINDING",
                "label": f"이 결함은 미탐지(같은 코드에서 다른 패턴 {', '.join(rules)} 탐지)",
                "rules": rules, "locations": locations}
    return {"status": "NOT_DETECTED_NO_RULE", "label": "미탐지(이 결함을 겨냥한 규칙 없음)", "rules": [], "locations": []}


def _interpretation(dynamic: dict, semgrep: dict) -> str:
    dyn, sem = dynamic["state"], semgrep["status"]
    if dyn == "NO_SCENARIO":
        if sem == "DETECTED":
            return "정적 분석만 탐지: 실행 검사 대상이 아닌 코드 패턴 결함. 탐지는 '검토 필요' 의심 항목이라 실제 악용 가능성은 사람이 따로 판단한다."
        if sem == "NOT_RUN":
            return "정적 분석 미실행."
        return "정적 분석이 이 패턴을 찾지 못함(안전 보증 아님)."
    if dyn == "NOT_RUN":
        return "동적 테스트 미실행: 비교할 수 없음."
    if dyn == "NOT_EFFECTIVE":
        return "취약 버전에서도 통과해 이 동적 검사가 결함을 재현하지 못함."
    if dyn == "UNDETERMINED":
        return "동적 테스트가 판정 불가(ERROR)여서 비교할 수 없음."
    # dyn == "REPRODUCED": 취약 버전에서 결함이 실제로 FAIL로 재현됨
    if sem == "DETECTED":
        return "동적 테스트와 정적 분석이 모두 탐지."
    if sem == "NOT_RUN":
        return "동적 테스트는 결함을 재현. 정적 분석은 미실행."
    if sem == "UNRELATED_FINDING":
        return "동적 테스트만 결함을 재현. Semgrep은 같은 코드에서 다른 패턴만 탐지했고 이 결함 자체는 잡지 못함."
    if sem == "SCAN_ERROR":
        return "동적 테스트는 결함을 재현. 정적 분석은 스캔 오류로 비교 불가."
    return "동적 테스트만 탐지: 업무 로직 결함은 소스 패턴 규칙으로 보이지 않음(이를 겨냥한 규칙이 없음)."


def coverage_rows(
    vulnerable: dict | None,
    secure: dict | None,
    sast_run: dict | None,
    lab_path: Path = PROJECT_ROOT / LAB_FILE,
) -> list[dict]:
    """명세 8.6 표: 결함 × (동적 테스트 결과, Semgrep 결과, 해석). 값은 모두 실제 실행 결과에서 계산한다."""
    v_items, s_items = _by_id(vulnerable), _by_id(secure)
    rows = []
    for spec in FLAW_ROWS:
        scenario_id = spec["scenario_id"]
        if scenario_id is None:
            dynamic = {"state": "NO_SCENARIO", "label": "해당 동적 시나리오 없음", "vulnerable": None, "secure": None}
        else:
            v = v_items.get(scenario_id, {}).get("status")
            s = s_items.get(scenario_id, {}).get("status")
            if v is None:
                state = "NOT_RUN"
            elif v in (ERROR, SKIP):
                state = "UNDETERMINED"
            elif v == FAIL:
                state = "REPRODUCED"
            else:
                state = "NOT_EFFECTIVE"
            dynamic = {
                "state": state,
                "label": f"{scenario_id} · 취약 {v or '미실행'} / 안전 {s or '미실행'}",
                "vulnerable": v,
                "secure": s,
            }
        semgrep = _semgrep_cell(spec, sast_run, lab_path)
        location = " / ".join(
            [*(["insecure_lab.py"] if spec["lab_symbols"] else []), *(Path(f).name for f in spec["fixture_files"])]
        )
        rows.append(
            {
                "flaw": spec["flaw"],
                "location": location,
                "dynamic": dynamic,
                "semgrep": semgrep,
                "interpretation": _interpretation(dynamic, semgrep),
            }
        )
    return rows
