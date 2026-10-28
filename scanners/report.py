"""실무형 보안 진단 보고서(Markdown) 생성 (명세 DAY 7).

항목: 점검항목 / 위험도(가능성×영향) / 취약 여부 / 근거 / 조치 권고 / 이행점검 결과 / 매핑.
입력은 실제 실행 결과(bundle)뿐이며, 실행하지 않은 부분은 '미실행'으로 적는다. 결과를 미리 쓰거나 꾸미지 않는다.

CLI
    python -m scanners.report                    # 모든 검사를 실제로 실행하고 artifacts/에 JSON·보고서 저장
    python -m scanners.report --from-artifacts   # artifacts/의 최근 JSON만으로 보고서 생성(검사 재실행 없음)
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
from datetime import datetime, timedelta, timezone

from scanners import artifacts
from scanners.compare import compare_runs, coverage_rows

KST = timezone(timedelta(hours=9))

VULNERABILITY_TEXT = {"FAIL": "취약(재현됨)", "PASS": "취약 동작 미재현", "ERROR": "판정 불가(ERROR)", "SKIP": "실행 안 함"}
REMEDIATION_TEXT = {"PASS": "이행 확인(PASS)", "FAIL": "미이행(FAIL)", "ERROR": "판정 불가(ERROR)", "SKIP": "실행 안 함"}


def format_kst(iso_utc: str | None) -> str:
    if not iso_utc:
        return "-"
    moment = datetime.fromisoformat(iso_utc.replace("Z", "+00:00")).astimezone(KST)
    return f"{moment:%Y-%m-%d %H:%M:%S} KST"


def _cell(value) -> str:
    """Markdown 표 셀용: 파이프와 줄바꿈을 무해하게 바꾼다."""
    return " ".join(str(value).replace("|", "\\|").split())


def _table(headers: list[str], rows: list[list]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return lines


def _items(run: dict | None) -> dict[str, dict]:
    return {item["id"]: item for item in (run or {}).get("items", [])}


def _risk(item: dict) -> str:
    return f"{item['risk']} ({item['likelihood']}×{item['impact']})"


def _mapping(item: dict) -> str:
    parts = [p for p in (item.get("owasp"), item.get("cwe"), item.get("kr_weakness")) if p]
    return " · ".join(parts) if parts else "-"


def build_report(bundle: dict, generated_at: datetime | None = None) -> str:
    vulnerable, secure = bundle.get("api_vulnerable"), bundle.get("api_secure")
    sast, det01 = bundle.get("sast"), bundle.get("det01")
    now = generated_at or datetime.now(timezone.utc)
    comparison = compare_runs(vulnerable, secure)
    v_items, s_items = _items(vulnerable), _items(secure)
    outcome_by_id = {row["id"]: row for row in comparison["rows"]}
    ordered = [row["id"] for row in comparison["rows"]]
    core_ids = [i for i in ordered if outcome_by_id[i]["tier"] == "core"]
    detail_ids = [i for i in ordered if outcome_by_id[i]["tier"] == "detail"]

    out: list[str] = []
    out += ["# BankGuard 보안 진단 보고서", ""]
    out += [
        "> 가상 은행 송금·계좌 API를 대상으로 한 **로컬 학습용 진단 결과**입니다. 실제 금융 서비스가 아니며 "
        "모든 계좌·토큰은 허구의 더미 데이터입니다. 아래 내용은 **정의된 검사 범위 내**의 실제 실행 결과이며, "
        "시스템 전체의 안전을 보증하지 않습니다.",
        "",
    ]
    out += ["## 0. 진단 개요", ""]
    out += _table(
        ["항목", "내용"],
        [
            ["진단 일시", format_kst(now.isoformat(timespec="seconds").replace("+00:00", "Z"))],
            ["진단 대상", "BankGuard 가상 은행 API (격리된 임시 DB·인프로세스 실행)"],
            ["환경", f"Python {platform.python_version()} · {platform.system()} {platform.release()}"],
            ["정적 분석 도구", f"Semgrep CE {sast.get('semgrep_version') or '버전 불명'}" if sast else "미실행"],
            ["위험도 기준", "가능성(L1~L3) × 영향(I1~I3) 3×3 표 — 프로젝트 내부 학습용 기준이며 CVSS 인증 점수가 아님"],
        ],
    )
    out.append("")

    # 1. 요약 ------------------------------------------------------------------------------
    core = comparison["core"]
    out += ["## 1. 요약", ""]
    if not comparison["has_both_runs"]:
        missing = [name for name, run in (("취약 버전", vulnerable), ("안전 버전", secure)) if not run]
        out.append(f"- **API 보안 시나리오: {' · '.join(missing)} 결과가 없어 수정 전후를 비교할 수 없습니다.** (미실행)")
    else:
        out.append(
            f"- 핵심 시나리오 {core['total']}개 중 **{core['IMPROVED']}개에서 개선 확인(취약 버전 FAIL → 안전 버전 PASS)**"
            f", 판정 불가 {core['UNDETERMINED']}개, 개선 안 됨 {core['NOT_IMPROVED']}개, 비교 무의미 {core['CHECK_INEFFECTIVE']}개, 역전 {core['REGRESSED']}개."
        )
    if sast:
        out.append(
            f"- 정적 분석: 규칙 {sast['rules_count']}개, 대상 {len(sast['targets'])}곳, 탐지 {sast['total_findings']}건"
            f"(모두 **검토 필요** 의심 항목), 스캔 오류 {sast['scan_errors']}건."
        )
    else:
        out.append("- 정적 분석: 미실행")
    if det01:
        out.append(f"- 감사 로그 기반 탐지 DET-01: **{det01['status']}** — {det01['observed']}")
    else:
        out.append("- 감사 로그 기반 탐지 DET-01: 미실행")
    out.append("")

    # 2. 점검 항목 결과 ----------------------------------------------------------------------
    out += ["## 2. 점검 항목 결과 (핵심 시나리오)", ""]
    if core_ids:
        rows = []
        for sid in core_ids:
            base = v_items.get(sid) or s_items[sid]
            rows.append(
                [
                    sid,
                    base["name"],
                    _risk(base),
                    VULNERABILITY_TEXT.get((v_items.get(sid) or {}).get("status"), "미실행"),
                    REMEDIATION_TEXT.get((s_items.get(sid) or {}).get("status"), "미실행"),
                    outcome_by_id[sid]["outcome_label"],
                    _mapping(base),
                ]
            )
        out += _table(["ID", "점검 항목", "위험도(L×I)", "취약 여부(취약 버전)", "이행점검(안전 버전 재검증)", "개선 판정", "매핑"], rows)
    else:
        out.append("실행된 API 보안 시나리오가 없습니다. (미실행)")
    out.append("")

    out += ["## 3. 항목별 상세", ""]
    for sid in core_ids + detail_ids:
        base = v_items.get(sid) or s_items[sid]
        v, s = v_items.get(sid), s_items.get(sid)
        label = "세부 테스트" if sid in detail_ids else "핵심 시나리오"
        out += [f"### {sid} · {base['name']} ({label})", ""]
        out.append(f"- **위험도:** {_risk(base)}")
        out.append(f"- **점검 내용:** {base['description']}")
        out.append(f"- **안전 기준(기대):** {base['expected']}")
        out.append(f"- **취약 여부(취약 버전):** {VULNERABILITY_TEXT.get(v['status']) if v else '미실행'}")
        out.append(f"  - 관측: {_cell(v['observed']) if v else '-'}")
        out.append(f"  - 근거: {_cell(v['evidence']) if v else '-'}")
        out.append(f"- **조치 권고:** {base['fix_guide']}")
        out.append(f"- **이행점검(안전 버전 재검증):** {REMEDIATION_TEXT.get(s['status']) if s else '미실행'}")
        out.append(f"  - 관측: {_cell(s['observed']) if s else '-'}")
        out.append(f"  - 근거: {_cell(s['evidence']) if s else '-'}")
        out.append(f"- **개선 판정:** {outcome_by_id[sid]['outcome_label']}")
        out.append(f"- **매핑:** {_mapping(base)}")
        out.append("")

    # 4. 정적 분석 -----------------------------------------------------------------------------
    out += ["## 4. 정적 분석(Semgrep) 결과", ""]
    if not sast:
        out += ["미실행", ""]
    else:
        out.append("탐지는 **검토가 필요한 의심 항목**이며 확정 취약점이 아닙니다. 탐지 0건은 안전 보증이 아닙니다.")
        out.append("")
        out += _table(
            ["대상", "상태", "탐지", "스캔 파일"],
            [
                [t["target"],
                 "완료" if t["scan_status"] == "COMPLETED" else f"스캔 오류({t['error_kind']})",
                 t["finding_count"], len(t["files_scanned"])]
                for t in sast["targets"]
            ],
        )
        out.append("")
        finding_rows = [
            [f["rule_id"], f"{f['file']}:{f['line']}", f["severity"], f["message"], "검토 필요"]
            for t in sast["targets"] for f in t["findings"]
        ]
        if finding_rows:
            out += _table(["규칙", "위치", "심각도", "설명", "상태"], finding_rows)
            out.append("")
        for t in sast["targets"]:
            if t["scan_status"] != "COMPLETED":
                out.append(f"- **{t['target']}** 스캔 오류: {_cell(t['error_message'])}")
        out.append("")

    # 5. 비교표 ---------------------------------------------------------------------------------
    out += ["## 5. SAST ↔ 동적 테스트 탐지 범위 비교", ""]
    if not (vulnerable or sast):
        out += ["미실행", ""]
    else:
        out += _table(
            ["결함", "위치", "동적 테스트", "Semgrep", "해석"],
            [[r["flaw"], r["location"], r["dynamic"]["label"], r["semgrep"]["label"], r["interpretation"]]
             for r in coverage_rows(vulnerable, secure, sast)],
        )
        out += [
            "",
            "정적 분석만으로 업무 로직 결함을 보장할 수 없고, 동적 테스트만으로 코드 패턴 결함을 모두 찾을 수도 없습니다. "
            "이 표는 같은 코드에 대해 두 방법이 각각 무엇을 잡았는지 실제 실행 결과로 보여 줍니다.",
            "",
        ]

    # 6. DET-01 ----------------------------------------------------------------------------------
    out += ["## 6. 감사 로그 기반 탐지 (DET-01 계좌 열거 의심)", ""]
    if not det01:
        out += ["미실행", ""]
    else:
        out.append(f"- **결과:** {det01['status']} — {det01['observed']}")
        out.append(f"- **기대:** {det01['expected']}")
        out.append(f"- **근거:** {_cell(det01['evidence'])}")
        out.append("")
        out += _table(
            ["단계", "요청", "응답", "그 시점 경보 수"],
            [[s["step"], s["request"], s["http_status"], s["alerts_after"]] for s in det01["steps"]],
        )
        out += [
            "",
            "한계: 정상 사용자의 연속 입력 실수나 공유 토큰은 오탐이 될 수 있고, 임계값 아래로 천천히 시도하거나 토큰을 바꿔 가며 "
            "시도하면 놓칩니다. 경보는 실제 감사 로그 조회로만 만들어집니다.",
            "",
        ]

    out += [
        "## 7. 한계와 주의",
        "",
        "- 토큰은 학습용 가상 식별자이며 실제 은행 인증과 동등하지 않습니다.",
        "- 취약 비교 구현은 격리된 임시 DB·인프로세스에서만 실행했고 네트워크에 공개하지 않았습니다.",
        "- SC-02(T06·T07)의 취약 앱은 DB의 `CHECK(amount_krw > 0)`만 뺀 전용 스키마를 사용합니다(서버 검증 누락의 영향을 보기 위함).",
        "- 위험도는 프로젝트 내부 학습용 등급이고, 매핑 항목 중 원문을 확인하지 못한 값은 비워 두었습니다.",
        "- '개선 확인'은 정의된 검사 범위 안에서 취약 버전 FAIL과 안전 버전 PASS가 모두 실제로 관측된 경우만 센 것이며 모든 취약점이 제거되었다는 뜻이 아닙니다.",
        "",
    ]
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BankGuard 진단 보고서 생성")
    parser.add_argument("--from-artifacts", action="store_true", help="검사를 다시 실행하지 않고 artifacts/의 최근 JSON으로 만든다")
    args = parser.parse_args(argv)

    if args.from_artifacts:
        bundle = artifacts.load_bundle()
        if not any(bundle.values()):
            print("artifacts/에 저장된 검사 결과가 없습니다. 먼저 `python -m scanners.report`로 검사를 실행하세요.", file=sys.stderr)
            return 2
    else:
        from scanners.pipeline import run_full_check

        print("전체 검사를 실행합니다 (취약 → 안전 → 정적 분석 → DET-01)...", flush=True)
        bundle = run_full_check(lambda done, total, name: print(f"  [{done}/{total}] {name}", flush=True))
        for kind, data in bundle.items():
            artifacts.save_json(kind, data)

    markdown = build_report(bundle)
    path = artifacts.save_text("diagnosis_report.md", markdown)
    coverage_path = artifacts.save_text(
        "coverage_matrix.json",
        json.dumps(coverage_rows(bundle["api_vulnerable"], bundle["api_secure"], bundle["sast"]), ensure_ascii=False, indent=2),
    )
    print(f"보고서: {path}")
    print(f"비교표 JSON: {coverage_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
