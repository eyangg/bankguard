"""대시보드 표시용 순수 함수(Streamlit 호출 없음). 단위 테스트가 가능하도록 화면 코드와 분리한다."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))  # 한국은 서머타임이 없어 고정 오프셋으로 충분하다

MODE_LABELS = {"vulnerable": "취약 버전(격리 실습)", "secure": "안전 버전(수정 후)"}

STATUS_LABELS = {
    "PASS": "✅ 보안 기준 통과(PASS)",
    "FAIL": "❌ 취약 동작 확인(FAIL)",
    "ERROR": "⚠️ 검사 불능(ERROR)",
    "SKIP": "⏭️ 실행 안 함(SKIP)",
}
STATUS_COLORS = {"PASS": "green", "FAIL": "red", "ERROR": "orange", "SKIP": "gray"}
RISK_COLORS = {"HIGH": "red", "MEDIUM": "orange", "LOW": "blue"}


def format_krw(amount: int) -> str:
    """원화 표시: 1000000 → '1,000,000원'."""
    return f"{amount:,}원"


def format_kst(iso_utc: str | None) -> str:
    """UTC ISO8601 문자열을 한국어 KST 표기로. 값이 없으면 '-'."""
    if not iso_utc:
        return "-"
    moment = datetime.fromisoformat(iso_utc.replace("Z", "+00:00")).astimezone(KST)
    return f"{moment.year}년 {moment.month}월 {moment.day}일 {moment:%H:%M:%S} (KST)"


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status)


def colored_status(status: str) -> str:
    return f":{STATUS_COLORS.get(status, 'gray')}[{status_label(status)}]"


def risk_text(risk: str, likelihood: str, impact: str) -> str:
    """'HIGH (가능성 L3 × 영향 I2)' — 프로젝트 내부 학습용 등급이며 CVSS 점수가 아니다."""
    return f":{RISK_COLORS.get(risk, 'gray')}[**{risk}**] (가능성 {likelihood} × 영향 {impact})"


def tier_items(items: list[dict], tier: str) -> list[dict]:
    return [item for item in items if item.get("tier", "core") == tier]


def summarize(items: list[dict]) -> dict[str, int]:
    """상태별 건수. 실행하지 않은 항목은 아예 items에 없으므로 0/0이 '통과'로 보이지 않게 total도 함께 둔다."""
    counts = {"total": len(items), "PASS": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return counts


def finding_rows(target_result: dict) -> list[dict]:
    """Semgrep 탐지 항목을 표(dataframe) 행으로. 값은 sast_runner가 정규화한 실제 출력 그대로다."""
    return [
        {
            "규칙": f["rule_id"],
            "파일": f["file"],
            "줄": f["line"],
            "심각도": f["severity"],
            "위험 설명": f["message"],
            "상태": "검토 필요",
        }
        for f in target_result["findings"]
    ]


def matrix_table(rows: list[dict]) -> list[dict]:
    """sast_runner.rule_matrix 결과를 '규칙 × 파일' 표로 바꾼다.

    내부 상태값(DETECTED / NOT_FOUND, 명세 8.5 용어)은 그대로 두고 화면 표시만 한국어로 한다.
    셀: '탐지(n건)' / '미탐지(패턴 없음)'. 미탐지는 그 규칙의 패턴을 찾지 못했다는 뜻이지 안전 보증이 아니다.
    """
    files = sorted({r["file"] for r in rows if r["file"]})
    rules = sorted({r["rule_id"] for r in rows})
    cell = {(r["rule_id"], r["file"]): r for r in rows}
    table = []
    for rule in rules:
        row = {"규칙": rule}
        for file in files:
            entry = cell[(rule, file)]
            row[file.rsplit("/", 1)[-1]] = (
                f"탐지({entry['count']}건)" if entry["status"] == "DETECTED" else "미탐지(패턴 없음)"
            )
        table.append(row)
    return table
