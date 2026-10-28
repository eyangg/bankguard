"""공통 검사 결과 모델 (명세 9장). UI·JSON·보고서가 같은 구조를 쓴다.

상태 의미(명세 7장):
- PASS : 사전에 정한 '안전한 동작'을 지켰다.
- FAIL : 안전 조건을 위반하는 동작이 실제로 관측됐다.
- ERROR: 서버 예외·양성 대조 실패 등으로 안전성 판단 자체가 불가능하다.
- SKIP : 실행하지 않았다.
`risk`는 BankGuard 내부 학습용 정성 등급이며 CVSS 인증 점수가 아니다.
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"
SKIP = "SKIP"
STATUSES = (PASS, FAIL, ERROR, SKIP)


@dataclass
class ScenarioItem:
    id: str
    name: str
    risk: str
    status: str
    expected: str
    observed: str
    description: str
    fix_guide: str
    evidence: str
    likelihood: str
    impact: str
    owasp: str = ""
    cwe: str = ""
    kr_weakness: str = ""  # 행안부 보안약점 항목명: 원문 확인 전에는 비워 둔다(명세 7.0)
    tier: str = "core"  # "core"(핵심 시나리오) | "detail"(세부 테스트, v1.2: SC-02는 T06·T07로 하향)


@dataclass
class RunResult:
    mode: str
    target: str = "isolated-demo-bank"
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    run_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
    items: list[ScenarioItem] = field(default_factory=list)

    def count(self, status: str) -> int:
        return sum(1 for item in self.items if item.status == status)

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "run_at": self.run_at,
            "target": self.target,
            "mode": self.mode,
            "total": len(self.items),
            "pass": self.count(PASS),
            "fail": self.count(FAIL),
            "error": self.count(ERROR),
            "skip": self.count(SKIP),
            "items": [asdict(item) for item in self.items],
        }
