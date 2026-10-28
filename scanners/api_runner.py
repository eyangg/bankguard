"""고정 시나리오 실행기 (명세 12장). DAY 3: SC-01 BOLA, SC-05 BFLA, SC-06 Mass Assignment.

원칙
- 시나리오(또는 그 변형)마다 독립된 임시 폴더의 새 SQLite DB와 새 앱(TestClient, 인프로세스)을 만든다.
  운영 DB와 다른 시나리오의 상태를 건드리지 않는다. 네트워크 요청은 하지 않는다.
- 판정은 모드 이름이 아니라 실제 응답 코드·본문·DB 상태로만 한다.
- 양성 대조(정상 사용이 되는가)가 깨지면 권한 검사가 아니라 기능 고장일 수 있으므로 ERROR로 처리한다.
- 예외는 ERROR로 바꾸되 스택트레이스·로컬 경로는 결과에 넣지 않는다(내부 로그에만 남긴다).
"""
from __future__ import annotations

import logging
import tempfile
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NamedTuple

from fastapi.testclient import TestClient

from backend.db import connect, init_db
from backend.factory import create_app
from scanners.models import ERROR, FAIL, PASS, RunResult, ScenarioItem

logger = logging.getLogger("bankguard.api_runner")

TOKEN_A = {"X-Demo-Token": "demo-token-a"}
TOKEN_B = {"X-Demo-Token": "demo-token-b"}
TOKEN_ADMIN = {"X-Demo-Token": "demo-token-admin"}

RUN_MODES = ("secure", "vulnerable")


class Outcome(NamedTuple):
    status: str
    observed: str
    evidence: str


class ControlFailed(Exception):
    """사전 준비 또는 양성 대조가 실패 → 안전성 판단 불가(ERROR)."""


class IsolatedEnv:
    """시나리오 1회분 격리 환경: 임시 폴더의 새 DB + 새 앱 + TestClient."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self._stack = ExitStack()

    def __enter__(self) -> "IsolatedEnv":
        tmp = self._stack.enter_context(
            tempfile.TemporaryDirectory(prefix="bankguard_", ignore_cleanup_errors=True)
        )
        self.db_path = Path(tmp) / "scenario.db"
        init_db(self.db_path)
        app = create_app(mode=self.mode, db_path=self.db_path)
        self.client = self._stack.enter_context(TestClient(app))
        return self

    def __exit__(self, *exc) -> None:
        self._stack.close()

    def query(self, sql: str, params: tuple = ()) -> list[dict]:
        conn = connect(self.db_path)
        try:
            return [dict(row) for row in conn.execute(sql, params)]
        finally:
            conn.close()

    def account(self, account_id: int) -> dict:
        return self.query("SELECT * FROM accounts WHERE id = ?", (account_id,))[0]

    def total_balance(self) -> int:
        return self.query("SELECT SUM(balance_krw) AS s FROM accounts")[0]["s"]


EnvFactory = Callable[[], IsolatedEnv]


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    risk: str
    likelihood: str
    impact: str
    owasp: str
    cwe: str
    expected: str
    description: str
    fix_guide: str
    execute: Callable[[EnvFactory], Outcome]
    kr_weakness: str = ""


# --- SC-01 BOLA -----------------------------------------------------------------

def _run_sc01(new_env: EnvFactory) -> Outcome:
    with new_env() as env:
        # 준비: B 계좌에 '유출될 데이터'가 있도록 B→C 10,000원 송금 (송금 API는 두 모드 모두 안전 구현)
        setup = env.client.post(
            "/api/transfers",
            json={"from_account_id": 102, "to_account_id": 103, "amount_krw": 10_000,
                  "request_id": str(uuid.uuid4())},
            headers=TOKEN_B,
        )
        if setup.status_code != 201:
            raise ControlFailed(f"사전 준비 송금 실패(HTTP {setup.status_code})")
        transfer_id = setup.json()["transfer_id"]

        # 양성 대조: B가 본인 거래내역을 조회하면 방금 거래가 보여야 한다.
        control = env.client.get("/api/accounts/102/transactions", headers=TOKEN_B)
        if control.status_code != 200 or [t["id"] for t in control.json()] != [transfer_id]:
            raise ControlFailed(f"본인 거래내역 조회 대조 실패(HTTP {control.status_code})")

        # 공격: A 토큰으로 B 계좌 조회
        attack = env.client.get("/api/accounts/102/transactions", headers=TOKEN_A)
        leaked = False
        if attack.status_code == 200:
            try:
                leaked = any(t.get("id") == transfer_id for t in attack.json())
            except (ValueError, AttributeError, TypeError):
                leaked = False

        evidence = (
            f"A 토큰으로 GET /api/accounts/102/transactions → HTTP {attack.status_code}. "
            f"양성 대조: B 토큰으로 본인 조회 HTTP 200, 거래 1건 확인."
        )
        if attack.status_code == 403 and not leaked:
            return Outcome(PASS, "403, 타인(B) 거래 데이터 미반환", evidence)
        if leaked:
            return Outcome(FAIL, "200, 타인(B)의 거래 데이터가 반환됨", evidence + " 응답에 B의 거래가 포함됨.")
        return Outcome(ERROR, f"예상 밖 응답 HTTP {attack.status_code}: 판정 불가", evidence)


# --- SC-05 BFLA -----------------------------------------------------------------

def _run_sc05(new_env: EnvFactory) -> Outcome:
    # 양성 대조(별도 격리 환경): 운영자 토큰이면 같은 요청이 정상 동작해야 한다.
    with new_env() as env:
        ok = env.client.post("/api/admin/accounts/102/freeze", headers=TOKEN_ADMIN)
        if ok.status_code != 200 or ok.json().get("status") != "FROZEN" or env.account(102)["status"] != "FROZEN":
            raise ControlFailed(f"운영자 지급정지 대조 실패(HTTP {ok.status_code})")

    with new_env() as env:
        attack = env.client.post("/api/admin/accounts/102/freeze", headers=TOKEN_A)
        status_after = env.account(102)["status"]
        denied_logs = env.query(
            "SELECT COUNT(*) AS n FROM audit_log WHERE event_type = 'ACCESS_DENIED' AND target_account_id = 102"
        )[0]["n"]

    evidence = (
        f"고객 A 토큰으로 POST /api/admin/accounts/102/freeze → HTTP {attack.status_code}, "
        f"102 계좌 status={status_after}, 감사로그 ACCESS_DENIED={denied_logs}건. "
        "양성 대조: 운영자 토큰은 같은 요청에 200 FROZEN."
    )
    if status_after == "FROZEN" or attack.status_code == 200:
        return Outcome(FAIL, f"HTTP {attack.status_code}, 고객이 타인 계좌를 지급정지시킴(status={status_after})", evidence)
    if attack.status_code == 403 and status_after == "ACTIVE":
        if denied_logs == 1:
            return Outcome(PASS, "403, 상태 불변(ACTIVE), 감사로그 ACCESS_DENIED 1건", evidence)
        return Outcome(FAIL, f"403·상태 불변이나 감사로그 ACCESS_DENIED가 {denied_logs}건(기대 1건)", evidence)
    return Outcome(ERROR, f"예상 밖 응답 HTTP {attack.status_code}: 판정 불가", evidence)


# --- SC-06 BOPLA / Mass Assignment ---------------------------------------------------

_SC06_VARIANTS = (
    {"nickname": "생활비", "balance_krw": 99_999_999},
    {"nickname": "x", "owner_user_id": 2},
    {"nickname": "x", "status": "ACTIVE"},
)
_WATCHED = ("balance_krw", "owner_user_id", "status", "nickname")


def _run_sc06(new_env: EnvFactory) -> Outcome:
    # 양성 대조: nickname만 보내면 200이고 nickname만 바뀐다.
    with new_env() as env:
        before = env.account(101)
        ok = env.client.patch("/api/accounts/101", json={"nickname": "생활비"}, headers=TOKEN_A)
        after = env.account(101)
        only_nickname = all(after[k] == before[k] for k in _WATCHED if k != "nickname")
        if ok.status_code != 200 or after["nickname"] != "생활비" or not only_nickname:
            raise ControlFailed(f"정상 별칭 변경 대조 실패(HTTP {ok.status_code})")

    unsafe, errors, lines = 0, 0, []
    for payload in _SC06_VARIANTS:
        with new_env() as env:
            before = env.account(101)
            total_before = env.total_balance()
            resp = env.client.patch("/api/accounts/101", json=payload, headers=TOKEN_A)
            after = env.account(101)
            changed = [k for k in _WATCHED if after[k] != before[k]]
            total_changed = env.total_balance() != total_before
        extra = [k for k in payload if k != "nickname"][0]
        if changed or total_changed or resp.status_code < 300:
            unsafe += 1
            lines.append(f"+{extra}: HTTP {resp.status_code}, 변경된 속성={changed or '없음'}")
        elif resp.status_code == 422:
            lines.append(f"+{extra}: HTTP 422, DB 불변")
        else:
            errors += 1
            lines.append(f"+{extra}: HTTP {resp.status_code}, 판정 불가")

    evidence = "A 토큰으로 PATCH /api/accounts/101 변형별 결과 — " + "; ".join(lines) + ". 양성 대조: nickname만 보내면 200."
    if unsafe:
        return Outcome(FAIL, f"변형 {len(_SC06_VARIANTS)}개 중 {unsafe}개에서 허용되지 않은 속성이 반영되거나 2xx로 수락됨", evidence)
    if errors:
        return Outcome(ERROR, f"변형 {len(_SC06_VARIANTS)}개 중 {errors}개가 예상 밖 응답: 판정 불가", evidence)
    return Outcome(PASS, f"변형 {len(_SC06_VARIANTS)}개 모두 422, DB 불변", evidence)


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="SC-01", name="타인 거래내역 조회 차단 (BOLA)", risk="HIGH", likelihood="L3", impact="I2",
        owasp="API1:2023", cwe="CWE-639",
        expected="403 및 타인 거래 데이터 비공개",
        description="요청 사용자와 계좌 소유자를 서버에서 비교하는지 검사한다(객체 수준 접근제어).",
        fix_guide="모든 객체 ID 접근 경로에서 토큰의 user_id와 계좌 owner_user_id를 서버 측에서 비교한다.",
        execute=_run_sc01,
    ),
    Scenario(
        id="SC-05", name="일반 고객의 관리자 기능 호출 차단 (BFLA)", risk="HIGH", likelihood="L3", impact="I3",
        owasp="API5:2023", cwe="CWE-285",
        expected="403, 계좌 상태 불변(ACTIVE), 감사로그 ACCESS_DENIED 1건",
        description="인증 여부가 아니라 역할(role)로 기능 단위 권한을 검사하는지 확인한다.",
        fix_guide="관리 기능 라우터 전체에 서버 측 역할 검사를 기본값으로 적용한다(기본 거부).",
        execute=_run_sc05,
    ),
    Scenario(
        id="SC-06", name="요청에 필드 끼워넣기 차단 (Mass Assignment)", risk="HIGH", likelihood="L3", impact="I3",
        owasp="API3:2023", cwe="CWE-915",
        expected="422, balance_krw·owner_user_id·status·nickname 모두 불변",
        description="요청 JSON이 바꿀 수 없는 속성(잔액·소유자·상태)까지 반영되지 않는지 검사한다.",
        fix_guide="입력 DTO에 허용 필드만 정의(extra=forbid)하고, DB 갱신은 명시한 컬럼만 대상으로 한다.",
        execute=_run_sc06,
    ),
)


def run_api_scenarios(mode: str, scenario_ids: list[str] | None = None) -> RunResult:
    """고정 시나리오를 지정한 모드의 격리 환경에서 실행하고 공통 결과 모델로 돌려준다."""
    if mode not in RUN_MODES:
        raise ValueError(f"지원하지 않는 모드입니다: {mode!r}")

    def new_env() -> IsolatedEnv:
        return IsolatedEnv(mode)

    result = RunResult(mode=mode)
    for scenario in SCENARIOS:
        if scenario_ids is not None and scenario.id not in scenario_ids:
            continue
        try:
            outcome = scenario.execute(new_env)
        except ControlFailed as exc:
            outcome = Outcome(ERROR, f"양성 대조 실패로 판정 불가: {exc}", "사전 준비 또는 정상 사용 대조가 실패해 안전성을 판단할 수 없음")
        except Exception as exc:  # 스택트레이스·경로는 결과에 넣지 않는다
            logger.exception("시나리오 %s 실행 중 예외", scenario.id)
            outcome = Outcome(ERROR, f"검사 중 예외 발생({type(exc).__name__}): 판정 불가", "내부 로그 참고")
        result.items.append(
            ScenarioItem(
                id=scenario.id, name=scenario.name, risk=scenario.risk, status=outcome.status,
                expected=scenario.expected, observed=outcome.observed, description=scenario.description,
                fix_guide=scenario.fix_guide, evidence=outcome.evidence,
                likelihood=scenario.likelihood, impact=scenario.impact,
                owasp=scenario.owasp, cwe=scenario.cwe, kr_weakness=scenario.kr_weakness,
            )
        )
    return result
