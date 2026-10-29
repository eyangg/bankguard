"""고정 시나리오 실행기 (명세 12장).

핵심 5종: SC-01 BOLA · SC-03 동시 송금 경쟁 조건 · SC-04 멱등성 · SC-05 BFLA · SC-06 Mass Assignment
v2.0 핵심 추가: SC-07 인증 무차별 대입(시도 횟수 제한)
세부 1종: SC-02(T06·T07 0원·음수 금액) — v1.2에서 핵심 집계에서 내려 'detail'로 표시한다.

원칙
- 시나리오(또는 그 변형)마다 독립된 임시 폴더의 새 SQLite DB와 새 앱(TestClient, 인프로세스)을 만든다.
  운영 DB와 다른 시나리오의 상태를 건드리지 않는다. 네트워크 요청은 하지 않는다.
- 판정은 모드 이름이 아니라 실제 응답 코드·본문·DB 상태로만 한다.
- 취약 모드에서는 시나리오가 노리는 결함 하나만 붙은 앱을 만든다(create_app(flaw=시나리오 ID)).
- 양성 대조(정상 사용이 되는가)가 깨지면 권한/검증 때문이 아니라 기능 고장일 수 있으므로 ERROR.
- FAIL은 결함이 응답·DB 상태로 관측될 때만. 5xx·예외·예상 밖 응답은 결함 증거가 아니므로 ERROR로 분리한다.
- 예외는 ERROR로 바꾸되 스택트레이스·로컬 경로는 결과에 넣지 않는다(내부 로그에만 남긴다).
"""
from __future__ import annotations

import logging
import tempfile
import threading
import uuid
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, NamedTuple

from fastapi.testclient import TestClient

from backend.auth_demo import ensure_db, get_conn
from backend.db import connect
from backend.factory import create_app
from scanners.models import ERROR, FAIL, PASS, RunResult, ScenarioItem
from scanners.race_harness import make_racing_get_conn

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

    def __init__(self, mode: str, flaw: str | None = None) -> None:
        self.mode = mode
        self.flaw = flaw
        self._stack = ExitStack()

    def __enter__(self) -> "IsolatedEnv":
        tmp = self._stack.enter_context(
            tempfile.TemporaryDirectory(prefix="bankguard_", ignore_cleanup_errors=True)
        )
        self.db_path = Path(tmp) / "scenario.db"
        self.app = create_app(mode=self.mode, db_path=self.db_path, flaw=self.flaw)
        ensure_db(self.app)  # 결함 전용 스키마를 쓰는 앱은 create_app이 이미 초기화했다(idempotent)
        self.client = self._stack.enter_context(TestClient(self.app))
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

    def balances(self) -> dict[int, int]:
        return {r["id"]: r["balance_krw"] for r in self.query("SELECT id, balance_krw FROM accounts")}

    def total_balance(self) -> int:
        return self.query("SELECT SUM(balance_krw) AS s FROM accounts")[0]["s"]

    def transfers(self) -> list[dict]:
        return self.query("SELECT * FROM transfers ORDER BY id")

    def post_transfer(self, token: dict, from_id: int, to_id: int, amount, request_id: str | None = None):
        return self.client.post(
            "/api/transfers",
            json={"from_account_id": from_id, "to_account_id": to_id, "amount_krw": amount,
                  "request_id": request_id or str(uuid.uuid4())},
            headers=token,
        )


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
    tier: str = "core"


# --- SC-01 BOLA -----------------------------------------------------------------

def _run_sc01(new_env: EnvFactory) -> Outcome:
    with new_env() as env:
        # 준비: B 계좌에 '유출될 데이터'가 있도록 B→C 10,000원 송금 (송금 API는 이 시나리오에서 안전 구현)
        setup = env.post_transfer(TOKEN_B, 102, 103, 10_000)
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


# --- SC-03 동시 송금 경쟁 조건 (lost update) --------------------------------------------

SC03_AMOUNT = 300_000


def _race_two_transfers(env: IsolatedEnv) -> list[tuple[int, dict] | None]:
    """B→A 300,000원 송금 2건(서로 다른 request_id)을 Barrier로 정렬해 동시에 보낸다."""
    start = threading.Barrier(2, timeout=10)  # 두 스레드가 동시에 요청을 시작
    gate = threading.Barrier(2, timeout=10)  # 두 요청이 모두 송금인(B) 행을 읽은 뒤에야 진행(race_harness)
    env.app.dependency_overrides[get_conn] = make_racing_get_conn(gate, 102)
    results: list[tuple[int, dict] | None] = [None, None]

    def worker(index: int) -> None:
        client = TestClient(env.app, raise_server_exceptions=False)  # 서버 예외도 500 응답으로 받는다
        try:
            start.wait()
            resp = client.post(
                "/api/transfers",
                json={"from_account_id": 102, "to_account_id": 101, "amount_krw": SC03_AMOUNT,
                      "request_id": str(uuid.uuid4())},
                headers=TOKEN_B,
            )
            try:
                body = resp.json()
            except ValueError:
                body = {}
            results[index] = (resp.status_code, body)
        except Exception:  # BrokenBarrierError 등: 결과 None → ERROR로 분리
            logger.exception("SC-03 워커 %s 예외", index)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    env.app.dependency_overrides.pop(get_conn, None)
    return results


def _run_sc03(new_env: EnvFactory) -> Outcome:
    # 양성 대조: 동시성 없이 한 건 보내면 정상 처리돼야 한다.
    with new_env() as env:
        resp = env.post_transfer(TOKEN_B, 102, 101, SC03_AMOUNT)
        balances = env.balances()
        if resp.status_code != 201 or balances[102] != 200_000 or balances[101] != 1_300_000:
            raise ControlFailed(f"단건 송금 대조 실패(HTTP {resp.status_code}, 잔액 B={balances[102]})")

    with new_env() as env:
        total_before = env.total_balance()
        results = _race_two_transfers(env)
        balances = env.balances()
        records = env.transfers()
        total_after = env.total_balance()

    codes = [r[0] if r else None for r in results]
    recorded_amount = sum(r["amount_krw"] for r in records)
    b_debited = 500_000 - balances[102]
    evidence = (
        f"B 토큰으로 B→A {SC03_AMOUNT:,}원 2건을 Barrier로 동시 전송 → HTTP {codes}. "
        f"잔액 B={balances[102]:,}, A={balances[101]:,}, 전체 합 {total_before:,}→{total_after:,}, "
        f"송금 기록 {len(records)}건(합계 {recorded_amount:,}원), B 실제 출금 {b_debited:,}원."
    )
    if any(c is None or c >= 500 for c in codes):
        return Outcome(ERROR, f"서버 오류/요청 실패 {codes}: 결함 때문인지 판정 불가", evidence)

    both_accepted = codes.count(201) >= 2
    money_mismatch = total_after != total_before or b_debited != recorded_amount
    if sorted(codes) == [201, 409] and not both_accepted and not money_mismatch \
            and balances[102] == 200_000 and balances[101] == 1_300_000 and len(records) == 1:
        return Outcome(PASS, "201 1건·409 1건, 잔액 합 보존, 송금 기록 1건", evidence)
    if both_accepted or money_mismatch:
        return Outcome(
            FAIL,
            f"HTTP {codes}: 잔액 합 {total_before:,}→{total_after:,}원"
            + (f"(+{total_after - total_before:,}원 복제)" if total_after > total_before else "")
            + f", 기록 {recorded_amount:,}원 vs 실제 출금 {b_debited:,}원",
            evidence,
        )
    return Outcome(ERROR, f"예상 밖 결과 HTTP {codes}: 판정 불가", evidence)


# --- SC-04 멱등성 -----------------------------------------------------------------

def _run_sc04(new_env: EnvFactory) -> Outcome:
    with new_env() as env:
        request_id = str(uuid.uuid4())
        first = env.post_transfer(TOKEN_A, 101, 102, 20_000, request_id)
        balances = env.balances()
        # 양성 대조: 첫 요청은 정상 처리(201, 1회 출금)여야 한다.
        if first.status_code != 201 or balances[101] != 980_000 or len(env.transfers()) != 1:
            raise ControlFailed(f"첫 송금 대조 실패(HTTP {first.status_code}, A={balances[101]})")

        second = env.post_transfer(TOKEN_A, 101, 102, 20_000, request_id)  # 같은 request_id·같은 내용
        conflict = env.post_transfer(TOKEN_A, 101, 102, 30_000, request_id)  # 같은 request_id·다른 금액
        balances = env.balances()
        records = env.transfers()

    evidence = (
        f"같은 request_id로 A→B 20,000원 2회 → HTTP {first.status_code}, {second.status_code}; "
        f"같은 request_id에 30,000원 → HTTP {conflict.status_code}. "
        f"A={balances[101]:,}원(정상 980,000), B={balances[102]:,}원(정상 520,000), 송금 기록 {len(records)}건(정상 1건)."
    )
    codes = [second.status_code, conflict.status_code]
    if any(c >= 500 for c in codes):
        return Outcome(ERROR, f"서버 오류 HTTP {codes}: 결함 때문인지 판정 불가", evidence)

    try:
        replay_ok = (
            second.status_code == 200
            and second.json().get("idempotent_replay") is True
            and second.json().get("transfer_id") == first.json().get("transfer_id")
        )
    except ValueError:
        replay_ok = False
    safe = replay_ok and conflict.status_code == 409 and len(records) == 1 \
        and balances[101] == 980_000 and balances[102] == 520_000
    if safe:
        return Outcome(PASS, "재전송 200(같은 거래 ID), ID 충돌 409, 출금 1회·기록 1건", evidence)

    double_debit = balances[101] < 980_000 or len(records) > 1
    accepted_conflict = 200 <= conflict.status_code < 300
    if second.status_code == 201 or double_debit or accepted_conflict:
        return Outcome(
            FAIL,
            f"같은 요청이 새 거래로 처리됨: 재전송 HTTP {second.status_code}, A 잔액 {balances[101]:,}원, 기록 {len(records)}건",
            evidence,
        )
    return Outcome(ERROR, f"예상 밖 응답 HTTP {codes}: 판정 불가", evidence)


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


# --- SC-07 인증 무차별 대입 (시도 횟수 제한) ----------------------------------------------------

# 문서용 예약 주소(RFC 5737 TEST-NET)라 실제 주소가 아니다. TestClient가 요청의 연결 주소로 쓴다.
SC07_ATTACKER = ("203.0.113.10", 50000)
SC07_OTHER_CLIENT = ("198.51.100.20", 50000)
# 틀린 토큰 7개 뒤 8번째에 실제 존재하는 토큰(고객 C)을 맞히는 공격. 제한(5회)을 넘긴 뒤의 '정답'이 통하는지 본다.
_SC07_GUESSES = tuple(f"demo-token-guess-{i:02d}" for i in range(1, 8)) + ("demo-token-c",)


def _auth_client(env: IsolatedEnv, address: tuple[str, int]) -> TestClient:
    return TestClient(env.app, raise_server_exceptions=False, client=address)


def _run_sc07(new_env: EnvFactory) -> Outcome:
    # 양성 대조: 제한보다 적게 틀린 뒤 맞는 토큰은 통과해야 한다(정상 사용자를 잘못 잠그지 않음).
    with new_env() as env:
        client = _auth_client(env, SC07_ATTACKER)
        typo = [client.get("/api/accounts", headers={"X-Demo-Token": t}).status_code
                for t in ("demo-token-typo-1", "demo-token-typo-2")]
        ok = client.get("/api/accounts", headers={"X-Demo-Token": "demo-token-c"})
        if typo != [401, 401] or ok.status_code != 200:
            raise ControlFailed(f"제한 이하 실패 후 정상 로그인 대조 실패(HTTP {typo} → {ok.status_code})")

    with new_env() as env:
        attacker = _auth_client(env, SC07_ATTACKER)
        responses = [attacker.get("/api/accounts", headers={"X-Demo-Token": t}) for t in _SC07_GUESSES]
        # 양성 대조: 잠금은 공격 클라이언트에만 걸려야 한다(다른 클라이언트의 정상 사용자는 200).
        other = _auth_client(env, SC07_OTHER_CLIENT).get("/api/accounts", headers=TOKEN_B)
        counts = {
            r["event_type"]: r["n"]
            for r in env.query(
                "SELECT event_type, COUNT(*) AS n FROM audit_log"
                " WHERE event_type IN ('AUTH_FAIL', 'AUTH_LOCKED') GROUP BY event_type"
            )
        }

    codes = [r.status_code for r in responses]
    retry_after = [r.headers.get("Retry-After") for r in responses if r.status_code == 429]
    evidence = (
        f"공격 클라이언트(203.0.113.10)에서 틀린 토큰 7개 뒤 실제 토큰(고객 C) 순서로 GET /api/accounts → HTTP {codes}. "
        f"429 응답의 Retry-After={retry_after or '없음'}. 감사로그 AUTH_FAIL={counts.get('AUTH_FAIL', 0)}건, "
        f"AUTH_LOCKED={counts.get('AUTH_LOCKED', 0)}건. 다른 클라이언트(198.51.100.20)의 고객 B → HTTP {other.status_code}. "
        "양성 대조: 2회 틀린 뒤 맞는 토큰은 200."
    )
    if any(c >= 500 for c in codes + [other.status_code]):
        return Outcome(ERROR, f"서버 오류 HTTP {codes}: 결함 때문인지 판정 불가", evidence)
    if codes[:5] != [401] * 5:
        return Outcome(ERROR, f"틀린 토큰 5회가 모두 401이 아님 {codes[:5]}: 판정 불가", evidence)
    if other.status_code != 200:
        raise ControlFailed(f"다른 클라이언트의 정상 사용자가 차단됨(HTTP {other.status_code})")

    guessed = codes[-1] == 200
    limited = codes[5:] == [429] * (len(codes) - 5) and all(v and v.isdigit() for v in retry_after)
    if limited and counts.get("AUTH_LOCKED", 0) == len(codes) - 5:
        return Outcome(PASS, "5회 실패 뒤 6번째부터 429(Retry-After), 잠금 중 실제 토큰도 거절, 다른 클라이언트 정상", evidence)
    if guessed or 401 in codes[5:]:
        return Outcome(
            FAIL,
            f"제한 없이 추측 계속 가능: 6번째 이후 HTTP {codes[5:]}"
            + (", 8번째 추측(실제 토큰)이 200으로 통과" if guessed else ""),
            evidence,
        )
    return Outcome(ERROR, f"예상 밖 응답 HTTP {codes}: 판정 불가", evidence)


# --- SC-02 (T06·T07) 잘못된 금액 -----------------------------------------------------------

_SC02_AMOUNTS = (("T06", -10_000), ("T07", 0))


def _run_sc02(new_env: EnvFactory) -> Outcome:
    # 양성 대조: 정상 금액은 처리돼야 한다.
    with new_env() as env:
        ok = env.post_transfer(TOKEN_A, 101, 102, 20_000)
        if ok.status_code != 201 or env.balances()[101] != 980_000:
            raise ControlFailed(f"정상 송금 대조 실패(HTTP {ok.status_code})")

    unsafe, errors, lines = 0, 0, []
    for label, amount in _SC02_AMOUNTS:
        with new_env() as env:
            before = env.balances()
            resp = env.post_transfer(TOKEN_A, 101, 102, amount)
            after = env.balances()
            records = env.transfers()
        moved = {k: after[k] - before[k] for k in before if after[k] != before[k]}
        if resp.status_code >= 500:
            errors += 1
            lines.append(f"{label}({amount:,}원): HTTP {resp.status_code}, 판정 불가")
        elif 200 <= resp.status_code < 300 or moved or records:
            unsafe += 1
            lines.append(
                f"{label}({amount:,}원): HTTP {resp.status_code}, 잔액 변화={moved or '없음'}, "
                f"기록 금액={[r['amount_krw'] for r in records] or '없음'}"
            )
        elif resp.status_code == 422:
            lines.append(f"{label}({amount:,}원): HTTP 422, DB 불변")
        else:
            errors += 1
            lines.append(f"{label}({amount:,}원): HTTP {resp.status_code}, 판정 불가")

    evidence = "A 토큰으로 A→B 송금 — " + "; ".join(lines) + ". 양성 대조: 20,000원은 201."
    if unsafe:
        return Outcome(FAIL, f"{len(_SC02_AMOUNTS)}건 중 {unsafe}건이 잘못된 금액을 수락(서버 검증 없음)", evidence)
    if errors:
        return Outcome(ERROR, f"{len(_SC02_AMOUNTS)}건 중 {errors}건이 예상 밖 응답: 판정 불가", evidence)
    return Outcome(PASS, "음수·0원 모두 422, DB 불변", evidence)


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
        id="SC-03", name="동시 송금 경쟁 조건 차단 (lost update)", risk="HIGH", likelihood="L2", impact="I3",
        # CWE 원문 확인(MITRE): 362 Race Condition, 367 TOCTOU. OWASP API 2023(10개 항목)에는 정확히 대응하는 항목이 없어 비움.
        owasp="", cwe="CWE-362 / CWE-367",
        expected="동시 2건 중 정확히 1건 201·1건 409, 잔액 합 보존, 송금 기록 1건",
        description="같은 잔액으로 동시에 출금 요청 2건이 들어와도 잔액 이상이 출금되거나 돈이 복제되지 않는지 검사한다.",
        fix_guide="잔액 확인과 차감을 하나의 원자적 연산으로 묶는다(BEGIN IMMEDIATE + 조건부 UPDATE).",
        execute=_run_sc03,
    ),
    Scenario(
        id="SC-04", name="중복 송금 방지 (멱등성)", risk="HIGH", likelihood="L3", impact="I3",
        # CWE 원문 확인(MITRE): 837 Improper Enforcement of a Single, Unique Action. OWASP API 2023에는 정확히 대응하는 항목이 없어 비움.
        owasp="", cwe="CWE-837",
        expected="같은 request_id 재전송은 200·같은 거래 ID(출금 1회), 다른 금액은 409",
        description="네트워크 재시도 등으로 같은 요청이 두 번 와도 이중 출금되지 않는지 검사한다.",
        fix_guide="클라이언트가 보낸 request_id를 유일키로 저장·조회하고 payload_fingerprint로 내용 변경을 구별한다.",
        execute=_run_sc04,
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
    Scenario(
        id="SC-07", name="인증 무차별 대입 차단 (시도 횟수 제한)", risk="HIGH", likelihood="L2", impact="I3",
        # CWE 원문 명칭: 307 Improper Restriction of Excessive Authentication Attempts. OWASP API2:2023 Broken Authentication.
        owasp="API2:2023", cwe="CWE-307",
        expected="5회 실패 뒤 6번째 요청부터 429+Retry-After, 잠금 중엔 실제 토큰도 거절, 다른 클라이언트는 정상 200",
        description="잘못된 토큰을 반복해 보내는 추측 공격을 서버가 횟수로 제한하는지 검사한다.",
        fix_guide="클라이언트별 인증 실패를 세어 제한을 넘으면 일시 잠그고, 확인과 기록은 원자적으로(시도 선예약) 처리한다.",
        execute=_run_sc07,
    ),
    Scenario(
        id="SC-02", name="잘못된 송금 금액 차단 (T06·T07, 0원·음수)", risk="HIGH", likelihood="L3", impact="I3",
        # CWE 원문 확인(MITRE): 602 Client-Side Enforcement of Server-Side Security, 20 Improper Input Validation.
        # OWASP API 2023에는 입력 검증을 직접 다루는 항목이 없어 비움.
        owasp="", cwe="CWE-602 / CWE-20", tier="detail",
        expected="422, 잔액 변동 없음, 신규 송금 기록 없음",
        description="서버가 금액을 직접 검증하는지(클라이언트 검증에 의존하지 않는지) 확인한다.",
        fix_guide="서버 입력 모델에서 금액을 정수 1 이상 상한 이하로 강제한다(StrictInt + gt/le).",
        execute=_run_sc02,
    ),
)


def run_api_scenarios(mode: str, scenario_ids: list[str] | None = None) -> RunResult:
    """고정 시나리오를 지정한 모드의 격리 환경에서 실행하고 공통 결과 모델로 돌려준다."""
    if mode not in RUN_MODES:
        raise ValueError(f"지원하지 않는 모드입니다: {mode!r}")

    result = RunResult(mode=mode)
    for scenario in SCENARIOS:
        if scenario_ids is not None and scenario.id not in scenario_ids:
            continue

        def new_env(flaw: str | None = scenario.id if mode == "vulnerable" else None) -> IsolatedEnv:
            return IsolatedEnv(mode, flaw)

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
                tier=scenario.tier,
            )
        )
    return result
