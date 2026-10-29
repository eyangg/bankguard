"""⚠️ 취약 비교 구현 — 검사(비교) 전용. 절대 공개 서버에 붙이지 않는다.

이 모듈의 코드는 "일부러" 보안 결함을 담고 있다. 같은 안전성 검사를 안전 모드와 취약 모드에 돌려
FAIL → PASS 개선을 실제 응답·DB 상태로 보여 주기 위한 교육용 비교 대상이다. 모든 데이터는 허구이며
외부 시스템에 요청하지 않는다.

구성 원칙: 결함 1개당 취약 구현 1개. 각 구현은 대응하는 안전 코드의 복사본이고, 결함 부분 외에는
한 줄도 다르지 않다(스위치·플래그 없음). 그래서 `diff 안전코드 취약코드`가 곧 "수정 패치"가 된다.
tests/test_lab_diff_shape.py가 이 "결함 부분만 다르다"를 AST 비교로 강제한다.

사용 범위(코드로 강제됨):
- backend.factory.create_app(mode="vulnerable", flaw="SC-xx", db_path=...)가 한 번에 결함 하나만 붙인다.
- 그 팩토리는 시스템 임시 폴더 안의 명시적 DB 경로가 아니면 ValueError를 낸다.
- 이 모듈은 vulnerable일 때만 지연 import된다. backend.main(공개 진입점)은 import하지 않는다.

결함 목록: SC-01 BOLA · SC-02 금액 서버 검증 누락(T06·T07) · SC-03 lost update ·
SC-04 멱등성 없음 · SC-05 BFLA · SC-06 Mass Assignment · SC-07 인증 시도 횟수 제한 없음.
"""
import sqlite3
import uuid
from dataclasses import dataclass, field

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator

from backend import audit, repository, routes
from backend.auth_demo import AuthUser, current_user, get_conn
from backend.config import MAX_TRANSFER_KRW
from backend.db import SCHEMA_SQL
from backend.schemas import (
    AccountNicknameOut,
    FreezeOut,
    TransactionOut,
    TransferIn,
    TransferOut,
)
from backend.services.transfers import (
    TransferRejected,
    TransferResult,
    execute_transfer,
    payload_fingerprint,
)

LAB_TAG = "INSECURE-LAB (검사 전용)"


@dataclass(frozen=True)
class LabSetup:
    """결함 하나를 붙이는 데 필요한 것: 먼저 등록할 라우터와(필요할 때만) 전용 DB 스키마·의존성 교체."""

    router: APIRouter
    schema_sql: str | None = None
    # 결함이 라우트가 아니라 공통 의존성(인증)에 있을 때만 쓴다(SC-07). {안전 의존성: 취약 의존성}
    dependency_overrides: dict = field(default_factory=dict)


# ===== SC-01 BOLA ========================================================================
# 실제 버그 패턴: 객체 ID로 조회하면서 소유자 확인을 빠뜨림(BOLA/IDOR, CWE-639).
# 근거 사례: 2021 Peloton API가 임의 사용자에게 타인 계정 데이터를 노출(Pen Test Partners 보고, Salt Security는 OWASP API1 BOLA로 분류).
# 안전 코드와의 차이: `owner_user_id != user.user_id` 검사 블록 삭제.
def lab_list_account_transactions(
    account_id: int,
    user: AuthUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
):
    account = repository.get_account(conn, account_id)
    if account is None:
        audit.record(
            conn, audit.NOT_FOUND, 404,
            actor_user_id=user.user_id, token_fp=user.token_fp,
            target_account_id=account_id, detail="거래내역 조회: 계좌 없음",
        )
        raise HTTPException(status_code=404, detail="계좌를 찾을 수 없습니다.")
    return repository.list_transactions(conn, account_id)


def _setup_bola() -> LabSetup:
    lab = APIRouter(prefix="/api", tags=[LAB_TAG])
    lab.add_api_route(
        "/accounts/{account_id}/transactions",
        lab_list_account_transactions,
        methods=["GET"],
        response_model=list[TransactionOut],
    )
    return LabSetup(lab)


# ===== SC-05 BFLA ========================================================================
# 실제 버그 패턴: 관리 라우트에 '로그인'만 걸고 역할(role) 검사 의존성을 빠뜨림(BFLA, CWE-285).
# 근거 사례: Snipe-IT CVE-2024-5685(Checkmarx Zero 공개, 6.4.2 수정)는 API 호출로 권한을 바꾸는 기능 단위 인가 결함이나, '일반 사용자의 관리자 API 호출'과 완전히 같은 사례는 아님.
# 안전 코드와의 차이: 핸들러는 routes.freeze_account를 그대로 재사용하고, 라우터에서 dependencies=[Depends(require_admin)] 한 줄만 없다.
def _setup_bfla() -> LabSetup:
    lab = APIRouter(prefix="/api/admin", tags=[LAB_TAG])
    lab.add_api_route(
        "/accounts/{account_id}/freeze",
        routes.freeze_account,
        methods=["POST"],
        response_model=FreezeOut,
    )
    return LabSetup(lab)


# ===== SC-06 Mass Assignment (BOPLA) =====================================================
# 실제 버그 패턴: 요청 본문의 키를 허용 목록 없이 갱신 대상으로 반영(CWE-915).
# 근거 사례: 2012-03 GitHub 공개키 갱신 폼의 Rails mass assignment로 Egor Homakov가 rails 조직에 키를 추가(GitHub 공식 블로그 2012-03-04).
# 안전 코드와의 차이: 입력 모델이 extra="allow"이고, 갱신문이 `SET nickname = ?` 고정문 대신 요청 키로 조립된다.
class NicknameUpdateLoose(BaseModel):
    """별칭 변경 요청. 허용 필드는 nickname 하나뿐이며 그 외 필드는 422 (SC-06 안전 기준)."""

    model_config = ConfigDict(extra="allow")

    nickname: StrictStr = Field(min_length=1, max_length=20)


def lab_update_account_nickname(
    account_id: int,
    body: NicknameUpdateLoose,
    user: AuthUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
):
    """본인 계좌의 별칭만 변경한다. 다른 필드가 섞이면 스키마 단계에서 422(Mass Assignment 방지)."""
    account = repository.get_account(conn, account_id)
    if account is None:
        audit.record(
            conn, audit.NOT_FOUND, 404,
            actor_user_id=user.user_id, token_fp=user.token_fp,
            target_account_id=account_id, detail="별칭 변경: 계좌 없음",
        )
        raise HTTPException(status_code=404, detail="계좌를 찾을 수 없습니다.")
    if account["owner_user_id"] != user.user_id:
        audit.record(
            conn, audit.ACCESS_DENIED, 403,
            actor_user_id=user.user_id, token_fp=user.token_fp,
            target_account_id=account_id,
            detail=f"타인 계좌 별칭 변경 시도 {audit.mask_account_no(account['account_no'])}",
        )
        raise HTTPException(status_code=403, detail="본인 소유 계좌만 변경할 수 있습니다.")
    columns = {r["name"] for r in conn.execute("PRAGMA table_info(accounts)")} - {"id"}
    updates = {key: value for key, value in body.model_dump().items() if key in columns}
    set_clause = ", ".join(f"{column} = ?" for column in updates)
    try:
        conn.execute(f"UPDATE accounts SET {set_clause} WHERE id = ?", (*updates.values(), account_id))
    except (sqlite3.IntegrityError, sqlite3.InterfaceError, sqlite3.ProgrammingError):
        raise HTTPException(status_code=422, detail="변경 값이 올바르지 않습니다.")
    return AccountNicknameOut(
        id=account["id"], account_no=account["account_no"], nickname=body.nickname
    )


def _setup_mass_assignment() -> LabSetup:
    lab = APIRouter(prefix="/api", tags=[LAB_TAG])
    lab.add_api_route(
        "/accounts/{account_id}",
        lab_update_account_nickname,
        methods=["PATCH"],
        response_model=AccountNicknameOut,
    )
    return LabSetup(lab)


# ===== 송금 라우트 배선 (SC-02·03·04 공통 plumbing: 결함 아님) ================================
# 세 결함은 모두 POST /api/transfers에 걸린다. 핸들러 본문은 routes.create_transfer와 같고
# 어떤 service 함수/입력 모델을 쓰느냐만 다르다. 결함 자체는 아래 service·model 코드에 있다.
def _make_transfer_router(execute, body_model) -> APIRouter:
    def lab_create_transfer(
        body: body_model,
        response: Response,
        user: AuthUser = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        try:
            result = execute(
                conn, user.user_id, body.from_account_id, body.to_account_id,
                body.amount_krw, body.request_id,
            )
        except TransferRejected as rejected:
            audit.record(
                conn, rejected.event_type, rejected.http_status,
                actor_user_id=user.user_id, token_fp=user.token_fp,
                target_account_id=rejected.target_account_id, detail=rejected.detail,
            )
            raise HTTPException(status_code=rejected.http_status, detail=rejected.message)

        response.status_code = 200 if result.replay else 201
        audit.record(
            conn,
            audit.IDEMPOTENT_REPLAY if result.replay else audit.TRANSFER_OK,
            response.status_code,
            actor_user_id=user.user_id, token_fp=user.token_fp,
            target_account_id=result.from_account_id,
            detail=f"{result.sender_account_no}->{result.recipient_account_no} amount={result.amount_krw}",
        )
        return TransferOut(
            transfer_id=result.transfer_id,
            request_id=result.request_id,
            from_account_id=result.from_account_id,
            to_account_id=result.to_account_id,
            amount_krw=result.amount_krw,
            idempotent_replay=result.replay,
        )

    lab = APIRouter(prefix="/api", tags=[LAB_TAG])
    lab.add_api_route("/transfers", lab_create_transfer, methods=["POST"], response_model=TransferOut)
    return lab


# ===== SC-03 Lost update (경쟁 조건) =====================================================
# 실제 버그 패턴: 읽어 둔 잔액으로 검사·계산한 뒤 그 값으로 덮어쓰는 read-modify-write를 트랜잭션 없이 수행(TOCTOU/lost update, CWE-362·CWE-367).
# 근거 사례: 2015-05 Starbucks 기프트카드 이체의 race condition(Egor Homakov 보고, 동시 요청으로 잔액 복제; Schneier 블로그 소개). 2014 Flexcoin 도난도 경쟁 조건으로 분석되나 이는 외부 분석이며 회사 공식 설명은 아님.
# 안전 코드와의 차이: BEGIN IMMEDIATE/COMMIT 삭제, 조건부 차감 UPDATE 대신 읽은 잔액으로 계산해 `SET balance_krw = ?`로 덮어쓴다.
def execute_transfer_lost_update(
    conn: sqlite3.Connection,
    user_id: int,
    from_account_id: int,
    to_account_id: int,
    amount_krw: int,
    request_id: str,
) -> TransferResult:
    sender = repository.get_account(conn, from_account_id)
    if sender is None:
        raise TransferRejected(
            404, audit.NOT_FOUND, "출금 계좌를 찾을 수 없습니다.", from_account_id, "출금 계좌 없음"
        )
    if sender["owner_user_id"] != user_id:
        raise TransferRejected(
            403,
            audit.ACCESS_DENIED,
            "본인 소유가 아닌 계좌에서는 출금할 수 없습니다.",
            from_account_id,
            f"타인 계좌 출금 시도 {audit.mask_account_no(sender['account_no'])}",
        )
    if from_account_id == to_account_id:
        raise TransferRejected(
            400,
            audit.TRANSFER_REJECTED,
            "같은 계좌로는 송금할 수 없습니다.",
            from_account_id,
            f"자기 계좌 송금 {audit.mask_account_no(sender['account_no'])}",
        )
    recipient = repository.get_account(conn, to_account_id)
    if recipient is None:
        raise TransferRejected(
            404, audit.NOT_FOUND, "입금 계좌를 찾을 수 없습니다.", to_account_id, "입금 계좌 없음"
        )

    fp = payload_fingerprint(from_account_id, to_account_id, amount_krw)
    s_mask = audit.mask_account_no(sender["account_no"])
    r_mask = audit.mask_account_no(recipient["account_no"])

    try:
        existing = conn.execute(
            "SELECT id, payload_fingerprint FROM transfers WHERE request_id = ?", (request_id,)
        ).fetchone()
        if existing is not None:
            if existing["payload_fingerprint"] != fp:
                raise TransferRejected(
                    409,
                    audit.TRANSFER_REJECTED,
                    "같은 request_id로 다른 내용의 송금이 이미 접수되었습니다.",
                    from_account_id,
                    f"request_id 충돌 {s_mask}->{r_mask}",
                )
            transfer_id, replay = existing["id"], True
        else:
            if sender["status"] != "ACTIVE":
                raise TransferRejected(
                    409,
                    audit.TRANSFER_REJECTED,
                    "출금 계좌가 지급정지 상태입니다.",
                    from_account_id,
                    f"지급정지 계좌 출금 시도 {s_mask}",
                )
            if sender["balance_krw"] < amount_krw:
                raise TransferRejected(
                    409,
                    audit.TRANSFER_REJECTED,
                    "잔액이 부족합니다.",
                    from_account_id,
                    f"잔액 부족 {s_mask} amount={amount_krw}",
                )
            conn.execute(
                "UPDATE accounts SET balance_krw = ? WHERE id = ?",
                (sender["balance_krw"] - amount_krw, from_account_id),
            )
            conn.execute(
                "UPDATE accounts SET balance_krw = balance_krw + ? WHERE id = ?",
                (amount_krw, to_account_id),
            )
            cur = conn.execute(
                "INSERT INTO transfers (request_id, sender_account_id, recipient_account_id,"
                " amount_krw, payload_fingerprint, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request_id, from_account_id, to_account_id, amount_krw, fp, audit.utc_now_iso()),
            )
            transfer_id, replay = cur.lastrowid, False
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

    return TransferResult(
        transfer_id, request_id, from_account_id, to_account_id, amount_krw, replay, s_mask, r_mask
    )


def _setup_lost_update() -> LabSetup:
    return LabSetup(_make_transfer_router(execute_transfer_lost_update, TransferIn))


# ===== SC-04 멱등성 없음 =================================================================
# 실제 버그 패턴: 멱등키를 클라이언트에서 받지 않고 서버가 요청마다 새로 만들어, 재시도가 매번 새 거래가 됨.
# 근거 사례: 공개된 대형 사고 사례는 확인하지 못했다. 설계 기준은 Stripe API 문서 'Idempotent requests'(같은 Idempotency-Key 재요청은 최초 결과를 반환)와 IETF Idempotency-Key 헤더 초안.
# 안전 코드와의 차이: 함수 첫머리의 `request_id = str(uuid.uuid4())` 한 줄뿐(클라이언트 값을 버리고 서버가 만든 ID를 저장·조회한다).
def execute_transfer_no_idempotency(
    conn: sqlite3.Connection,
    user_id: int,
    from_account_id: int,
    to_account_id: int,
    amount_krw: int,
    request_id: str,
) -> TransferResult:
    request_id = str(uuid.uuid4())
    sender = repository.get_account(conn, from_account_id)
    if sender is None:
        raise TransferRejected(
            404, audit.NOT_FOUND, "출금 계좌를 찾을 수 없습니다.", from_account_id, "출금 계좌 없음"
        )
    if sender["owner_user_id"] != user_id:
        raise TransferRejected(
            403,
            audit.ACCESS_DENIED,
            "본인 소유가 아닌 계좌에서는 출금할 수 없습니다.",
            from_account_id,
            f"타인 계좌 출금 시도 {audit.mask_account_no(sender['account_no'])}",
        )
    if from_account_id == to_account_id:
        raise TransferRejected(
            400,
            audit.TRANSFER_REJECTED,
            "같은 계좌로는 송금할 수 없습니다.",
            from_account_id,
            f"자기 계좌 송금 {audit.mask_account_no(sender['account_no'])}",
        )
    recipient = repository.get_account(conn, to_account_id)
    if recipient is None:
        raise TransferRejected(
            404, audit.NOT_FOUND, "입금 계좌를 찾을 수 없습니다.", to_account_id, "입금 계좌 없음"
        )

    fp = payload_fingerprint(from_account_id, to_account_id, amount_krw)
    s_mask = audit.mask_account_no(sender["account_no"])
    r_mask = audit.mask_account_no(recipient["account_no"])

    conn.execute("BEGIN IMMEDIATE")
    try:
        existing = conn.execute(
            "SELECT id, payload_fingerprint FROM transfers WHERE request_id = ?", (request_id,)
        ).fetchone()
        if existing is not None:
            if existing["payload_fingerprint"] != fp:
                raise TransferRejected(
                    409,
                    audit.TRANSFER_REJECTED,
                    "같은 request_id로 다른 내용의 송금이 이미 접수되었습니다.",
                    from_account_id,
                    f"request_id 충돌 {s_mask}->{r_mask}",
                )
            transfer_id, replay = existing["id"], True
        else:
            # 지급정지 확인과 잔액 확인을 차감과 같은 문장에 묶는다. 읽은 뒤 정지되는 경우(TOCTOU)도 막는다.
            debited = conn.execute(
                "UPDATE accounts SET balance_krw = balance_krw - ?"
                " WHERE id = ? AND balance_krw >= ? AND status = 'ACTIVE'",
                (amount_krw, from_account_id, amount_krw),
            )
            if debited.rowcount != 1:
                current = conn.execute(
                    "SELECT status FROM accounts WHERE id = ?", (from_account_id,)
                ).fetchone()
                if current is not None and current["status"] != "ACTIVE":
                    raise TransferRejected(
                        409,
                        audit.TRANSFER_REJECTED,
                        "출금 계좌가 지급정지 상태입니다.",
                        from_account_id,
                        f"지급정지 계좌 출금 시도 {s_mask}",
                    )
                raise TransferRejected(
                    409,
                    audit.TRANSFER_REJECTED,
                    "잔액이 부족합니다.",
                    from_account_id,
                    f"잔액 부족 {s_mask} amount={amount_krw}",
                )
            conn.execute(
                "UPDATE accounts SET balance_krw = balance_krw + ? WHERE id = ?",
                (amount_krw, to_account_id),
            )
            cur = conn.execute(
                "INSERT INTO transfers (request_id, sender_account_id, recipient_account_id,"
                " amount_krw, payload_fingerprint, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (request_id, from_account_id, to_account_id, amount_krw, fp, audit.utc_now_iso()),
            )
            transfer_id, replay = cur.lastrowid, False
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise

    return TransferResult(
        transfer_id, request_id, from_account_id, to_account_id, amount_krw, replay, s_mask, r_mask
    )


def _setup_no_idempotency() -> LabSetup:
    return LabSetup(_make_transfer_router(execute_transfer_no_idempotency, TransferIn))


# ===== SC-02 금액 서버 검증 누락 (T06·T07) ==============================================
# 실제 버그 패턴: 금액 검증을 클라이언트에만 두고 서버는 일반 int로 수용(CWE-602 Client-Side Enforcement of Server-Side Security, CWE-20).
# 근거 사례: WooCommerce 'Wallet System' 플러그인 2.8.0 미만이 이체 금액의 양수 여부를 검증하지 않음 — CVE-2026-93509(WPScan 등록, OpenCVE 기준 CVSS 6.5).
# 안전 코드와의 차이: 입력 모델의 `amount_krw: StrictInt = Field(gt=0, le=MAX)`가 `amount_krw: int` 한 줄로 바뀐다.
# 전제: 안전 DB에는 `CHECK (amount_krw > 0)`가 있어 음수/0은 500으로 막힌다(다층 방어). 서버 검증 누락의 실제 영향을
#       보려면 DB 제약이 없는 시스템과 같게 이 결함 전용 스키마(아래)에서만 해당 CHECK를 뺀다(명세 5장 허용).
class TransferInLoose(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_account_id: StrictInt
    to_account_id: StrictInt
    amount_krw: int
    request_id: StrictStr

    @field_validator("request_id")
    @classmethod
    def _must_be_uuid(cls, v: str) -> str:
        try:
            return str(uuid.UUID(v))  # 소문자 하이픈 표준형으로 정규화
        except ValueError as exc:
            raise ValueError("request_id는 UUID 문자열이어야 합니다.") from exc


def schema_without_amount_check() -> str:
    needle = " CHECK (amount_krw > 0)"
    if needle not in SCHEMA_SQL:
        raise RuntimeError("안전 스키마에서 amount_krw CHECK를 찾지 못했습니다: 스키마가 바뀌었는지 확인하세요.")
    return SCHEMA_SQL.replace(needle, "")


def _setup_int_amount() -> LabSetup:
    return LabSetup(
        _make_transfer_router(execute_transfer, TransferInLoose),
        schema_sql=schema_without_amount_check(),
    )


# ===== SC-07 인증 시도 횟수 제한 없음 ========================================================
# 실제 버그 패턴: 인증 실패를 세지 않아 토큰·코드를 무제한으로 추측할 수 있음(CWE-307, OWASP API2:2023).
# 근거 사례: 2019-07 Instagram 모바일 비밀번호 재설정의 6자리 코드를 무차별 대입 가능, 시도 제한은 IP 분산·동시 요청으로 우회(Laxman Muthiyah 보고, The Hacker News·Security Affairs 보도).
# 안전 코드와의 차이: auth_demo.current_user에서 시도 예약·잠금(429) 블록과 성공 시 예약 해제 한 줄을 삭제.
def lab_current_user(
    conn: sqlite3.Connection = Depends(get_conn),
    x_demo_token: str | None = Header(default=None),
) -> AuthUser:
    fp = audit.token_fingerprint(x_demo_token)
    user = repository.get_user_by_token(conn, x_demo_token) if x_demo_token else None
    if user is None:
        audit.record(
            conn,
            audit.AUTH_FAIL,
            401,
            token_fp=fp,
            detail="토큰 없음" if not x_demo_token else "토큰 불일치",
        )
        raise HTTPException(status_code=401, detail="인증 토큰이 없거나 올바르지 않습니다.")
    return AuthUser(user_id=user["id"], token_fp=fp, role=user["role"])


def _setup_no_auth_limit() -> LabSetup:
    # 라우트는 모두 안전 구현 그대로 두고, 모든 보호 경로가 쓰는 인증 의존성만 바꿔 끼운다.
    return LabSetup(APIRouter(), dependency_overrides={current_user: lab_current_user})


# 결함 ID → 설치 함수. 한 번에 하나만 붙는다.
LAB_FLAWS = {
    "SC-01": _setup_bola,
    "SC-02": _setup_int_amount,
    "SC-03": _setup_lost_update,
    "SC-04": _setup_no_idempotency,
    "SC-05": _setup_bfla,
    "SC-06": _setup_mass_assignment,
    "SC-07": _setup_no_auth_limit,
}


def build_lab(flaw: str) -> LabSetup:
    if not isinstance(flaw, str) or flaw not in LAB_FLAWS:
        raise ValueError(f"알 수 없는 결함 ID입니다: {flaw!r} (가능: {sorted(LAB_FLAWS)}, 한 번에 하나만)")
    return LAB_FLAWS[flaw]()
