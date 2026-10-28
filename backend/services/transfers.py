"""안전한 송금 구현 (명세 5장 불변식, 6.5, 7장 SC-03/SC-04).

- 출금 차감은 조건부 UPDATE(`balance_krw >= ?`)로 검증과 차감을 한 문장에 묶는다.
- BEGIN IMMEDIATE로 쓰기를 직렬화하고, 차감·입금·송금 기록을 하나의 트랜잭션으로 처리한다.
- 같은 request_id는 payload_fingerprint가 같으면 기존 거래를 재사용하고, 다르면 409로 거절한다.
- 감사 로그는 이 모듈이 쓰지 않는다. 호출자가 트랜잭션 종료(롤백 포함) 후에 기록한다.
"""
from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass

from backend import audit, repository


class TransferRejected(Exception):
    """업무 규칙·권한 위반으로 송금을 거절. DB에는 아무 변경도 남지 않는다."""

    def __init__(
        self,
        http_status: int,
        event_type: str,
        message: str,
        target_account_id: int | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.http_status = http_status
        self.event_type = event_type
        self.message = message
        self.target_account_id = target_account_id
        self.detail = detail


@dataclass(frozen=True)
class TransferResult:
    transfer_id: int
    request_id: str
    from_account_id: int
    to_account_id: int
    amount_krw: int
    replay: bool
    sender_account_no: str
    recipient_account_no: str


def payload_fingerprint(from_account_id: int, to_account_id: int, amount_krw: int) -> str:
    """같은 request_id로 들어온 요청 내용이 같은지 구별하는 지문."""
    raw = f"{from_account_id}:{to_account_id}:{amount_krw}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def execute_transfer(
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
