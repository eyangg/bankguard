"""안전 모드 REST 라우트 (명세 6.3~6.5). /health는 factory.py에 있다."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Response

from backend import audit, repository
from backend.auth_demo import AuthUser, current_user, get_conn
from backend.schemas import AccountOut, TransactionOut, TransferIn, TransferOut
from backend.services.transfers import TransferRejected, execute_transfer

router = APIRouter(prefix="/api", tags=["bank"])


@router.get("/accounts", response_model=list[AccountOut])
def list_my_accounts(
    user: AuthUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
):
    """토큰에 연결된 사용자 본인의 계좌만 반환한다."""
    return [dict(r) for r in repository.list_accounts_for_user(conn, user.user_id)]


@router.get("/accounts/{account_id}/transactions", response_model=list[TransactionOut])
def list_account_transactions(
    account_id: int,
    user: AuthUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
):
    """소유권 확인 후 거래내역 반환. 존재하지 않으면 404, 타인 계좌면 403."""
    account = repository.get_account(conn, account_id)
    if account is None:
        audit.record(
            conn, audit.NOT_FOUND, 404,
            actor_user_id=user.user_id, token_fp=user.token_fp,
            target_account_id=account_id, detail="거래내역 조회: 계좌 없음",
        )
        raise HTTPException(status_code=404, detail="계좌를 찾을 수 없습니다.")
    if account["owner_user_id"] != user.user_id:
        audit.record(
            conn, audit.ACCESS_DENIED, 403,
            actor_user_id=user.user_id, token_fp=user.token_fp,
            target_account_id=account_id,
            detail=f"타인 계좌 거래내역 조회 시도 {audit.mask_account_no(account['account_no'])}",
        )
        raise HTTPException(status_code=403, detail="본인 소유 계좌만 조회할 수 있습니다.")
    return repository.list_transactions(conn, account_id)


@router.post("/transfers", response_model=TransferOut)
def create_transfer(
    body: TransferIn,
    response: Response,
    user: AuthUser = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
):
    """첫 성공 201, 동일 request_id·동일 내용 재요청 200(idempotent_replay=true)."""
    try:
        result = execute_transfer(
            conn, user.user_id, body.from_account_id, body.to_account_id,
            body.amount_krw, body.request_id,
        )
    except TransferRejected as rejected:
        # 트랜잭션은 이미 롤백된 상태이므로 거절 기록은 별도로 남는다.
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
