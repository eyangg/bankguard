"""⚠️ 취약 비교 구현 — 검사(비교) 전용. 절대 공개 서버에 붙이지 않는다.

이 모듈의 코드는 "일부러" 보안 결함을 담고 있다. 같은 안전성 검사를 안전 모드와 취약 모드에
돌려 FAIL → PASS 개선을 실제 응답·DB 상태로 보여 주기 위한 교육용 비교 대상이다.

사용 범위(코드로 강제됨):
- backend.factory.create_app(mode="vulnerable", db_path=...)가 vulnerable일 때만 지연 import한다.
- 그 팩토리는 시스템 임시 폴더 안의 명시적 DB 경로가 아니면 ValueError를 낸다.
- backend.main(공개 진입점)은 이 모듈을 import하지 않는다 (tests/test_lab_isolation.py가 확인).

DAY 3 범위: SC-01(BOLA), SC-05(BFLA), SC-06(Mass Assignment)만 구현한다.
각 결함은 아래 FLAW 주석으로 표시한다. 인증(토큰 확인)은 안전 모드와 같고, 결함은 인가에만 있다.
모든 데이터는 허구이며 외부 시스템에 요청하지 않는다.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from backend import repository
from backend.auth_demo import AuthUser, current_user, get_conn
from backend.schemas import AccountNicknameOut, FreezeOut, TransactionOut


def build_lab_router() -> APIRouter:
    lab = APIRouter(prefix="/api", tags=["INSECURE-LAB (검사 전용)"])

    @lab.get("/accounts/{account_id}/transactions", response_model=list[TransactionOut])
    def lab_transactions(
        account_id: int,
        user: AuthUser = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        if repository.get_account(conn, account_id) is None:
            raise HTTPException(status_code=404, detail="계좌를 찾을 수 없습니다.")
        # FLAW (SC-01 BOLA): 로그인만 확인하고 계좌 소유자(owner_user_id)와 비교하지 않는다.
        return repository.list_transactions(conn, account_id)

    @lab.post("/admin/accounts/{account_id}/freeze", response_model=FreezeOut)
    def lab_freeze(
        account_id: int,
        user: AuthUser = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        # FLAW (SC-05 BFLA): "인증된 사용자인가"만 보고 role == 'admin' 확인을 빼먹었다.
        if repository.get_account(conn, account_id) is None:
            raise HTTPException(status_code=404, detail="계좌를 찾을 수 없습니다.")
        conn.execute("UPDATE accounts SET status = 'FROZEN' WHERE id = ?", (account_id,))
        return FreezeOut(account_id=account_id, status="FROZEN")

    @lab.patch("/accounts/{account_id}", response_model=AccountNicknameOut)
    def lab_patch_account(
        account_id: int,
        payload: dict[str, Any] = Body(...),
        user: AuthUser = Depends(current_user),
        conn: sqlite3.Connection = Depends(get_conn),
    ):
        account = repository.get_account(conn, account_id)
        if account is None:
            raise HTTPException(status_code=404, detail="계좌를 찾을 수 없습니다.")
        if account["owner_user_id"] != user.user_id:  # 소유권 검사는 유지: 결함을 속성 수준으로 한정
            raise HTTPException(status_code=403, detail="본인 소유 계좌만 변경할 수 있습니다.")

        # FLAW (SC-06 BOPLA / Mass Assignment): 요청 JSON의 키를 허용 목록 없이 컬럼으로 그대로 반영한다.
        # 컬럼명은 실제 컬럼 목록과 대조해 SQL 문법 오류만 피하고(id는 제외해 실습 DB를 보호),
        # 값은 파라미터 바인딩을 쓴다. 즉 SQL 삽입이 아니라 "바꾸면 안 되는 속성이 바뀌는" 결함이다.
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(accounts)")} - {"id"}
        updates = {key: value for key, value in payload.items() if key in columns}
        if not updates:
            raise HTTPException(status_code=422, detail="변경할 필드가 없습니다.")
        set_clause = ", ".join(f"{column} = ?" for column in updates)
        try:
            conn.execute(
                f"UPDATE accounts SET {set_clause} WHERE id = ?",
                (*updates.values(), account_id),
            )
        except (sqlite3.IntegrityError, sqlite3.InterfaceError, sqlite3.ProgrammingError):
            raise HTTPException(status_code=422, detail="변경 값이 올바르지 않습니다.")

        refreshed = repository.get_account(conn, account_id)
        return AccountNicknameOut(
            id=refreshed["id"], account_no=refreshed["account_no"], nickname=refreshed["nickname"]
        )

    return lab
