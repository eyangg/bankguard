"""감사 로그 기록·마스킹 (명세 5장 audit_log).

- 토큰 원문과 전체 계좌번호는 저장하지 않는다(토큰은 SHA-256 앞 12자리 지문, 계좌번호는 마스킹).
- 송금 트랜잭션과 분리해 기록한다: 호출자는 트랜잭션이 끝난(롤백 포함) 뒤에 record()를 부른다.
"""
from __future__ import annotations

import hashlib
import logging
import sqlite3
from datetime import datetime, timezone

logger = logging.getLogger("bankguard.audit")

AUTH_FAIL = "AUTH_FAIL"
ACCESS_DENIED = "ACCESS_DENIED"
NOT_FOUND = "NOT_FOUND"
TRANSFER_OK = "TRANSFER_OK"
TRANSFER_REJECTED = "TRANSFER_REJECTED"
IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def token_fingerprint(token: str | None) -> str | None:
    """토큰 원문 대신 저장할 SHA-256 앞 12자리. 토큰이 없으면 None."""
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def mask_account_no(account_no: str) -> str:
    """'DEMO-101' -> 'DEMO-1**' (앞 6자만 남기고 마스킹)."""
    return account_no[:6] + "**" if len(account_no) > 6 else account_no[:1] + "**"


def record(
    conn: sqlite3.Connection,
    event_type: str,
    http_status: int,
    *,
    actor_user_id: int | None = None,
    token_fp: str | None = None,
    target_account_id: int | None = None,
    detail: str | None = None,
) -> None:
    """감사 로그 1건을 기록한다. 기록 실패가 API 응답을 깨뜨리지 않도록 오류는 로그로만 남긴다."""
    try:
        conn.execute(
            "INSERT INTO audit_log (created_at, event_type, actor_user_id, token_fingerprint,"
            " target_account_id, http_status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (utc_now_iso(), event_type, actor_user_id, token_fp, target_account_id, http_status, detail),
        )
    except sqlite3.Error:
        logger.exception("감사 로그 기록 실패: event=%s status=%s", event_type, http_status)
