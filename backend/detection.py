"""DET-01 계좌 열거 의심 탐지 (명세 5장).

경보는 **audit_log 조회 결과로만** 만든다(추측·하드코딩 없음).
규칙: 같은 사용자(+토큰 지문)가 최근 N분 안에 서로 다른 계좌 ID에 대해 ACCESS_DENIED/NOT_FOUND를 K개 이상 받으면 경보.

오탐/미탐 한계
- 같은 계좌를 반복해서 틀리는 경우는 '서로 다른 계좌'가 아니라 경보가 나지 않는다(재시도 오탐 완화).
- 정상 사용자가 계좌 ID를 여러 번 잘못 입력하거나, 한 토큰을 여러 사람이 공유하면 오탐이 날 수 있다.
- 임계값(K) 아래로 천천히 시도하거나(창 N분 밖으로 분산) 토큰을 바꿔 가며 시도하면 놓친다.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from backend.config import DET01_EVENT_TYPES, DET01_MIN_DISTINCT_ACCOUNTS, DET01_WINDOW_MINUTES

RULE_ID = "DET-01"
TITLE = "계좌 열거 의심"


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def detect_account_enumeration(
    conn: sqlite3.Connection,
    now: datetime | None = None,
    window_minutes: int = DET01_WINDOW_MINUTES,
    min_distinct_accounts: int = DET01_MIN_DISTINCT_ACCOUNTS,
) -> list[dict]:
    """감사 로그를 읽어 열거 의심 사용자별 경보 목록을 돌려준다(경보가 없으면 빈 목록)."""
    now = now or datetime.now(timezone.utc)
    since = _iso(now - timedelta(minutes=window_minutes))
    placeholders = ", ".join("?" for _ in DET01_EVENT_TYPES)
    rows = conn.execute(
        "SELECT actor_user_id, token_fingerprint, target_account_id, event_type, created_at"
        f" FROM audit_log WHERE event_type IN ({placeholders})"
        " AND target_account_id IS NOT NULL AND actor_user_id IS NOT NULL"
        " AND created_at >= ? AND created_at <= ? ORDER BY created_at, id",
        (*DET01_EVENT_TYPES, since, _iso(now)),
    ).fetchall()

    groups: dict[tuple, list[sqlite3.Row]] = {}
    for row in rows:
        groups.setdefault((row["actor_user_id"], row["token_fingerprint"]), []).append(row)

    alerts = []
    for (actor_user_id, token_fp), events in groups.items():
        targets = sorted({e["target_account_id"] for e in events})
        if len(targets) >= min_distinct_accounts:
            alerts.append(
                {
                    "rule_id": RULE_ID,
                    "title": TITLE,
                    "actor_user_id": actor_user_id,
                    "token_fingerprint": token_fp,
                    "distinct_accounts": len(targets),
                    "event_count": len(events),
                    "target_account_ids": targets,
                    "first_seen": events[0]["created_at"],
                    "last_seen": events[-1]["created_at"],
                    "window_minutes": window_minutes,
                    "threshold": min_distinct_accounts,
                }
            )
    return alerts
