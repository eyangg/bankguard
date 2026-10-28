"""DET-01 계좌 열거 의심 탐지 시연/검증 (T18).

격리된 안전 모드 앱에 고객 A로 남의 계좌를 차례로 조회하고, 그때마다 **실제 audit_log를 조회해** 경보가 나오는지 본다.
경보는 backend.detection이 감사 로그 행에서만 만든다. 이 모듈은 결과를 꾸미지 않고 관측값을 기록할 뿐이다.
"""
from __future__ import annotations

import logging

from backend.db import connect
from backend.detection import detect_account_enumeration
from scanners.api_runner import TOKEN_A, IsolatedEnv
from scanners.models import ERROR, FAIL, PASS
from scanners.sast_runner import utc_now_iso

logger = logging.getLogger("bankguard.det_runner")

# A가 순서대로 조회하는 남의 계좌/없는 계좌: 403, 403, 404 → 3번째에 경보가 기대된다(T18).
PROBES = (102, 103, 999)


def _alerts(env: IsolatedEnv) -> list[dict]:
    conn = connect(env.db_path)
    try:
        return detect_account_enumeration(conn)
    finally:
        conn.close()


def run_det01_check() -> dict:
    """DET-01이 의도대로(2회까지는 무경보, 3번째에 경보 1건, 반복·정상 사용은 무경보) 동작하는지 실제로 실행한다."""
    try:
        return _run()
    except Exception as exc:  # 스택트레이스·경로는 결과에 넣지 않는다
        logger.exception("DET-01 시연 실행 중 예외")
        return _result(ERROR, f"검사 중 예외 발생({type(exc).__name__}): 판정 불가", "내부 로그 참고", [], [], {})


def _result(status, observed, evidence, steps, alerts, controls) -> dict:
    return {
        "rule_id": "DET-01",
        "name": "계좌 열거 의심 탐지",
        "status": status,
        "expected": "남의 계좌 3개를 연속 조회하면 경보 1건, 2회까지는 경보 없음 (정상 사용·같은 계좌 반복은 경보 없음)",
        "observed": observed,
        "evidence": evidence,
        "steps": steps,
        "alerts": alerts,
        "controls": controls,
        "run_at": utc_now_iso(),
    }


def _run() -> dict:
    steps: list[dict] = []
    controls: dict[str, dict] = {}

    with IsolatedEnv("secure") as env:
        # 정상 사용 대조: 본인 계좌 조회는 200이고 경보가 없어야 한다.
        own = env.client.get("/api/accounts/101/transactions", headers=TOKEN_A)
        controls["본인 계좌 조회"] = {"status": own.status_code, "alerts": len(_alerts(env))}
        for number, account_id in enumerate(PROBES, start=1):
            resp = env.client.get(f"/api/accounts/{account_id}/transactions", headers=TOKEN_A)
            steps.append(
                {
                    "step": number,
                    "request": f"GET /api/accounts/{account_id}/transactions",
                    "http_status": resp.status_code,
                    "alerts_after": len(_alerts(env)),
                }
            )
        alerts = _alerts(env)

    with IsolatedEnv("secure") as env:
        # 음성 대조: 같은 남의 계좌를 5번 반복해도(서로 다른 계좌가 아니므로) 경보가 없어야 한다.
        codes = [env.client.get("/api/accounts/102/transactions", headers=TOKEN_A).status_code for _ in range(5)]
        controls["같은 계좌 5회 반복"] = {"status": codes, "alerts": len(_alerts(env))}

    evidence = (
        "A 토큰으로 "
        + " → ".join(f"{s['request'].split()[1]}(HTTP {s['http_status']}, 경보 {s['alerts_after']}건)" for s in steps)
        + f". 본인 계좌 조회 HTTP {controls['본인 계좌 조회']['status']}(경보 {controls['본인 계좌 조회']['alerts']}건), "
        f"같은 계좌 5회 반복 경보 {controls['같은 계좌 5회 반복']['alerts']}건."
    )

    if controls["본인 계좌 조회"]["status"] != 200:
        return _result(ERROR, "양성 대조 실패(본인 계좌 조회가 200이 아님): 판정 불가", evidence, steps, alerts, controls)

    before_threshold_quiet = all(s["alerts_after"] == 0 for s in steps[:2])
    alerts_after_third = steps[2]["alerts_after"] == 1 and len(alerts) == 1
    alert_ok = bool(alerts) and alerts[0]["actor_user_id"] == 1 and alerts[0]["distinct_accounts"] == 3
    controls_quiet = controls["본인 계좌 조회"]["alerts"] == 0 and controls["같은 계좌 5회 반복"]["alerts"] == 0

    if before_threshold_quiet and alerts_after_third and alert_ok and controls_quiet:
        return _result(PASS, "2회까지 경보 없음, 3번째에서 경보 1건(사용자 A, 서로 다른 계좌 3개)", evidence, steps, alerts, controls)
    return _result(FAIL, "탐지 규칙이 기대와 다르게 동작함", evidence, steps, alerts, controls)
