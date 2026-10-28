"""대시보드가 검사 엔진을 부르는 얇은 연결부(Streamlit 호출 없음).

결과는 scanners의 실제 실행 결과 그대로이며 이 파일에서 PASS/FAIL을 만들거나 바꾸지 않는다.
검사 실행 함수는 scanners.pipeline에 있고 여기서는 같은 이름으로 다시 내보낸다(화면 코드가 services.*로 부른다).
"""
from __future__ import annotations

import httpx

from backend.config import API_BASE_URL
from backend.seed import SEED_USERS
from scanners.pipeline import (  # noqa: F401  (재내보내기)
    run_api_checks,
    run_detection_check,
    run_full_check,
    run_static_analysis,
)


def fetch_live_accounts(base_url: str = API_BASE_URL, timeout: float = 1.5) -> dict[int, list[dict]] | None:
    """실행 중인 로컬 API에서 고객별 계좌를 조회한다. API가 꺼져 있거나 이상하면 None(= 초기값으로 대체 표시).

    토큰은 backend.seed의 허구 상수를 import해서 쓴다(공개 API로 토큰을 노출하지 않는다, 명세 6.2).
    """
    live: dict[int, list[dict]] = {}
    try:
        for user in SEED_USERS:
            if user.role != "customer":
                continue
            resp = httpx.get(
                f"{base_url}/api/accounts", headers={"X-Demo-Token": user.demo_token}, timeout=timeout
            )
            if resp.status_code != 200:
                return None
            live[user.user_id] = resp.json()
    except (httpx.HTTPError, ValueError):
        return None
    return live
