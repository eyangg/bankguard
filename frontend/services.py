"""대시보드가 검사 엔진을 부르는 얇은 연결부(Streamlit 호출 없음).

결과는 scanners의 실제 실행 결과 그대로이며 이 파일에서 PASS/FAIL을 만들거나 바꾸지 않는다.
"""
from __future__ import annotations

import time
from typing import Callable

import httpx

from backend.config import API_BASE_URL
from backend.seed import SEED_USERS
from scanners import sast_runner
from scanners.api_runner import SCENARIOS, run_api_scenarios
from scanners.models import RunResult

ProgressCallback = Callable[[int, int, str], None]


def run_api_checks(mode: str, on_progress: ProgressCallback | None = None) -> dict:
    """모든 시나리오를 하나씩 실행하며 진행 상황을 알린다. 반환은 공통 결과 모델(dict)이다."""
    result = RunResult(mode=mode)
    started = time.monotonic()
    total = len(SCENARIOS)
    for index, scenario in enumerate(SCENARIOS, start=1):
        if on_progress:
            on_progress(index - 1, total, f"{scenario.id} {scenario.name}")
        result.items.extend(run_api_scenarios(mode, [scenario.id]).items)
    if on_progress:
        on_progress(total, total, "완료")
    data = result.to_dict()
    data["duration_sec"] = round(time.monotonic() - started, 1)
    return data


def run_static_analysis() -> dict:
    """고정된 대상 3곳을 Semgrep으로 스캔한다. 실패는 예외가 아니라 SCAN_ERROR 결과로 돌아온다."""
    started = time.monotonic()
    data = sast_runner.run_sast()
    data["duration_sec"] = round(time.monotonic() - started, 1)
    data["catalog"] = sast_runner.rule_catalog()
    return data


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
