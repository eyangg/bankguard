"""검사 실행 묶음: API 시나리오 / 정적 분석 / DET-01 / 전체 실행.

대시보드, 보고서 CLI, CI 게이트가 같은 함수를 쓴다. 이 모듈은 결과를 만들지 않고 각 검사 엔진의 실제 실행 결과를 모아 준다.
"""
from __future__ import annotations

import time
from typing import Callable

from scanners import sast_runner
from scanners.api_runner import SCENARIOS, run_api_scenarios
from scanners.det_runner import run_det01_check
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


def run_detection_check() -> dict:
    started = time.monotonic()
    data = run_det01_check()
    data["duration_sec"] = round(time.monotonic() - started, 1)
    return data


def run_full_check(on_progress: ProgressCallback | None = None) -> dict:
    """취약 → 안전 → 정적 분석 → DET-01 순서로 전부 실제 실행한다."""
    unit = len(SCENARIOS)
    total = 2 * unit + 2
    offset = [0]

    def sub(label: str) -> ProgressCallback:
        def callback(done: int, _total: int, name: str) -> None:
            if on_progress:
                on_progress(offset[0] + done, total, f"{label}: {name}")

        return callback

    vulnerable = run_api_checks("vulnerable", sub("취약 버전"))
    offset[0] += unit
    secure = run_api_checks("secure", sub("안전 버전"))
    offset[0] += unit
    if on_progress:
        on_progress(offset[0], total, "정적 분석(Semgrep) 실행 중")
    sast = run_static_analysis()
    offset[0] += 1
    if on_progress:
        on_progress(offset[0], total, "DET-01 탐지 검증 중")
    det01 = run_detection_check()
    if on_progress:
        on_progress(total, total, "완료")
    return {"api_vulnerable": vulnerable, "api_secure": secure, "sast": sast, "det01": det01}
