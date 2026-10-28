"""BankGuard Streamlit 대시보드 진입점.

실행: .\\.venv\\Scripts\\python.exe -m streamlit run frontend/app.py
- 4개 탭(개요 / API 보안 테스트 / 정적 코드 분석 / 개선 비교·보고서).
- 화면에 표시하는 결과는 버튼으로 실제 실행한 검사 결과뿐이다. 임의의 PASS/FAIL 예시를 넣지 않는다.
- 검사 엔진(scanners)을 직접 불러 쓰므로 API 서버(uvicorn)를 켜지 않아도 검사를 실행할 수 있다.
"""
from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

# `streamlit run frontend/app.py`로 실행하면 프로젝트 루트가 sys.path에 없으므로 추가한다.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from frontend import tabs  # noqa: E402

st.set_page_config(page_title="BankGuard", page_icon="🏦", layout="wide")

tabs.init_state()

st.title("BANKGUARD | BANK API SECURITY LAB")
st.caption("가상 은행 API의 취약점을 자동 검증하고, 수정 전후를 비교합니다.")
tabs.render_sidebar()

# 검사 진행 상황·알림은 어느 탭을 보고 있든 보이도록 탭 위쪽 고정 영역에 둔다.
status_box = st.container()
tabs.render_notice(status_box)

overview, api_tab, sast_tab, compare_tab = st.tabs(
    ["① 개요", "② API 보안 테스트", "③ 정적 코드 분석", "④ 개선 비교·보고서"]
)
with overview:
    tabs.render_overview()
with api_tab:
    tabs.render_api_tab()
with sast_tab:
    tabs.render_sast_tab()
with compare_tab:
    tabs.render_compare_tab()

# 예약된 검사가 있으면 화면을 모두 그린 뒤(실행 버튼은 비활성화된 상태) 실제로 실행하고, 끝나면 새로 그려 결과를 반영한다.
tabs.execute_pending_job(status_box)
