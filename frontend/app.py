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

overview, api_tab, sast_tab, compare_tab = st.tabs(
    ["① 개요", "② API 보안 테스트", "③ 정적 코드 분석", "④ 개선 비교·보고서"]
)
# 탭의 화면 위치는 st.tabs()에서 만든 순서로 정해지고, 채우는 순서는 자유다.
# 검사 버튼(②③)이 세션 상태를 바꾸므로 ①개요의 요약은 그 뒤에 그려야 방금 실행한 결과가 바로 반영된다.
with api_tab:
    tabs.render_api_tab()
with sast_tab:
    tabs.render_sast_tab()
with compare_tab:
    tabs.render_compare_tab()
with overview:
    tabs.render_overview()
