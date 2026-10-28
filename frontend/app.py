"""BankGuard Streamlit 대시보드 (DAY 1: 첫 화면 + API 연결 상태).

실행: python -m streamlit run frontend/app.py
4개 탭·검사 실행 버튼은 DAY 6에 구현한다. 여기서 임의의 PASS/FAIL 예시를 표시하지 않는다.
"""
from __future__ import annotations

import sys
from pathlib import Path

import httpx
import streamlit as st

# `streamlit run frontend/app.py`로 실행하면 프로젝트 루트가 sys.path에 없으므로 추가한다.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import API_BASE_URL  # noqa: E402


def check_api_health(base_url: str = API_BASE_URL, timeout: float = 2.0) -> tuple[bool, str]:
    """로컬 API의 /health를 호출해 (성공 여부, 사용자용 메시지)를 돌려준다."""
    try:
        resp = httpx.get(f"{base_url}/health", timeout=timeout)
    except httpx.HTTPError:
        # 상세 예외(로컬 경로 등)는 화면에 노출하지 않는다.
        return False, "API 서버에 연결할 수 없습니다."
    if resp.status_code == 200 and resp.json().get("status") == "ok":
        return True, f"API 정상 응답 (HTTP {resp.status_code})"
    return False, f"API가 예상과 다른 응답을 했습니다 (HTTP {resp.status_code})"


st.set_page_config(page_title="BankGuard", page_icon="🏦", layout="wide")

st.title("BANKGUARD | BANK API SECURITY LAB")
st.markdown(
    "**BankGuard는 가상의 은행 계좌·송금 API를 대상으로 보안 시나리오를 자동 실행하고, "
    "Python 소스코드를 정적 분석해 위험 사항과 수정 전후 검증 결과를 한 화면에서 보여주는 "
    "로컬 보안 점검 플랫폼입니다.**"
)
st.warning(
    "로컬 학습·포트폴리오용 실습 환경입니다. 실제 금융 서비스가 아니며, "
    "모든 사용자·계좌·토큰은 허구의 더미 데이터입니다."
)

st.subheader("API 서버 상태")
ok, message = check_api_health()
if ok:
    st.success(message)
else:
    st.error(message)
    st.code(
        "python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000",
        language="powershell",
    )
    st.caption("다른 터미널에서 위 명령으로 API 서버를 먼저 실행한 뒤 새로고침하세요.")

st.subheader("보안 검사 결과")
st.info("아직 검사를 실행하지 않았습니다.")
