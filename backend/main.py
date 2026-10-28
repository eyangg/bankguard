"""운영(공개) FastAPI 진입점 — 안전 모드만 노출한다.

실행: python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

주의: 이 파일에서 모드를 환경변수·인자로 바꿀 수 있게 만들지 않는다.
취약 비교 모드는 공개 서버로 절대 실행되지 않아야 한다(명세 4장 설계 결정 1~2).
"""
from backend.factory import create_app

app = create_app(mode="secure")
