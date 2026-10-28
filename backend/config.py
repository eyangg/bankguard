"""BankGuard 공통 설정.

모든 값은 로컬 데모용 고정값이다. 외부 대상 주소를 입력받지 않는다(명세 4장 설계 결정 4).
"""
from __future__ import annotations

from pathlib import Path

SERVICE_NAME = "BankGuard API"
API_VERSION = "0.1.0"

# 프로젝트 루트(= 이 파일의 상위 폴더의 상위)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# 운영(안전 모드) 서버가 사용할 기본 SQLite 경로. DAY 2부터 사용한다.
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "bankguard.db"

# 대시보드가 호출하는 로컬 API 주소(고정값, 사용자 입력으로 바꾸지 않음)
API_BASE_URL = "http://127.0.0.1:8000"

# DET-01 계좌 열거 의심 탐지(명세 5장). 같은 사용자가 최근 N분 안에 서로 다른 계좌 ID로 거부/없음 응답을 K개 이상 받으면 경보.
# 근거: 정상 사용자는 본인 계좌만 조회하므로 남의 계좌 ID에 403/404를 여러 개 받을 일이 드물다. 한계는 README 참고.
DET01_WINDOW_MINUTES = 5
DET01_MIN_DISTINCT_ACCOUNTS = 3
DET01_EVENT_TYPES = ("ACCESS_DENIED", "NOT_FOUND")

# 안전 모드 송금 금액 상한(원). 하한은 1원 (명세 5장 불변식)
MAX_TRANSFER_KRW = 10_000_000

# 공개 서버에서 허용하는 모드. 취약 비교 모드는 여기에 절대 추가하지 않는다.
PUBLIC_MODES = frozenset({"secure"})

# 테스트·검사 코드에서만 만들 수 있는 취약 비교 모드. create_app이 임시 DB 경로를 강제한다.
LAB_MODES = frozenset({"vulnerable"})
