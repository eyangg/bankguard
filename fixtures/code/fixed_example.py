"""⚠️ Semgrep 분석 전용 샘플 — 절대 실행하거나 import하지 않는다.

vulnerable_example.py와 같은 기능을 안전하게 고친 버전이다. 규칙이 '탐지하면 안 되는' 패턴이다.
이 파일에서는 BankGuard 규칙 탐지가 0건이어야 한다. 일부러 비슷하게 생겼지만 안전한 코드(near-miss)를 섞었다.
아무 곳에서도 import하지 않으며 함수도 호출하지 않는다. 외부 요청·셸 실행은 일어나지 않는다.
"""
import logging
import os

import requests

logger = logging.getLogger("fixture")


# --- BG-SAST-001 대응: 파라미터 바인딩 / 상수 SQL --------------------------------------------

def sql_with_binding(conn, account_id):
    return conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))


def sql_constant_only(conn):
    return conn.execute("SELECT COUNT(*) FROM accounts")


def sql_in_variable_with_binding(conn, account_no):
    query = "SELECT * FROM accounts WHERE account_no = ?"
    return conn.execute(query, (account_no,))


def not_a_database_call(items, name):
    # execute가 아닌 메서드의 문자열 조립은 이 규칙의 대상이 아니다.
    return items.append(f"SELECT {name}")


# --- BG-SAST-002 대응: 정수 금액, 금액과 무관한 float --------------------------------------

def money_as_int():
    amount = int("20000")
    balance_krw = 1_000_000
    return amount + balance_krw


def transfer_with_int_parameter(from_id, to_id, amount_krw: int):
    return from_id, to_id, amount_krw


interest_rate = 0.035  # 금액이 아닌 비율: 이름에 amount/balance/_krw가 없다
timeout_seconds: float = 2.5


# --- BG-SAST-003 대응: 마스킹·지문만 기록 ---------------------------------------------------

def logs_only_safe_values(token_fp, masked_account_no, user_id):
    print("token_fp:", token_fp)
    print(f"account {masked_account_no}")
    logging.info("login user_id=%s", user_id)
    logger.warning("token_fp=%s", token_fp)


# --- BG-SAST-004 대응: 검증 켜기, 비밀은 환경변수에서 ---------------------------------------

API_SECRET = os.environ.get("BANKGUARD_API_SECRET")
db_password = os.getenv("BANKGUARD_DB_PASSWORD")
empty_password = ""


def call_with_tls_verification():
    return requests.get("https://example.invalid/health", timeout=5)
