"""⚠️ Semgrep 분석 전용 샘플 — 절대 실행하거나 import하지 않는다.

BankGuard 규칙(rules/bankguard.yml)이 '탐지해야 하는' 취약 패턴만 모은 파일이다.
- 아무 곳에서도 import하지 않으며, 함수도 호출하지 않는다. 외부 요청·셸 실행은 일어나지 않는다.
- 비밀 문자열은 가짜 값(DEMO_ONLY_NOT_A_REAL_SECRET)만 쓴다. 주소는 example.invalid(예약된 무효 도메인)다.
- `# EXPECT: <규칙ID>` 주석은 그 줄(또는 바로 그 줄에서 시작하는 구문)에서 해당 규칙이 탐지돼야 한다는 표시다.
  tests/test_sast_rules.py가 이 표시와 Semgrep의 실제 출력을 대조한다(결과를 미리 적어 두는 용도가 아니다).
"""
import logging

import requests

logger = logging.getLogger("fixture")


# --- BG-SAST-001: SQL 문자열 조립 -----------------------------------------------------------

def sql_with_fstring(conn, account_id):
    return conn.execute(f"SELECT * FROM accounts WHERE id = {account_id}")  # EXPECT: BG-SAST-001


def sql_with_percent(conn, account_id):
    return conn.execute("SELECT * FROM accounts WHERE id = %s" % account_id)  # EXPECT: BG-SAST-001


def sql_with_concat(conn, account_no):
    return conn.execute("SELECT * FROM accounts WHERE account_no = '" + account_no + "'")  # EXPECT: BG-SAST-001


def sql_with_format(conn, account_id):
    return conn.execute("SELECT * FROM accounts WHERE id = {}".format(account_id))  # EXPECT: BG-SAST-001


def sql_assembled_in_variable(conn, account_id):
    query = f"SELECT * FROM accounts WHERE id = {account_id}"  # EXPECT: BG-SAST-001
    return conn.execute(query)


def script_with_fstring(conn, account_id):
    conn.executescript(f"DELETE FROM accounts WHERE id = {account_id}")  # EXPECT: BG-SAST-001


# --- BG-SAST-002: 금액 관련 이름에 float ---------------------------------------------------

def money_as_float():
    amount = float("20000.5")  # EXPECT: BG-SAST-002
    balance_krw = 1000000.0  # EXPECT: BG-SAST-002
    return amount + balance_krw


def transfer_with_float_parameter(from_id, to_id, amount_krw: float):  # EXPECT: BG-SAST-002
    return from_id, to_id, amount_krw


fee_amount: float = 150.5  # EXPECT: BG-SAST-002


# --- BG-SAST-003: 민감 이름 변수를 로그·출력에 그대로 기록 -------------------------------------

def leaks_to_logs(token, account_no, password):
    print("token:", token)  # EXPECT: BG-SAST-003
    print(f"account {account_no}")  # EXPECT: BG-SAST-003
    logging.info("login password=%s", password)  # EXPECT: BG-SAST-003
    logger.warning("token=%s", token)  # EXPECT: BG-SAST-003


# --- BG-SAST-004: TLS 검증 비활성화 / 하드코딩된 비밀 -----------------------------------------

API_SECRET = "DEMO_ONLY_NOT_A_REAL_SECRET"  # EXPECT: BG-SAST-004
db_password = "DEMO_ONLY_NOT_A_REAL_SECRET"  # EXPECT: BG-SAST-004


def call_without_tls_verification():
    return requests.get("https://example.invalid/health", verify=False, timeout=5)  # EXPECT: BG-SAST-004
