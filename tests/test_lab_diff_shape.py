"""취약 구현이 '안전 코드 + 결함 부분만 다른 복사본'인지 AST 비교로 강제한다.

주석·docstring·함수 이름·데코레이터는 무시하고 코드 문장만 비교한다. 취약 코드에 결함과 무관한 변경이
섞이면(= README의 취약↔수정 diff가 더러워지면) 이 테스트가 깨진다.
"""
from __future__ import annotations

import ast
import difflib
import inspect
import textwrap

import pytest

from backend import routes, schemas
from backend.services import insecure_lab as lab
from backend.services import transfers


def normalized(obj) -> list[str]:
    node = ast.parse(textwrap.dedent(inspect.getsource(obj))).body[0]
    node.name = "TARGET"
    node.decorator_list = []
    first = node.body[0] if node.body else None
    if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) \
            and isinstance(first.value.value, str):
        node.body = node.body[1:]  # docstring 제거
    return ast.unparse(node).splitlines()


def diff_of(secure, vulnerable):
    a, b = normalized(secure), normalized(vulnerable)
    unified = list(difflib.unified_diff(a, b, n=1, lineterm=""))
    hunks = sum(1 for line in unified if line.startswith("@@"))
    removed = [l[1:].strip() for l in unified if l.startswith("-") and not l.startswith("---")]
    added = [l[1:].strip() for l in unified if l.startswith("+") and not l.startswith("+++")]
    return hunks, removed, added


# 이름 → (안전 코드, 취약 코드, 기대 변경 블록 수). 블록 수가 늘면 결함과 무관한 변경이 섞인 것이다.
PAIRS = {
    "SC-01 route": (routes.list_account_transactions, lab.lab_list_account_transactions, 1),
    "SC-03 service": (transfers.execute_transfer, lab.execute_transfer_lost_update, 3),
    "SC-04 service": (transfers.execute_transfer, lab.execute_transfer_no_idempotency, 1),
    "SC-06 route": (routes.update_account_nickname, lab.lab_update_account_nickname, 2),
    "SC-06 model": (schemas.NicknameUpdate, lab.NicknameUpdateLoose, 1),
    "SC-02 model": (schemas.TransferIn, lab.TransferInLoose, 1),
}


@pytest.mark.parametrize("name", PAIRS)
def test_vulnerable_copy_differs_only_in_expected_blocks(name):
    secure, vulnerable, expected_hunks = PAIRS[name]
    hunks, removed, added = diff_of(secure, vulnerable)
    assert hunks == expected_hunks, f"{name}: 변경 블록 {hunks}개 (기대 {expected_hunks}) removed={removed} added={added}"


def test_sc01_only_removes_the_ownership_check():
    _, removed, added = diff_of(routes.list_account_transactions, lab.lab_list_account_transactions)
    assert added == []
    assert any("owner_user_id" in line for line in removed)
    assert any("ACCESS_DENIED" in line for line in removed)


def test_sc04_only_adds_server_generated_request_id():
    _, removed, added = diff_of(transfers.execute_transfer, lab.execute_transfer_no_idempotency)
    assert removed == []
    assert added == ["request_id = str(uuid.uuid4())"]


def test_sc02_only_loosens_amount_field():
    _, removed, added = diff_of(schemas.TransferIn, lab.TransferInLoose)
    assert removed == ["amount_krw: StrictInt = Field(gt=0, le=MAX_TRANSFER_KRW)"]
    assert added == ["amount_krw: int"]


def test_sc06_model_only_allows_extra_fields():
    _, removed, added = diff_of(schemas.NicknameUpdate, lab.NicknameUpdateLoose)
    assert removed == ["model_config = ConfigDict(extra='forbid')"]
    assert added == ["model_config = ConfigDict(extra='allow')"]


def test_sc03_removes_transaction_boundary_and_overwrites_balance():
    _, removed, added = diff_of(transfers.execute_transfer, lab.execute_transfer_lost_update)
    assert "conn.execute('BEGIN IMMEDIATE')" in removed
    assert "conn.execute('COMMIT')" in removed
    assert any("balance_krw - ?" in line and "AND balance_krw >= ?" in line for line in removed)  # 조건부 원자 차감 제거
    assert any("SET balance_krw = ?" in line for line in added)  # 계산한 값으로 덮어쓰기
    assert not any("BEGIN" in line or "COMMIT" in line for line in added)


def test_sc03_credit_and_insert_stay_identical_to_secure():
    # 입금(원자적 +)과 송금 기록 INSERT는 안전 코드와 같아야 한다(결함은 출금 read-modify-write뿐).
    _, removed, added = diff_of(transfers.execute_transfer, lab.execute_transfer_lost_update)
    for line in removed + added:
        assert "balance_krw + ?" not in line
        assert "INSERT INTO transfers" not in line


def test_sc05_differs_from_secure_only_by_missing_router_dependency():
    # 핸들러는 안전 코드의 것을 그대로 재사용하고, 라우터의 역할 검사 의존성만 빠져 있다.
    setup = lab.build_lab("SC-05")
    assert [r.endpoint for r in setup.router.routes] == [routes.freeze_account]
    assert len(routes.admin_router.dependencies) == 1
    assert setup.router.dependencies == []


def test_every_lab_flaw_has_a_registered_setup():
    assert sorted(lab.LAB_FLAWS) == ["SC-01", "SC-02", "SC-03", "SC-04", "SC-05", "SC-06"]


def test_unknown_flaw_is_rejected():
    with pytest.raises(ValueError):
        lab.build_lab("SC-99")


def test_only_sc02_uses_a_custom_schema():
    custom = {flaw for flaw in lab.LAB_FLAWS if lab.build_lab(flaw).schema_sql is not None}
    assert custom == {"SC-02"}
    sql = lab.build_lab("SC-02").schema_sql
    assert "amount_krw > 0" not in sql
    # 나머지 제약은 그대로: 결함 전용 스키마의 차이는 amount CHECK 하나뿐이다.
    from backend.db import SCHEMA_SQL

    assert sql.replace(" ", "") == SCHEMA_SQL.replace(" CHECK (amount_krw > 0)", "").replace(" ", "")
