"""Pydantic 입력/출력 모델. 금액은 StrictInt로 bool·float·문자열을 거절한다."""
from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, field_validator

from backend.config import MAX_TRANSFER_KRW


class AccountOut(BaseModel):
    id: int
    account_no: str
    balance_krw: int


class TransactionOut(BaseModel):
    id: int
    type: Literal["IN", "OUT"]
    amount_krw: int
    created_at: str


class AccountNicknameOut(BaseModel):
    id: int
    account_no: str
    nickname: str | None


class NicknameUpdate(BaseModel):
    """별칭 변경 요청. 허용 필드는 nickname 하나뿐이며 그 외 필드는 422 (SC-06 안전 기준)."""

    model_config = ConfigDict(extra="forbid")

    nickname: StrictStr = Field(min_length=1, max_length=20)


class FreezeOut(BaseModel):
    account_id: int
    status: Literal["ACTIVE", "FROZEN"]


class TransferIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_account_id: StrictInt
    to_account_id: StrictInt
    amount_krw: StrictInt = Field(gt=0, le=MAX_TRANSFER_KRW)
    request_id: StrictStr

    @field_validator("request_id")
    @classmethod
    def _must_be_uuid(cls, v: str) -> str:
        try:
            return str(uuid.UUID(v))  # 소문자 하이픈 표준형으로 정규화
        except ValueError as exc:
            raise ValueError("request_id는 UUID 문자열이어야 합니다.") from exc


class TransferOut(BaseModel):
    transfer_id: int
    request_id: str
    from_account_id: int
    to_account_id: int
    amount_krw: int
    idempotent_replay: bool
