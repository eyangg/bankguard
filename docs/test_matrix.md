# 테스트 매트릭스 (시나리오별 요청 · 기대 · 실제 · 근거)

> 이 표는 사람이 쓴 값이 아니라 `python -m scanners.report`가 **실제로 실행해 저장한 결과**(`artifacts/latest_*.json`)에서 스크립트로 옮긴 것입니다.
> 실행 시각(UTC): 취약 2026-10-29T00:28:24Z / 안전 2026-10-29T00:28:25Z / DET-01 2026-10-29T00:28:37Z. 환경: Windows 11, Python 3.12.10, Semgrep CE 1.182.1.
> 다시 만들려면 `python -m scanners.report`를 실행하세요. 판정은 모두 실제 HTTP 응답과 임시 DB 상태로만 했고, 취약 버전은 격리된 임시 DB·인프로세스 `TestClient`에서만 실행됩니다.

## 1. 동적 API 시나리오 (취약 구현 ↔ 안전 구현)

| ID | 구분 | 점검 항목 | 기대(안전 기준) | 취약 버전 실제 | 안전 버전 실제 |
|---|---|---|---|---|---|
| SC-01 | 핵심 | 타인 거래내역 조회 차단 (BOLA) | 403 및 타인 거래 데이터 비공개 | **FAIL** — 200, 타인(B)의 거래 데이터가 반환됨 | **PASS** — 403, 타인(B) 거래 데이터 미반환 |
| SC-03 | 핵심 | 동시 송금 경쟁 조건 차단 (lost update) | 동시 2건 중 정확히 1건 201·1건 409, 잔액 합 보존, 송금 기록 1건 | **FAIL** — HTTP [201, 201]: 잔액 합 3,500,000→3,800,000원(+300,000원 복제), 기록 600,000원 vs 실제 출금 300,000원 | **PASS** — 201 1건·409 1건, 잔액 합 보존, 송금 기록 1건 |
| SC-04 | 핵심 | 중복 송금 방지 (멱등성) | 같은 request_id 재전송은 200·같은 거래 ID(출금 1회), 다른 금액은 409 | **FAIL** — 같은 요청이 새 거래로 처리됨: 재전송 HTTP 201, A 잔액 930,000원, 기록 3건 | **PASS** — 재전송 200(같은 거래 ID), ID 충돌 409, 출금 1회·기록 1건 |
| SC-05 | 핵심 | 일반 고객의 관리자 기능 호출 차단 (BFLA) | 403, 계좌 상태 불변(ACTIVE), 감사로그 ACCESS_DENIED 1건 | **FAIL** — HTTP 200, 고객이 타인 계좌를 지급정지시킴(status=FROZEN) | **PASS** — 403, 상태 불변(ACTIVE), 감사로그 ACCESS_DENIED 1건 |
| SC-06 | 핵심 | 요청에 필드 끼워넣기 차단 (Mass Assignment) | 422, balance_krw·owner_user_id·status·nickname 모두 불변 | **FAIL** — 변형 3개 중 3개에서 허용되지 않은 속성이 반영되거나 2xx로 수락됨 | **PASS** — 변형 3개 모두 422, DB 불변 |
| SC-02 | 세부 | 잘못된 송금 금액 차단 (T06·T07, 0원·음수) | 422, 잔액 변동 없음, 신규 송금 기록 없음 | **FAIL** — 2건 중 2건이 잘못된 금액을 수락(서버 검증 없음) | **PASS** — 음수·0원 모두 422, DB 불변 |

## 2. 요청 · 근거 (실제 관측)

### SC-01 · 타인 거래내역 조회 차단 (BOLA)

- **취약 버전 (FAIL):** A 토큰으로 GET /api/accounts/102/transactions → HTTP 200. 양성 대조: B 토큰으로 본인 조회 HTTP 200, 거래 1건 확인. 응답에 B의 거래가 포함됨.
- **안전 버전 (PASS):** A 토큰으로 GET /api/accounts/102/transactions → HTTP 403. 양성 대조: B 토큰으로 본인 조회 HTTP 200, 거래 1건 확인.

### SC-03 · 동시 송금 경쟁 조건 차단 (lost update)

- **취약 버전 (FAIL):** B 토큰으로 B→A 300,000원 2건을 Barrier로 동시 전송 → HTTP [201, 201]. 잔액 B=200,000, A=1,600,000, 전체 합 3,500,000→3,800,000, 송금 기록 2건(합계 600,000원), B 실제 출금 300,000원.
- **안전 버전 (PASS):** B 토큰으로 B→A 300,000원 2건을 Barrier로 동시 전송 → HTTP [409, 201]. 잔액 B=200,000, A=1,300,000, 전체 합 3,500,000→3,500,000, 송금 기록 1건(합계 300,000원), B 실제 출금 300,000원.

### SC-04 · 중복 송금 방지 (멱등성)

- **취약 버전 (FAIL):** 같은 request_id로 A→B 20,000원 2회 → HTTP 201, 201; 같은 request_id에 30,000원 → HTTP 201. A=930,000원(정상 980,000), B=570,000원(정상 520,000), 송금 기록 3건(정상 1건).
- **안전 버전 (PASS):** 같은 request_id로 A→B 20,000원 2회 → HTTP 201, 200; 같은 request_id에 30,000원 → HTTP 409. A=980,000원(정상 980,000), B=520,000원(정상 520,000), 송금 기록 1건(정상 1건).

### SC-05 · 일반 고객의 관리자 기능 호출 차단 (BFLA)

- **취약 버전 (FAIL):** 고객 A 토큰으로 POST /api/admin/accounts/102/freeze → HTTP 200, 102 계좌 status=FROZEN, 감사로그 ACCESS_DENIED=0건. 양성 대조: 운영자 토큰은 같은 요청에 200 FROZEN.
- **안전 버전 (PASS):** 고객 A 토큰으로 POST /api/admin/accounts/102/freeze → HTTP 403, 102 계좌 status=ACTIVE, 감사로그 ACCESS_DENIED=1건. 양성 대조: 운영자 토큰은 같은 요청에 200 FROZEN.

### SC-06 · 요청에 필드 끼워넣기 차단 (Mass Assignment)

- **취약 버전 (FAIL):** A 토큰으로 PATCH /api/accounts/101 변형별 결과 — +balance_krw: HTTP 200, 변경된 속성=['balance_krw', 'nickname']; +owner_user_id: HTTP 200, 변경된 속성=['owner_user_id', 'nickname']; +status: HTTP 200, 변경된 속성=['nickname']. 양성 대조: nickname만 보내면 200.
- **안전 버전 (PASS):** A 토큰으로 PATCH /api/accounts/101 변형별 결과 — +balance_krw: HTTP 422, DB 불변; +owner_user_id: HTTP 422, DB 불변; +status: HTTP 422, DB 불변. 양성 대조: nickname만 보내면 200.

### SC-02 · 잘못된 송금 금액 차단 (T06·T07, 0원·음수)

- **취약 버전 (FAIL):** A 토큰으로 A→B 송금 — T06(-10,000원): HTTP 201, 잔액 변화={101: 10000, 102: -10000}, 기록 금액=[-10000]; T07(0원): HTTP 201, 잔액 변화=없음, 기록 금액=[0]. 양성 대조: 20,000원은 201.
- **안전 버전 (PASS):** A 토큰으로 A→B 송금 — T06(-10,000원): HTTP 422, DB 불변; T07(0원): HTTP 422, DB 불변. 양성 대조: 20,000원은 201.

## 3. 감사 로그 탐지 DET-01 (계좌 열거 의심)

- **판정:** PASS
- **기대:** 남의 계좌 3개를 연속 조회하면 경보 1건, 2회까지는 경보 없음 (정상 사용·같은 계좌 반복은 경보 없음)
- **관측:** 2회까지 경보 없음, 3번째에서 경보 1건(사용자 A, 서로 다른 계좌 3개)

| 단계 | 요청 | HTTP | 누적 경보 |
|---|---|---|---|
| 1 | GET /api/accounts/102/transactions | 403 | 0 |
| 2 | GET /api/accounts/103/transactions | 403 | 0 |
| 3 | GET /api/accounts/999/transactions | 404 | 1 |

## 4. 정적 분석 (Semgrep) — 동적 시나리오와 별개의 검사

| 대상 | 상태 | 탐지 수 |
|---|---|---|
| `fixtures/code` | COMPLETED | 17 |
| `backend/services/insecure_lab.py` | COMPLETED | 1 |
| `backend (insecure_lab.py 제외)` | COMPLETED | 0 |

합계 18건(모두 '검토 필요' 의심 항목), 스캔 오류 0건. 탐지 0건은 안전하다는 뜻이 아닙니다.
