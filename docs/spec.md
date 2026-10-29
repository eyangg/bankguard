# BankGuard SPEC — 기술 명세

> 기준 문서: `BANKGUARD_CLAUDE_MASTER_SPEC.md` v2.0 장(V0~V9)과 본문. 이 문서와 명세가 충돌하면 명세가 우선입니다.
> 수업 문서 흐름: MVP → PRD → **SPEC**(이 문서) → PLAN
> 각 항목은 **현재(구현됨)**와 **목표(v2.0, 예정 Phase)**를 나눠 적습니다.

## 1. 기술 스택

| 영역 | 현재 | 목표(v2.0) |
|---|---|---|
| 백엔드 | FastAPI 0.162 + Pydantic 2 (Python 3.12) | 유지 |
| 화면 | Streamlit 1.66 (임시) | Vite + React + TypeScript(`strict: true`), `.ts`/`.tsx`만 — Phase D |
| DB | SQLite(`sqlite3`) | Supabase PostgreSQL(드라이버 `psycopg` 3.x, Session pooler). SQLite는 테스트 전용 — Phase B |
| 인증 | `X-Demo-Token` 헤더(가짜 토큰) | 로그인 + 서버 세션 쿠키 + 송금 OTP(TOTP) — Phase C |
| 테스트 | pytest + FastAPI `TestClient` | 유지 + `pytest -m postgres`(테스트용 Supabase) |
| 정적 분석 | Semgrep CE 1.182.1 (별도 가상환경 `.venv-semgrep`) | 유지 |
| 의존성 점검 | pip-audit 2.10.1 (별도 가상환경 `.venv-sca`) | 유지 + 프론트 `npm audit` — Phase E |
| CI | GitHub Actions | 유지 + 프론트 빌드·타입 검사 — Phase E |

## 2. 구조

### 2.1 목표 구조 (명세 V2)

```text
[React + TypeScript (Vite)] ──(같은 출처: Vite proxy /api)──▶ [FastAPI] ──(Session pooler)──▶ [Supabase PostgreSQL]
                                                                 ▲
[CLI·CI: 시나리오·Semgrep·pip-audit 실행] ─▶ artifacts/*.json ─────┘ (FastAPI는 결과를 읽기 전용으로 제공)
```

### 2.2 설계 결정

| ID | 결정 | 이유 |
|---|---|---|
| D1 | 브라우저는 Supabase에 직접 접속하지 않는다. 키를 프론트 코드·`VITE_*`에 두지 않는다 | `VITE_*` 값은 번들에 그대로 공개된다. 프론트가 anon 키로 직접 접속하는 구조에서 RLS 누락으로 데이터가 노출된 사례(CVE-2025-48757) |
| D2 | 모든 public 테이블에 RLS를 켜고 `anon`·`authenticated`의 테이블 권한을 회수한다 | 정책 없는 RLS는 API 역할에 전부 거부가 된다. 백엔드는 DB 소유 역할로 접속 |
| D3 | 로그인을 직접 구현한다(Supabase Auth 미사용) | 인증 설계가 이 포트폴리오의 핵심 보안 요소 |
| D4 | 점검 실행은 CLI·CI에서만, 웹은 결과를 관리자만 읽기 전용으로 본다 | 배포 환경에 subprocess 실행 경로·취약 모드 경로가 0개여야 한다 |
| D5 | 취약 비교 모드는 TestClient + 임시 SQLite에서만 | 취약 코드가 네트워크에 노출되지 않게 한다 |
| D6 | 비밀값은 `.env`에만, `.env.example`에는 항목과 설명만 | 코드·문서·로그에 비밀값이 남지 않게 한다 |

### 2.3 폴더별 역할 (현재)

| 폴더 | 역할 |
|---|---|
| `backend/` | `main.py`(안전 모드 고정 공개 진입점), `factory.py`(`create_app`), `routes.py`, `auth_demo.py`(인증 의존성), `throttle.py`(SC-07), `audit.py`, `detection.py`(DET-01), `db.py`, `seed.py`, `repository.py`, `schemas.py` |
| `backend/services/` | `transfers.py`(안전 송금), `insecure_lab.py`(취약 비교 구현 — 테스트 전용) |
| `scanners/` | `api_runner.py`(시나리오), `race_harness.py`, `sast_runner.py`, `sca_runner.py`, `det_runner.py`, `compare.py`, `report.py`, `ci_gate.py`, `artifacts.py` |
| `rules/` | Semgrep 규칙 `bankguard.yml` |
| `fixtures/code/` | 정적 분석 샘플(취약 / 수정) |
| `frontend/` | Streamlit 대시보드(Phase D에서 React로 교체) |
| `tests/` | pytest |
| `artifacts/` | 실행 결과 JSON·보고서(git 제외) |

목표 구조에는 `database/migrations/0001_*.sql`(테이블·RLS·권한 회수)과 적용 스크립트가 추가됩니다(Phase B).

## 3. 데이터

### 3.1 현재 테이블 (SQLite)

| 테이블 | 주요 컬럼 | 규칙 |
|---|---|---|
| `users` | `id`, `display_name`, `demo_token`(유일), `role` | role은 `customer` 또는 `admin` |
| `accounts` | `id`, `owner_user_id`, `account_no`(유일), `balance_krw`, `status`, `nickname` | `balance_krw >= 0`, status는 `ACTIVE`/`FROZEN` |
| `transfers` | `id`, `request_id`(유일), `sender_account_id`, `recipient_account_id`, `amount_krw`, `payload_fingerprint`, `created_at` | `amount_krw > 0` |
| `audit_log` | `id`, `created_at`, `event_type`, `actor_user_id`, `token_fingerprint`, `target_account_id`, `http_status`, `detail` | 토큰은 SHA-256 앞 12자리만, 계좌번호는 마스킹 |
| `auth_attempts` | `id`, `client_key`, `created_at` | SC-07. 아직 성공으로 확인되지 않은 인증 시도. 성공하면 행 삭제 |

시드: 가상 고객 A·B·C(계좌 101/102/103, 잔액 1,000,000 / 500,000 / 2,000,000원)와 가상 운영자 1명. 모두 허구의 값입니다.

### 3.2 목표 변경

- PostgreSQL로 옮길 때 SQL 차이(자리표시자 `?`↔`%s`, 트랜잭션 시작, 자동 증가 키, 시간 타입)는 연결 계층에서 흡수합니다. 안전 송금의 조건부 UPDATE는 두 DB에서 같은 의미로 동작해야 합니다 — Phase B
- 운영 서버는 PostgreSQL 설정(`BANKGUARD_DB_URL`)이 없으면 SQLite로 자동 전환하지 않고 **시작을 거부**합니다 — Phase B
- 인증용 테이블(사용자 비밀번호 해시, 세션 해시, 송금 대기, 암호화된 TOTP 시크릿)이 추가됩니다 — Phase C

## 4. API

### 4.1 현재 (안전 모드)

| 메서드 · 경로 | 설명 | 주요 응답 |
|---|---|---|
| `GET /health` | 상태 확인(인증 없음, DB 미사용) | 200 |
| `GET /api/accounts` | 내 계좌 목록 | 200 / 401 |
| `GET /api/accounts/{id}/transactions` | 내 계좌 거래내역 | 200 / 401 / 403 / 404 |
| `PATCH /api/accounts/{id}` | 별칭 변경(`nickname`만 허용) | 200 / 403 / 404 / 422 |
| `POST /api/transfers` | 송금(멱등) | 201 신규 / 200 재전송 / 400·403·404 / 409 / 422 |
| `POST /api/admin/accounts/{id}/freeze` | 운영자 전용 지급정지 | 200 / 403 / 404 |

- 금액은 `StrictInt`, 1원 이상 10,000,000원 이하. 소수·문자열·불리언은 422
- 서버 오류는 내부 정보 없이 일반 메시지(500), DB 잠금은 `503 + Retry-After`
- 인증이 필요한 모든 경로는 같은 클라이언트의 인증 실패가 누적되면 `429 + Retry-After`(SC-07)

### 4.2 목표 변경 (Phase C)

- 회원가입·로그인·로그아웃 엔드포인트 추가, `X-Demo-Token`은 운영 경로에서 제거(테스트에만 로그인 헬퍼)
- `POST /api/transfers`는 **송금 대기**만 만들고(잔액 변경 없음, 5분 만료), `POST /api/transfers/{id}/confirm`이 OTP를 서버에서 검증한 뒤에만 실행
- 상태 변경 요청은 CSRF 토큰 헤더 필요
- 관리자용 점검 결과 조회(읽기 전용) — Phase D 화면과 함께

## 5. 보안 점검 설계

### 5.1 공통 판정 원칙

- 시나리오마다 **임시 폴더의 새 SQLite DB + 새 앱 + TestClient**를 만든다. 다른 시나리오나 운영 데이터에 영향이 없다
- 판정은 모드 이름이 아니라 **실제 응답 코드·본문·DB 상태**로만 한다
- **양성 대조**(정상 요청은 성공하는가)가 깨지면 기능 고장일 수 있으므로 ERROR
- 5xx·예외는 결함의 증거가 아니므로 ERROR로 분리
- 취약 모드는 시나리오가 노리는 **결함 하나만** 붙은 앱이다(`create_app(mode="vulnerable", flaw="SC-xx", db_path=임시 경로)`)

### 5.2 취약 구현 원칙

- 결함 하나당 취약 구현 하나. 안전 코드의 복사본에서 **결함 부분만** 다르다(스위치·플래그 없음)
- `tests/test_lab_diff_shape.py`가 AST 비교로 "결함 부분만 다르다"를 강제한다
- 각 취약 구현 위에 "실제 버그 패턴 + 근거 사례" 주석을 둔다
- 공개 진입점 `backend/main.py`는 취약 모듈을 import하지 않고, 취약 모드는 시스템 임시 폴더 안의 DB만 쓸 수 있다

### 5.3 시나리오별 기준

| ID | 취약 구현의 결함 | 안전 기준(PASS) | 매핑 | 상태 |
|---|---|---|---|---|
| SC-01 | 계좌 소유자 확인 누락 | 403, 타인 데이터 미반환 | API1:2023 · CWE-639 | 완료 |
| SC-03 | 잔액 읽기 → 계산 → 덮어쓰기, 트랜잭션 없음 | 동시 2건 중 1건 201·1건 409, 잔액 합 보존, 기록 1건 | CWE-362 / CWE-367 | 완료(SQLite), PostgreSQL 예정(B) |
| SC-04 | 클라이언트 `request_id`를 저장·확인 안 함 | 재전송 200·같은 거래 ID, 다른 내용 409, 출금 1회 | CWE-837 | 완료 |
| SC-05 | 관리 라우터에 역할 검사 없음 | 403, 상태 불변, 감사 로그 1건 | API5:2023 · CWE-285 | 완료 |
| SC-06 | 요청 키를 그대로 갱신에 반영 | 422, 잔액·소유자·상태·별칭 불변 | API3:2023 · CWE-915 | 완료 |
| SC-07 | 인증 실패를 세지 않음 | 5회 실패 뒤 6번째부터 429 + Retry-After, 잠금 중엔 맞는 토큰도 거절, 다른 클라이언트는 200 | API2:2023 · CWE-307 | 완료(토큰 인증), 로그인 연결 예정(C) |
| SC-08 | (취약 버전을 클라우드에 만들지 않음, CVE 사례로 설명) | public 테이블 전부 RLS 켜짐 + `anon`·`authenticated` 테이블 권한 없음. 접속 불가는 ERROR | API8:2023 · CWE-284 | 예정(B) |
| SC-09 | 서버가 OTP를 검증하지 않고 클라이언트의 `"otp_verified": true`를 믿음 | OTP 없음·틀림·재사용 모두 거절, 송금 미실행, 잔액·기록 불변. 양성 대조: 올바른 OTP로 201 | CWE-841 / CWE-287 | 예정(C) |
| SC-02(세부) | 서버 모델이 일반 int를 받음 | 0원·음수 422, DB 불변 | CWE-602 / CWE-20 | 완료 |

### 5.4 SC-07 동작 상세 (현재)

- 클라이언트 구분: 연결 주소(`request.client.host`). `X-Forwarded-For`는 신뢰하지 않는다
- 기준: 최근 300초 안에 실패 5회(`backend/config.py`의 `AUTH_MAX_FAILURES`, `AUTH_WINDOW_SECONDS`)
- 경쟁 조건 방지: `BEGIN IMMEDIATE` 안에서 횟수 확인과 시도 예약을 한 번에 하고, 인증 성공 시 예약을 지운다
- 성공해도 이전 실패 횟수는 초기화하지 않는다
- 잠금 응답은 감사 로그에 `AUTH_LOCKED`(429)로 남긴다

### 5.5 정적 분석·의존성 점검·탐지

| 항목 | 내용 |
|---|---|
| Semgrep 대상 | `fixtures/code`, `backend/services/insecure_lab.py`, `backend/`(insecure_lab 제외) — 상수로 고정 |
| Semgrep 규칙 | BG-SAST-001 SQL 문자열 조립(CWE-89), 002 금액 float(CWE-1339), 003 민감정보 로그(CWE-532), 004 TLS 검증 해제·하드코딩 비밀(CWE-295/798) |
| Semgrep 결과 | "검토 필요" 의심 항목. 0건 ≠ 안전. 도구 오류는 `SCAN_ERROR`로 0건과 구분 |
| SCA | pip-audit이 앱 가상환경에 **실제 설치된 패키지**를 점검(`PIPAPI_PYTHON_LOCATION`). 인터넷 필요 → 대시보드 전체 검사에는 미포함, 별도 명령·CI·보고서에만 |
| DET-01 | 같은 사용자가 5분 안에 서로 다른 계좌 3개 이상에서 `ACCESS_DENIED`/`NOT_FOUND` → 경보. 실제 감사 로그 조회로만 생성. 탐지이지 차단이 아님 |

모든 외부 프로그램 실행은 `subprocess`에 리스트 인자(`shell=False`), 고정 대상, 타임아웃으로만 합니다.

## 6. 결과 데이터

시나리오 실행 결과(공통 모델):

- 실행 단위: `run_id`, `run_at`(UTC), `target`, `mode`, `total`, `pass`, `fail`, `error`, `skip`, `items`
- 항목: `id`, `name`, `risk`, `status`, `expected`, `observed`, `description`, `fix_guide`, `evidence`, `likelihood`, `impact`, `owasp`, `cwe`, `kr_weakness`, `tier`(`core`/`detail`)

저장 위치는 `artifacts/latest_{api_vulnerable,api_secure,sast,det01,sca}.json`이며, 보고서는 `artifacts/diagnosis_report.md`, 비교표는 `artifacts/coverage_matrix.json`입니다. 대시보드는 시작할 때 이 파일을 자동으로 읽지 않습니다(이전 PASS를 현재 결과로 오인하지 않도록).

위험도는 가능성(L1~L3) × 영향(I1~I3)의 프로젝트 내부 학습용 기준이며 CVSS 인증 점수가 아닙니다.

## 7. CI

| 단계 | 실패 조건 |
|---|---|
| pytest | 테스트 하나라도 실패 |
| 보안 게이트(`scanners.ci_gate`) | 안전 코드에서 Semgrep 탐지 또는 스캔 오류, 취약 샘플 미탐지·수정 샘플 오탐, 안전 모드 핵심 시나리오가 PASS가 아님 |
| 의존성 점검(`scanners.sca_runner`) | 알려진 취약점 발견 또는 점검 불가 |
| (예정, Phase E) 프론트 | `npm run build`(타입 검사 포함) 실패, `npm audit` high 이상 |

보안 게이트와 의존성 점검 단계는 pytest가 실패해도 실행됩니다(`if: ${{ !cancelled() }}`). 작업 전체는 어느 단계든 실패하면 실패입니다.

## 8. 설정값과 환경변수

| 이름 | 용도 | 상태 |
|---|---|---|
| `BANKGUARD_SEMGREP_BIN` | Semgrep 실행 파일 경로(없으면 `.venv-semgrep` → PATH) | 현재 |
| `BANKGUARD_PIP_AUDIT_BIN` | pip-audit 실행 파일 경로(없으면 `.venv-sca` → PATH) | 현재 |
| `BANKGUARD_ARTIFACTS_DIR` | 결과 저장 위치 변경(테스트가 실제 결과를 덮어쓰지 않게) | 현재 |
| `PYTHONUTF8=1` | 한국어 Windows에서 UTF-8 규칙 파일 읽기(실행기가 자동 설정) | 현재 |
| `BANKGUARD_DB_URL` | SQLite/PostgreSQL 선택. 운영은 PostgreSQL 필수 | 예정(B) |
| DB 접속 정보, TOTP 암호화 키, 시연 계정 비밀번호 | `.env`에만. 항목과 설명은 `.env.example` | 예정(B·C) |

## 9. 테스트 전략

- 기본 `pytest`: 임시 SQLite, 인터넷 불필요. 2026-10-29 기준 **332개**
- Semgrep이 설치돼 있으면 실제 Semgrep 통합 테스트도 실행, 없으면 SKIP
- pip-audit 단위 테스트는 가짜 출력으로 파서를 검증(실제 실행은 인터넷이 필요해 별도 명령으로 기록)
- 예정(Phase B): `pytest -m postgres` — 테스트용 Supabase에서 SC-03 재현. DB 설정이 없으면 **SKIP으로 보고**하고 PASS로 세지 않음
- 예정(Phase C): 새 인증 위에서 SC-01·03·04·05·06이 그대로 재현되는지 회귀 테스트
