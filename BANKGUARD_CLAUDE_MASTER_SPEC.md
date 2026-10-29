# BankGuard — Claude 전달용 마스터 개발 명세서

> **문서 버전:** v2.0 / 2026-10-29 (v1.2 / 2026-10-28, v1.1 / 2026-10-28, v1.0 / 2026-10-27)  
> **프로젝트 성격:** 1인 바이브 코딩 프로젝트(바이브코딩 수업 개별 사이드 프로젝트), 은행 IT·애플리케이션 보안 포트폴리오  
> **목표 직무:** 금융권 IT 보안 부서 (AppSec·취약점 진단·데이터분석보안)  
> **일정:** 10/28~11/6 오전 개발, 11/6 오후 최종 산출물 정리·발표. v1.x 계획(DAY 1~8)은 10/29 오전에 완료됨 → 남은 일정은 `docs/plan.md`(Phase A~E + 확장 X1~X4)를 따른다  
> **필수 스택(수업 고정):** FastAPI · React · TypeScript · Supabase  
> **언어:** 모든 UI, README, 결과 설명, 작업 보고는 한국어  
> **우선순위:** 실제 동작 > 검증 가능성 > 직무 연관성 > 시연 완성도 > 화면 장식

---

## v2.0 (2026-10-29) — 이 장이 문서 전체의 최상위 기준

우선순위: **v2.0 장 > v1.2 표 > v1.1 표 > 본문.** 아래 9절에 적힌 v1.x 항목은 v2.0으로 대체된다.

### V0. 배경

- v1.x 계획(DAY 1~8)은 Claude Code로 10/28 오후~10/29 오전에 모두 완료됐다(커밋 1f00d7e~d8c479f). 일정 추정이 사람이 직접 코딩하는 속도 기준이었기 때문이다.
- 이 프로젝트는 바이브코딩 수업의 개별 사이드 프로젝트이며, 수업 필수 스택은 **FastAPI, React, TypeScript, Supabase**다. v1.x는 Streamlit·SQLite를 써서 React·TypeScript·Supabase가 빠져 있었다.
- 수업 문서 흐름(MVP → PRD → SPEC → PLAN)에 맞춰 `docs/mvp.md`, `docs/prd.md`, `docs/spec.md`, `docs/plan.md`를 둔다. 이 마스터 명세는 원천 문서로 유지하고, docs 문서는 이 명세에서 쉬운 말로 뽑아낸다.
- 남은 일정은 실제 속도 기준으로 다시 짰다. AI가 코드를 쓰는 부분은 빠르고, **사람이 해야 하는 일(Supabase 설정, Figma, 화면 직접 확인, 이해 정리, 발표)이 병목**이다. 수업 원칙 "사람이 병목이어야 한다"를 일부러 지킨다.

### V1. 필수 스택 (완료 기준 1순위)

| 영역 | 필수 도구 | v1.x 상태 | v2.0 목표 |
|---|---|---|---|
| 백엔드 | FastAPI | 사용 중 | 유지 |
| 화면 | React | 없음(Streamlit) | Vite + React로 교체, Streamlit 제거 |
| 언어 | TypeScript | 없음 | 모든 화면 코드는 `.ts`/`.tsx`, `strict: true`. `.jsx`/`.js` 금지 |
| DB | Supabase | 없음(SQLite) | Supabase PostgreSQL을 운영(시연) DB로 사용. SQLite는 테스트 전용(수업 방식) |

수업 06·08강과 같은 방식으로 **FastAPI가 Session pooler 접속 정보(`.env`)로 Supabase PostgreSQL에 연결**한다.

### V2. 아키텍처와 설계 결정

```text
[React + TypeScript (Vite)] ──(같은 출처: Vite proxy /api)──▶ [FastAPI] ──(Session pooler)──▶ [Supabase PostgreSQL]
                                                                 ▲
[CLI·CI: 시나리오·Semgrep·pip-audit 실행] ─▶ artifacts/*.json ─────┘ (FastAPI는 결과를 읽기 전용으로 제공)
```

- **D1. 브라우저는 Supabase에 직접 접속하지 않는다.** anon/publishable 키를 프론트 코드나 `VITE_*` 변수에 두지 않는다(Vite의 `VITE_*` 값은 번들에 그대로 공개된다). DB 접근은 FastAPI만 한다. 근거: 프론트가 anon 키로 Supabase를 직접 부르는 구조에서 RLS 누락으로 수백 개 앱의 데이터가 노출된 사례(CVE-2025-48757).
- **D2. 모든 public 테이블에 RLS를 켜고, `anon`·`authenticated` 역할의 테이블 권한을 회수(REVOKE)한다.** 정책이 없는 RLS는 API 역할에 대해 전부 거부가 된다. 백엔드는 DB 소유 역할로 접속한다.
- **D3. 로그인은 직접 구현한다(Supabase Auth 미사용).** 인증 설계가 이 포트폴리오의 핵심 보안 요소이기 때문이다. 수업 자료도 Supabase를 DB로만 사용한다.
- **D4. 점검 실행(시나리오·Semgrep·pip-audit)은 CLI와 CI에서만 한다.** 웹은 `artifacts/`의 결과를 **관리자만 읽기 전용**으로 본다. 배포 환경에 subprocess 실행 경로와 취약 모드 경로가 0개여야 한다.
- **D5. 취약 비교 모드는 지금처럼 TestClient + 임시 SQLite에서만** 만든다. PostgreSQL 경쟁 조건 재현은 **테스트 전용 DB(시연 DB와 분리)**에서 공개 API 없이 한다.
- **D6. 비밀값:** DB 접속 정보, TOTP 암호화 키, 시연 계정 비밀번호는 `.env`에만 둔다. `.env.example`에는 항목과 설명만 둔다. 코드·문서·로그·답변에 출력하지 않는다.

### V3. DB 전환 (Phase B)

- 드라이버 `psycopg`(3.x). 연결 계층에서 `BANKGUARD_DB_URL`로 SQLite/PostgreSQL을 고른다. 운영 서버는 PostgreSQL URL이 없으면 **SQLite로 자동 전환하지 않고 시작을 거부**한다(수업 06강 원칙). pytest 기본 실행은 임시 SQLite로 오프라인 유지.
- SQL 차이를 연결 계층에서 흡수한다: 자리표시자(`?`↔`%s`), 트랜잭션 시작(`BEGIN IMMEDIATE`↔PostgreSQL 기본 트랜잭션), 자동 증가 키, 시간 타입. **안전 송금의 조건부 UPDATE(`WHERE balance_krw >= ? AND status='ACTIVE'`)는 두 DB에서 같은 의미로 동작해야 하며**, PostgreSQL에서는 행 잠금으로 직렬화됨을 테스트로 확인한다.
- 스키마는 `database/migrations/0001_*.sql`처럼 번호 붙인 SQL 파일로 관리하고 적용 스크립트를 둔다(ORM을 쓰지 않으므로). RLS·REVOKE 문도 마이그레이션에 포함한다.
- Supabase 프로젝트: **시연 DB와 통합 테스트 DB를 분리**한다(별도 프로젝트 권장, 불가하면 별도 schema). 무료 프로젝트 일시 정지 가능성을 README에 적는다.
- **SC-08 Supabase 직접 접근 차단 점검(설정 점검, 신규).** 실제 시연 DB에 대해 SQL로 확인한다: (a) public 스키마의 모든 테이블이 `pg_class.relrowsecurity = true`, (b) `anon`·`authenticated` 역할에 테이블 권한이 없음(`information_schema.role_table_grants`). 하나라도 어기면 FAIL, 접속 불가는 ERROR. 취약 버전을 클라우드에 만들지 않는다(비교는 CVE 사례로 설명). 매핑: OWASP API8:2023, CWE-284.
- **SC-03 PostgreSQL 재현(신규 통합 테스트).** `pytest -m postgres`로 테스트 DB에서 경쟁 조건 하네스를 실행한다. DB URL이 없으면 **SKIP으로 보고**하고 PASS로 세지 않는다.

### V4. 진짜 인증과 2차 인증 (Phase C)

- **회원가입·로그인:** 이메일·비밀번호·이름. 비밀번호는 Argon2id 해시(평문·약한 해시 금지). 시연 계정 비밀번호는 `.env` 값으로 시드한다.
- **세션:** 서버 측 세션 토큰(무작위 256비트, DB에는 해시만 저장), 유휴 30분·절대 8시간 만료, 로그아웃 시 폐기. **httpOnly + SameSite=Strict 쿠키**로 전달(배포 시 Secure). 상태 변경 요청은 CSRF 토큰 헤더를 요구한다. 토큰을 localStorage에 두지 않는다.
- **로그인 실패 제한(SC-07):** 진행 중인 `backend/throttle.py`를 로그인 엔드포인트에 연결한다. 클라이언트 주소 기준 + 계정 기준.
- **송금 2차 인증(OTP, TOTP):** `POST /api/transfers`는 '송금 대기'를 만들고(5분 만료, 잔액 변경 없음), `POST /api/transfers/{id}/confirm`이 OTP를 **서버에서 검증한 뒤에만** 실행한다. 같은 OTP 재사용 거절. 대기 건은 만든 세션의 사용자만 확정 가능. 멱등성(request_id)은 유지한다. TOTP 시크릿은 `.env`의 키로 암호화해 저장하고 출력하지 않는다.
- **SC-09 2차 인증 단계 건너뛰기(신규 핵심 시나리오).** 취약 구현: 서버가 OTP를 검증하지 않고 클라이언트가 보낸 확인 결과(`"otp_verified": true`)를 믿음 → OTP 없이 송금 실행 → FAIL. 안전 기준: OTP 없음·틀림·재사용 모두 거절, 송금 미실행, 잔액·기록 불변 → PASS. 양성 대조: 올바른 OTP로 확정 시 201. 매핑: CWE-841(업무 흐름 강제 미흡), CWE-287. 근거: 응답·파라미터 조작으로 MFA를 우회하는 사례는 버그바운티에서 반복 보고되는 유형.
- **X-Demo-Token 제거:** 운영 경로에서 삭제한다. 기존 시나리오 하네스는 로그인 세션으로 옮기고, 테스트 편의용 로그인 헬퍼만 둔다.
- 관리자 역할(지급정지)과 기존 SC-01·03·04·05·06은 새 인증 위에서 그대로 PASS/FAIL이 재현돼야 한다(회귀 테스트).

### V5. React + TypeScript 화면 (Phase D)

- **Figma로 화면을 먼저 정한다(수업 07강, 사람 작업).** 그다음 `frontend/`에 Vite + React + TypeScript(strict)로 구현한다. Streamlit 파일(`frontend/*.py`)과 관련 테스트는 React가 같은 정보를 보여준 것을 확인한 뒤 삭제한다.
- **화면:** 로그인·회원가입, 내 계좌(원화 쉼표 표시), 거래내역, 송금(+OTP 확인), 계좌 별칭, 관리자 지급정지, **보안 점검 결과(관리자)**: 핵심 시나리오 전후 비교, SAST 결과, SAST↔동적 비교표, DET-01 경보, SCA 결과, 마지막 실행 시각. 결과가 없으면 "아직 검사를 실행하지 않았습니다".
- **개발 환경:** Vite proxy로 `/api`를 FastAPI에 넘겨 같은 출처로 동작시킨다(쿠키 SameSite=Strict 유지). 배포 시 CORS는 정확한 출처 1개만 허용.
- **프론트 보안 규칙:** `dangerouslySetInnerHTML` 금지, 토큰 저장소(localStorage·sessionStorage) 사용 금지, `VITE_*`에 비밀값 금지, 서버 오류 상세를 화면에 그대로 출력 금지.
- **검증:** `npm run build`(타입 검사 `tsc --noEmit` 포함) 성공 + **사람이 브라우저에서 직접 확인**(Network 탭에서 Supabase 도메인 요청 0건 포함).

### V6. 일정

상세는 `docs/plan.md`. 요약: Phase A(SC-07·SCA 마무리, 수업 산출물 docs) → B(Supabase 전환, SC-08, PostgreSQL 경쟁 조건) → C(인증·OTP·SC-09) → D(Figma → React+TS) → E(통합·CI·README·발표 준비). 이후 남는 시간에 확장 X1~X4를 순서대로 한다. 각 Phase 끝에 **사람 화면 확인 + `docs/learning_log.md` 3줄 + 커밋**.

### V7. 확장 목록 (Phase E 이후, 이 순서로)

| ID | 내용 | 직무 연결 |
|---|---|---|
| X1 | **CSRF로 송금시키기(SC-10)·XSS 점검:** 취약 비교는 TestClient에서 CSRF 토큰 검사를 뺀 구현 | 웹 시큐어코딩 연구(CSRF)를 금융 맥락으로 확장 |
| X2 | **이상거래 탐지 확장:** 가상 거래 트래픽(정상+공격) 생성, DET-02 무차별 로그인, DET-03 단시간 다수 송금, DET-04 첫 수취인 고액 송금, 탐지율·오탐률 측정 | 데이터분석보안 |
| X3 | **점검 도구 고도화:** 정답 라벨 기반 Semgrep 정밀도·재현율, TypeScript용 Semgrep 규칙(토큰 저장소·`dangerouslySetInnerHTML`), 로컬 OWASP ZAP baseline | AppSec·DevSecOps |
| X4 | **클라우드 배포:** 안전 모드만, 보안 헤더(CSP 등) 점검, 배포 환경에 점검 실행 경로 없음 확인 | 이후 클라우드 수업 연계 |

### V8. v2.0 완료 기준

- [ ] **필수 스택 4개가 실제로 동작:** React(TypeScript) 화면에서 로그인 → 송금(OTP) → 거래내역 확인, 데이터가 FastAPI를 거쳐 Supabase에 저장됨(Supabase Table Editor에서 확인)
- [ ] 브라우저 Network 탭에 Supabase 도메인 요청 0건, 프론트 빌드 결과물에 Supabase 키·DB 접속 정보 없음(문자열 검색)
- [ ] `npm run build` 성공, `pytest` 전체 통과(SQLite), `pytest -m postgres` 실제 실행 기록(SKIP 아님)
- [ ] 핵심 시나리오 SC-01·03·04·05·06·09 취약 FAIL → 안전 PASS, SC-07 PASS, SC-08 PASS(시연 DB), 진단 보고서 갱신
- [ ] CI: pytest + 보안 게이트 + 프론트 빌드·타입 검사 + `npm audit`(결과 기록, 실패 기준은 high 이상)
- [ ] 수업 산출물 `docs/mvp.md`, `docs/prd.md`, `docs/spec.md`, `docs/plan.md` + `docs/learning_log.md`
- [ ] README: 스택, 실행 방법(백엔드·프론트 터미널 2개 + `.env` 준비), 결과, 한계, AI 활용 내역 갱신
- [ ] 각 Phase의 사람 화면 확인 기록

### V9. 대체되는 v1.x 항목

| v1.x | v2.0 |
|---|---|
| Streamlit 대시보드(10장, DAY 6) | React + TypeScript 화면(V5) |
| `X-Demo-Token` 인증(6장) | 로그인 + 세션 쿠키 + 송금 OTP(V4). 테스트에서만 로그인 헬퍼 |
| SQLite 운영 DB(3·5장) | Supabase PostgreSQL. SQLite는 테스트 전용(V3) |
| 2장 "명시적 제외: React" | 삭제 |
| 14장 "외부 API 키·인터넷 없이 완전 시연" | 시연은 Supabase 때문에 인터넷 필요. **pytest 기본 실행은 오프라인 유지** |
| 13장 DAY 계획 | `docs/plan.md` Phase A~E + X1~X4 |
| P1 "SC-07 무차별 대입" | 핵심 범위로 포함(V4) |

---

## v1.1 변경 요약 (2026-10-28) — 이 표가 본문과 충돌하면 이 표가 우선

목적: 흔한 "취약한 가상 은행" 포트폴리오와 차별화하고 금융권 보안 실무(진단 → 조치 → 이행점검, 로그 기반 탐지)에 맞춘다. 범위는 8일 안에서 유지한다.

| # | 변경 | 반영 위치 |
|---|---|---|
| 1 | **SC-03을 '동시 송금 경쟁 조건(TOCTOU)'으로 교체.** 단순 잔액 초과는 세부 테스트 T08로 유지 | 7장, DAY 4 |
| 2 | **감사 로그(`audit_log`) + 탐지 규칙 1개(계좌 열거 의심)** 를 P0에 추가 | 5장, 6장, 7장, DAY 2·7 |
| 3 | **Semgrep 규칙을 금융 맥락으로 교체**(SQL 문자열 조립, 금액 float, 민감정보 로깅, TLS 비활성화/하드코딩 비밀) + 분석 대상에 `backend/`, `insecure_lab.py` 포함 | 8장, DAY 5 |
| 4 | **SAST ↔ 동적 테스트 탐지 범위 비교표**를 P0 산출물로 추가 | 8.6, DAY 7 |
| 5 | **실무형 진단 보고서(Markdown)** 와 **CI 보안 게이트(GitHub Actions)** 를 P1 → P0로 이동 | 2장, DAY 7 |
| 6 | **`GET /api/demo/users` 삭제.** 공개 서버에서 토큰을 노출하지 않는다. 대시보드는 `backend.seed`의 상수를 직접 import | 6.2 |
| 7 | 자기 계좌 송금은 **400**으로 확정, `transfers.amount_krw`에 `CHECK(amount_krw > 0)` 추가 | 5장, 6.5 |
| 8 | 위험도 산정 기준(가능성 × 영향 3×3) 명시, 결과 항목에 OWASP/CWE/행안부 보안약점 매핑 필드 추가 | 7.0, 9장 |
| 9 | 500 오류 시 스택트레이스·로컬 경로 비노출 테스트(T16), 403 시도 감사 로그 기록 테스트(T17) 추가 | 7장 |
| 10 | `docs/threat_model.md`(데이터 흐름 + STRIDE 1페이지) 추가 | 11장, DAY 6 |
| 11 | DAY 1 실제 결과 반영: Semgrep은 앱과 **별도 가상환경**(`requirements-sast.txt`) — opentelemetry-api 버전 충돌 | 3장 |
| 12 | 후속 확장(AI 에이전트 보안 등)은 **구현하지 않고** README '향후 확장'에 2~3줄로만 기록 | 2장 |

## v1.2 변경 요약 (2026-10-28) — v1.1 표와 충돌하면 이 표가 우선

목적: OWASP API Security Top 10(2023) 상위 항목 커버리지를 넓혀 프로젝트 체급을 키운다. DAY 2 구현(진행 중)은 그대로 두고, 추가분은 DAY 3에 반영한다.

| # | 변경 | 반영 위치 |
|---|---|---|
| 1 | **핵심 시나리오를 5개로 재구성:** SC-01 BOLA, SC-03 경쟁 조건, SC-04 멱등성, **SC-05 BFLA(권한 없는 관리자 기능 호출)**, **SC-06 BOPLA/Mass Assignment(요청에 필드 끼워넣기)** | 2장, 7장 |
| 2 | **SC-02(0원·음수 금액)는 핵심에서 하향** → 세부 테스트 T06·T07로만 유지(검사 자체는 계속 실행). 너무 기본적인 결함이라 대표 시나리오로 내세우지 않음 | 7장 |
| 3 | 스키마 추가: `users.role`(`customer`/`admin`), `accounts.status`(`ACTIVE`/`FROZEN`), `accounts.nickname` + 가상 운영자 계정(user 9, `demo-token-admin`, 계좌 없음) | 5장 |
| 4 | API 추가: `POST /api/admin/accounts/{id}/freeze`(지급정지, admin 전용), `PATCH /api/accounts/{id}`(계좌 별칭 변경, 본인만, `nickname`만 허용) | 6.6, 6.7 |
| 5 | 지급정지 계좌에서 출금 시도는 409 | 6.5 |
| 6 | SC-07(인증 무차별 대입·시도 횟수 제한, API2/API4)은 **P1** | 2장 |
| 7 | 시나리오 ID는 그대로 유지(SC-02 번호는 결번 처리하지 않고 '세부 테스트로 이동'이라고 표기) — 문서·코드 간 혼동 방지 | 전체 |

---

## 0. Claude에게 가장 먼저 전달할 지시 (필독)

당신은 이 프로젝트의 **시니어 Python 개발자 + 금융권 AppSec 엔지니어 + 테스트 엔지니어** 역할을 맡는다. 단순하게 그럴듯한 코드를 출력하는 것이 아니라, 아래 요구사항에 맞는 **실행 가능하고 반복 검증되는 최소 제품(MVP)** 을 단계별로 구현한다.

### 반드시 지킬 원칙

1. 이 문서의 **필수(P0) 범위**를 먼저 완성한다. 새 기능을 임의로 확장하지 않는다.
2. 작업 전 현재 프로젝트 파일과 실행 환경을 확인하고, 이미 만든 코드를 보존·재사용한다.
3. 각 단계 종료 시 **추가/변경 파일, 구현 기능, 실행 명령, 실제 테스트 결과, 미해결 문제, 다음 단계**를 한국어로 간결히 보고한다.
4. 실행하지 않은 테스트를 통과했다고 말하지 않는다. 터미널에 접근할 수 없는 Claude 채팅 환경이라면 실행 가능한 코드·명령을 제공하고 **실행 미검증**이라고 표시한다.
5. 한 번에 거대한 코드를 생성하지 말고 **작동하는 작은 단위**로 구현하고 검증한다. 실패하면 원인을 확인해 최소 수정 후 다시 확인한다.
6. 보안 실습은 **로컬의 가상 데이터에 한정**한다. 실제 은행, 외부 시스템, 타인의 계정, 외부 URL에 공격 요청을 보내지 않는다.
7. 정상 API는 언제나 안전하게 구현하고, 비교용 취약 구현은 **네트워크에 공개하지 않는 격리된 테스트 클라이언트 안에서만** 호출 가능하게 한다.
8. 보안 검사 결과를 하드코딩하거나 가짜 PASS/FAIL을 만들지 않는다. 결과는 **실제 실행한 API 테스트 및 Semgrep 스캔 출력**에서 생성한다.
9. 정적 분석(SAST)으로 송금 비즈니스 로직 취약점을 탐지했다고 허위 주장하지 않는다. 업무 로직은 실행 기반 테스트로, 소스 패턴은 Semgrep으로 확인한다.
10. 라이브러리 버전·CLI 사용법이 실제 환경과 다르면 설치 로그 및 공식 문서를 기준으로 조정하되, 변경 이유를 기록한다.
11. 사용자가 구현 범위를 줄이도록 요구하지 않는 한 본 명세의 P0 구현·테스트·README까지를 **완료 기준**으로 삼는다.
12. 프로젝트에 진짜 계좌정보·인증키·개인정보를 넣지 않는다. 모든 비밀 문자열 예시는 무효한 더미 값으로 명시한다.

### 첫 응답에서 해야 할 일

- 이 명세를 10줄 이내로 요약한다.
- Windows/PowerShell에서 Python 및 Semgrep 설치 가능 여부, 작업 폴더, 가상환경 상태를 점검한다.
- DAY 1의 폴더 구조와 실행 가능한 `GET /health`부터 구현한다.
- 필수 정보가 없어 진행이 불가능한 경우를 제외하고, 이 문서에 이미 확정된 사항은 다시 묻지 않는다.

---

## 1. 프로젝트 한 줄 정의

**BankGuard는 가상의 은행 계좌·송금 API를 대상으로 보안 시나리오를 자동 실행하고, Python 소스코드를 정적 분석해 위험 사항과 수정 전후 검증 결과를 한 화면에서 보여주는 로컬 보안 점검 플랫폼이다.**

### 왜 만드는가?

- 목표 직무: **은행 IT 보안 / 애플리케이션 보안(AppSec) / 시큐어코딩 점검 / DevSecOps**.
- 채용 포트폴리오에서 보여 줄 역량: API 구현 이해 → 접근권한 및 거래 무결성 점검 → 코드 정적 분석 → 테스트 자동화 → 취약점 보고 및 재검증.
- 기존 도구를 단순 설치한 경험을 넘어, 은행 업무에 맞는 **검증 기준(test oracle)** 을 직접 설계했다는 점이 핵심이다.

### 처음 보는 사람을 위한 설명

가상의 A·B 고객 계좌가 있는 작은 은행을 만든다. 정상 송금은 가능하지만, 타인 거래내역 조회, 음수 송금, 잔액 초과, 동일 송금 중복 처리 같은 상황에서는 서버가 적절히 막는지 검사해야 한다. BankGuard에서 **[보안 테스트 실행]** 버튼을 누르면 테스트가 자동 수행되고, 각 항목에 **안전 기준 통과(PASS) / 취약 동작 확인(FAIL) / 검사 자체 오류(ERROR)** 를 표시한다. 별도로 **[정적 분석 실행]** 버튼을 누르면 코드에 위험한 함수·설정이 있는지 Semgrep으로 찾는다. 마지막으로 수정 전후 결과를 나란히 비교해 설명한다.

### 이번 프로젝트에서 '은행'이 의미하는 것

실제 은행 시스템의 복제물이 아니라 **테스트용 송금·계좌조회 비즈니스 규칙을 가진 소규모 금융 도메인**이다. 금융 규제 준수·실제 금융망 연계·운영 수준의 인증·암호화 체계 구현을 주장하지 않는다.

---

## 2. 범위 정의 — 절대 과도하게 확장하지 말 것

### P0: 반드시 구현

- [ ] 가상 사용자 3명, 계좌 3개 및 초기 잔액 생성
- [ ] 안전한 계좌 조회·거래내역 조회·송금 REST API
- [ ] **5개 핵심 보안 시나리오**(v1.2: SC-01 BOLA, SC-03 동시 송금 경쟁 조건, SC-04 멱등성, SC-05 BFLA, SC-06 BOPLA/Mass Assignment) + 세부 검증(T01~T21, 0원·음수 금액 T06·T07 포함)
- [ ] 비교용 '취약한 로직'과 '수정된 안전한 로직'의 격리 실행
- [ ] **감사 로그**(인증 실패·권한 거부·송금 성공/실패 기록, 계좌번호 마스킹) + **탐지 규칙 1개**(계좌 열거 의심)
- [ ] Semgrep CE와 **금융 맥락 로컬 규칙 4개 이상** 연동
- [ ] Semgrep 결과에서 실제 탐지 위치(파일/행/규칙/메시지) 추출
- [ ] **SAST ↔ 동적 테스트 탐지 범위 비교표**(실제 실행 결과로 생성)
- [ ] Streamlit 한국어 대시보드: 테스트 결과, 세부 설명, 정적 분석, 전후 비교
- [ ] 재현 가능한 `pytest` 자동 테스트 및 실행 방법
- [ ] **실무형 취약점 진단 보고서(Markdown)**: 점검항목/위험도/취약여부/근거/조치권고/이행점검 결과
- [ ] **CI 보안 게이트**: GitHub Actions에서 pytest + Semgrep 실행, 기준 위반 시 실패
- [ ] `docs/threat_model.md`: 송금 데이터 흐름 + STRIDE 표 1페이지
- [ ] 실제 실행 결과에 근거한 최종 README, 시연 시나리오, 결과 보고

### P1: P0를 다 끝내고 시간이 남으면

- [ ] PDF 또는 HTML 보안 진단 보고서 내보내기
- [ ] 실행 기록을 파일로 저장하고 과거 검사와 비교
- [ ] SCA(`pip-audit`) 의존성 취약점 점검
- [ ] (v1.2) SC-07 인증 무차별 대입: 잘못된 토큰 반복 시 시도 횟수 제한·일시 차단(OWASP API2/API4)
- [ ] 추가 보안 시나리오(로그인 시도 제한 등)

### 향후 확장 (구현하지 않음 — README에 2~3줄로만 기록)

- 송금 API를 도구로 쓰는 금융 AI 에이전트의 보안 점검(모델 계층 탈옥 탐지 + 실행 계층 권한 통제). 캡스톤(한국어 LLM 탈옥 탐지)과의 연결 아이디어로만 언급하고, 구현했다고 표현하지 않는다.

### 명시적으로 제외

- 실제 계좌 개설/인증, 계좌이체·오픈뱅킹 연동, 결제, 실명정보
- 실서비스 배포 및 인터넷에 취약 API 공개
- 자체 SAST 엔진 개발, 거대한 취약점 데이터베이스 구축
- AI 모델 학습, 이상거래 예측 모델, LLM 자동 수정
- React/Node.js 프론트엔드, 복잡한 로그인·회원가입
- 클라우드·Kubernetes·마이크로서비스·대규모 트래픽 아키텍처

### 범위 조정 원칙

- 일정이 밀리면 **Streamlit 디자인 → 위협 모델링 문서 분량 → 대시보드 탭 수** 순으로 축소한다. CI 게이트와 Markdown 진단 보고서는 작게라도 유지한다.
- API 안전성·테스트 반복성·결과 신뢰도는 축소하지 않는다.
- 보안 테스트 개수를 무조건 늘리기보다 **핵심 4종이 확실히 재현되는 것**을 우선한다.

---

## 3. 기본 기술 스택과 실행 환경

| 영역 | 선택 | 이유 |
|---|---|---|
| 언어 | Python 3.11 또는 3.12 | Python 중심, Windows 호환성과 학습 효율 |
| REST API | FastAPI + Pydantic | 명확한 요청/응답 검증, 자동 API 문서 |
| DB | Python 표준 라이브러리 `sqlite3` | ORM 설정 부담 감소; 트랜잭션 직접 검증 |
| 대시보드 | Streamlit | 프론트 구현 시간을 크게 절약 |
| API 테스트 | pytest + FastAPI `TestClient`(HTTPX 기반) | 실제 HTTP 라우팅과 응답을 인프로세스 검사 |
| 정적 코드 분석 | Semgrep Community Edition | 로컬 규칙 및 JSON 결과 활용 |
| 규칙 파일 | YAML | 재현 가능한 SAST 정책 |
| 결과 데이터 | Python dict/dataclass + JSON | 화면/리포트 공통 결과 포맷 |
| 버전관리 | Git/GitHub | 커밋과 실행 절차, 결과 기록 |
| OS | Windows 10 + PowerShell 또는 Git Bash | 사용자 개발환경 고려 |

**중요:** Semgrep은 현재 Windows용 로컬 CLI를 제공하지만 버전/환경별 설치 이슈가 있을 수 있다. 우선 PowerShell에서 `python -m pip install semgrep`, `semgrep --version`으로 확인하고, 실패 시 WSL 또는 Docker 대안을 검토한다. Semgrep 설치가 안 될 때 탐지 결과를 임의 생성하지 않는다.

### 의존성(초기 제안)

- `fastapi`
- `uvicorn[standard]`
- `pydantic`
- `streamlit`
- `pytest`
- `httpx`
- `semgrep`
- `PyYAML` (필요한 경우)

**v1.1 확정(DAY 1 실측):** `semgrep`은 `requirements.txt`에 넣지 않고 `requirements-sast.txt`로 분리해 별도 가상환경(`.venv-semgrep`) 또는 pipx에 설치한다. semgrep 1.182.1은 `opentelemetry-api==1.37.x`를 고정하고 fastapi 0.162.0은 `>=1.44.0`을 요구해 같은 환경에서 충돌한다(함께 설치하면 semgrep이 1.79.0으로 내려감). `sast_runner.py`는 Semgrep 실행 파일 경로를 설정값(예: 환경변수 `BANKGUARD_SEMGREP_BIN` → `.venv-semgrep` → PATH 순)으로 찾는다.

실제 설치에 성공한 버전을 `requirements.txt` 또는 잠금 파일에 반영한다. 필요하지 않은 패키지는 추가하지 않는다. `.env`는 필요 시 로컬 설정에 한정하고 버전관리에서 제외한다.

---

## 4. 시스템 아키텍처

```text
                    [ Streamlit 대시보드 ]
                       │           │
          실제 송금 API │           │ [보안 검사 실행] 버튼
                       ▼           ▼
                [ FastAPI ]    [검사 실행 서비스]
                 안전 모드       ├── API 시나리오 실행기
                    │           │    ├─ 격리 DB + 취약 비교 모드
                    ▼           │    └─ 격리 DB + 안전 모드
              [ SQLite ]       ├── pytest 검증
              더미 계좌         └── Semgrep CLI + YAML 규칙
                                    │
                                    ▼
                              [ 공통 결과 모델 ]
                                    │
                                    ▼
                          [PASS/FAIL/ERROR / SAST]
                                    │
                                    ▼
                         [개선 비교 · 진단 리포트]
```

### 핵심 설계 결정

1. **운영 API와 취약 비교 모드를 분리:** `backend.main:app`은 항상 **안전 모드만** 공개한다.
2. **취약 비교 코드는 내부 테스트 전용:** `create_app(mode="vulnerable", db_path=임시파일)` 식으로 **TestClient에서만 생성**하고 외부 서버 실행 명령에 취약 모드를 허용하지 않는다. 취약 모드는 프로덕션 실행 진입점에서 선택 불가하게 만든다.
3. **테스트 데이터 격리:** 각 시나리오 실행마다 `tempfile.TemporaryDirectory` 아래 독립 SQLite DB를 만들고 초기화한다. 검사는 실사용 UI의 계좌 데이터나 이전 시나리오의 잔액을 변경하지 않는다.
4. **외부 시스템 접근 금지:** 대상 IP/도메인을 입력받거나 임의 외부 URL을 검사하는 기능은 구현하지 않는다.
5. **같은 테스트를 두 모드에서 반복:** 안전성 검증 기준은 동일하며, 취약한 로직이 기준을 어기면 **FAIL**, 수정된 로직이 충족하면 **PASS**로 나타나야 한다.
6. **정적 분석은 고정된 로컬 경로만:** `fixtures/code` 및 제한된 로컬 분석 대상으로 실행한다. 사용자 입력을 셸 명령문에 직접 연결하지 않는다.

---

## 5. 데이터 모델 및 시드 데이터

### DB 스키마 제안

**users**

| 필드 | 타입 | 의미 |
|---|---|---|
| id | INTEGER PK | 사용자 ID |
| display_name | TEXT NOT NULL | 더미 사용자 이름 |
| demo_token | TEXT UNIQUE NOT NULL | 데모 전용 식별 토큰. 실제 인증 체계가 아님 |

**accounts**

| 필드 | 타입 | 의미 |
|---|---|---|
| id | INTEGER PK | 내부 계좌 식별자 |
| owner_user_id | INTEGER FK(users.id) | 계좌 소유자 |
| account_no | TEXT UNIQUE NOT NULL | 허구의 계좌번호 |
| balance_krw | INTEGER NOT NULL CHECK(balance_krw >= 0) | 잔액(원 단위 정수) |

**transfers**

| 필드 | 타입 | 의미 |
|---|---|---|
| id | INTEGER PK | 송금 ID |
| request_id | TEXT UNIQUE NOT NULL | 중복 요청 판별 ID(UUID 문자열) |
| sender_account_id | INTEGER NOT NULL FK | 출금 계좌 |
| recipient_account_id | INTEGER NOT NULL FK | 입금 계좌 |
| amount_krw | INTEGER NOT NULL CHECK(amount_krw > 0) | 송금 금액 (v1.1: DB 수준 다층 방어) |
| payload_fingerprint | TEXT NOT NULL | 동일 ID·상이한 페이로드 구별 |
| created_at | TEXT NOT NULL | UTC ISO8601 생성시각 |

**audit_log (v1.1 추가)**

| 필드 | 타입 | 의미 |
|---|---|---|
| id | INTEGER PK | 로그 ID |
| created_at | TEXT NOT NULL | UTC ISO8601 |
| event_type | TEXT NOT NULL | `AUTH_FAIL` / `ACCESS_DENIED` / `NOT_FOUND` / `TRANSFER_OK` / `TRANSFER_REJECTED` / `IDEMPOTENT_REPLAY` 등 |
| actor_user_id | INTEGER NULL | 토큰으로 식별된 사용자(인증 실패면 NULL) |
| token_fingerprint | TEXT NULL | 토큰 원문이 아닌 SHA-256 앞 12자리 (인증 실패 추적용) |
| target_account_id | INTEGER NULL | 대상 계좌 ID |
| http_status | INTEGER NOT NULL | 응답 코드 |
| detail | TEXT NULL | 마스킹된 요약(계좌번호는 `DEMO-1**`), 토큰·전체 계좌번호 원문 저장 금지 |

- 감사 로그 기록은 송금 트랜잭션과 분리한다. 송금 실패로 rollback되어도 거절 로그는 남아야 한다.
- 탐지 규칙 `DET-01 계좌 열거 의심`: 같은 사용자(또는 토큰 지문)가 최근 N분(기본 5분) 안에 서로 다른 계좌 ID에 대해 `ACCESS_DENIED`/`NOT_FOUND`를 K회(기본 3회) 이상 받으면 경보. 임계값은 설정값으로 두고 README에 근거·한계(오탐 가능성)를 적는다. 경보는 실제 audit_log 조회 결과로만 생성한다.

안전 모드는 DB `CHECK(balance_krw >= 0)`을 활성화하고, 오류 시 `ROLLBACK`해야 한다. 취약 모드 구현 방식 때문에 동일 제약을 우회하지 못한다면 `vulnerable` 모드 전용 임시 DB 스키마를 분리하거나 DB 변경 없는 부정확한 응답 예시보다 **실제 재현 가능한 핵심 2~3개 취약 사례**를 우선하라. 단, P0 목표는 4개 모두 재현이다.

### 시드 데이터 (모두 허구)

| 사용자 | user_id | 계좌 ID | 초기 잔액 | 데모 토큰 |
|---|---:|---:|---:|---|
| 가상 고객 A | 1 | 101 | 1,000,000원 | `demo-token-a` |
| 가상 고객 B | 2 | 102 | 500,000원 | `demo-token-b` |
| 가상 고객 C | 3 | 103 | 2,000,000원 | `demo-token-c` |

**v1.2 추가 시드:** 가상 운영자 `user_id=9`, 이름 `가상 운영자`, 토큰 `demo-token-admin`, `role='admin'`, 계좌 없음. 고객 A/B/C는 `role='customer'`. 모든 계좌는 `status='ACTIVE'`, `nickname`은 NULL로 시작.

**v1.2 스키마 추가(DAY 3에 반영):**
- `users.role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','admin'))`
- `accounts.status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK(status IN ('ACTIVE','FROZEN'))`
- `accounts.nickname TEXT NULL` (최대 20자)

계좌번호는 실재하지 않는 시연용 값(`DEMO-101`, `DEMO-102`, `DEMO-103`)을 사용한다. 정적분석 샘플의 `password` 등은 명시적인 가짜 문자열만 허용한다.

### 돈과 DB에 관한 불변식(Invariants)

- 원화 금액은 **정수(원)** 로만 다룬다. `float` 또는 소수 금액 금지.
- 안전 모드에서 송금 금액은 `1 <= amount_krw <= 10_000_000`.
- 자기 계좌로의 송금은 거절한다.
- 송금 성공 시 **송금인 잔액 감소분 == 수취인 잔액 증가분 == amount_krw**.
- 잔액 부족/권한 없음/유효하지 않은 입력에서 **DB 잔액은 전혀 변하지 않아야** 한다.
- 출금·입금·송금 기록 생성은 하나의 원자적 DB 트랜잭션이다.
- 같은 `request_id`와 같은 요청 데이터는 두 번째 호출 시 **기존 거래를 재사용**하고 재출금하지 않는다.
- 같은 `request_id`에 다른 요청 내용은 **409 Conflict**로 거절한다.
- SQLite 연결별 `PRAGMA foreign_keys=ON`, 송금 시 트랜잭션 경계를 적절히 관리한다. 동시 접근 안전성을 위해 `BEGIN IMMEDIATE` 또는 동등한 직렬화 방식을 구현·검증한다.

---

## 6. REST API 상세 계약 (안전 모드)

기본 URL: `http://127.0.0.1:8000`. 통일된 오류 응답은 FastAPI 기본 오류 JSON을 허용하되, 프론트에서 안전하게 메시지를 처리한다.

### 6.1 `GET /health`

- 인증 불필요
- 응답 `200 OK`: `{"status":"ok","service":"BankGuard API"}`
- DB 초기화 전에도 서버 생존여부를 확인할 수 있어야 한다.

### 6.2 ~~`GET /api/demo/users`~~ (v1.1 삭제)

- 공개 서버가 토큰 목록을 반환하면 "안전 모드만 공개" 원칙과 충돌하므로 **만들지 않는다.**
- 대시보드의 사용자 선택 UI는 `backend/seed.py`의 시드 상수(더미 이름·계좌 ID·데모 토큰)를 직접 import해 사용한다.
- 테스트: `GET /api/demo/users`가 404임을 확인한다(실수로 다시 생기지 않게).

### 6.3 `GET /api/accounts`

- 헤더: `X-Demo-Token: demo-token-a`
- 본인 계좌만 조회. 유효하지 않거나 누락된 토큰은 `401`.
- 성공 예: `[{"id":101,"account_no":"DEMO-101","balance_krw":1000000}]`
- 토큰은 **학습용 가상 사용자 식별**에 불과하며 실제 은행 인증과 동등하다고 주장하지 않는다.

### 6.4 `GET /api/accounts/{account_id}/transactions`

- 헤더: `X-Demo-Token`
- 본인 소유 계좌인지 확인한 뒤 거래 내역을 반환.
- 성공: `200` + `[{"id":1,"type":"OUT","amount_krw":20000,"created_at":"..."}, ...]` (구현 시 일관된 스키마 유지)
- 존재하지만 남의 계좌를 조회하면 `403 Forbidden`.
- 존재하지 않는 계좌는 `404 Not Found`.
- 토큰 누락 또는 오류는 `401 Unauthorized`.
- **주의:** 거래 기록 조회도 소유권 검사를 거쳐야 한다. 브라우저 UI에서 ID를 숨기는 것은 보안 통제가 아니다.

### 6.5 `POST /api/transfers`

- 헤더: `X-Demo-Token`
- 요청 JSON:

```json
{
  "from_account_id": 101,
  "to_account_id": 102,
  "amount_krw": 20000,
  "request_id": "5d1d7124-1a48-4b3c-9eb0-f9e7ee923801"
}
```

- 첫 송금 성공: `201 Created`.
- 동일 `request_id` + 동일 데이터 재요청: `200 OK` 및 **원래 송금의 같은 `transfer_id`** 반환, 잔액 변동 없음.
- 동일 `request_id` + 다른 송금 데이터: `409 Conflict`.
- 인증 정보 없음/틀림: `401`.
- 출금 계좌가 타인의 계좌: `403`.
- 미존재 계좌: `404`.
- 자기 계좌 송금: **`400`** (v1.1 확정 — 형식 오류는 422, 업무 규칙 위반은 400/409로 구분).
- 음수, 0, 정수가 아닌 금액, 상한 초과: Pydantic 검사 실패 `422`.
- 잔액 부족: `409 Conflict` (다른 오류 코드와 구분 가능한 메시지 권장).
- (v1.2) 출금 계좌가 지급정지(`FROZEN`): `409 Conflict`, 잔액·기록 불변, 감사 로그 `TRANSFER_REJECTED`.
- 성공 응답 예:

```json
{
  "transfer_id": 1,
  "request_id": "5d1d7124-1a48-4b3c-9eb0-f9e7ee923801",
  "from_account_id": 101,
  "to_account_id": 102,
  "amount_krw": 20000,
  "idempotent_replay": false
}
```

재요청 시 `idempotent_replay` 값만 `true`가 될 수 있다. 잔액 등 타인 계좌 민감정보는 송금 응답에 포함하지 않는다.

### 6.6 `POST /api/admin/accounts/{account_id}/freeze` (v1.2)

- 헤더: `X-Demo-Token` — **`role='admin'`인 사용자만** 허용.
- 성공: `200` + `{"account_id": 102, "status": "FROZEN"}`. 이미 FROZEN이면 동일 응답(멱등).
- 고객 토큰: `403`, 계좌 상태 불변, 감사 로그 `ACCESS_DENIED`.
- 토큰 누락/오류: `401`. 없는 계좌: `404`(admin일 때만 판별).
- 권한 검사는 라우터 의존성(예: `require_admin`)으로 서버에서 수행한다. "관리자 화면에 버튼이 안 보이니 안전"은 통제가 아니다.

### 6.7 `PATCH /api/accounts/{account_id}` (v1.2)

- 헤더: `X-Demo-Token`, 본인 계좌만.
- 요청: `{"nickname": "생활비"}` — **허용 필드는 `nickname` 하나**(1~20자). Pydantic `extra="forbid"`.
- 성공: `200` + `{"id":101,"account_no":"DEMO-101","nickname":"생활비"}`.
- `balance_krw`, `owner_user_id`, `status`, `account_no` 등 다른 필드가 섞이면 `422`, DB 불변.
- 타인 계좌: `403`, 없는 계좌: `404`, 토큰 오류: `401`.

#### 정상 송금 예시 계산

송금 전 A 1,000,000원, B 500,000원 → A가 B에게 20,000원 송금 → A 980,000원, B 520,000원. 재전송 후에도 이 잔액을 유지한다.

---

## 7. 보안 시나리오 설계: PASS의 뜻을 분명하게

**PASS = 사전에 정한 '안전한 동작'을 지켰다.**  
**FAIL = 안전 조건을 위반하는 동작이 실제로 관측됐다.**  
**ERROR = 서버 예외·툴 실행 실패 등으로 안전성 판단 자체가 불가능하다.**  
**SKIP = 해당 시나리오를 실행하지 않았다.**

'취약점 탐지 성공'을 PASS로 표현하면 오해가 생기므로, UI에는 `보안 기준 통과(PASS)` / `취약 동작 확인(FAIL)`이라고 명시한다.

### 7.0 위험도 산정 기준 (v1.1)

프로젝트 내부 학습용 기준이며 CVSS 인증 점수가 아니다. `가능성(L1~L3) × 영향(I1~I3)` 3×3 표로 산정한다.

| | 영향 I1 (정보 일부) | I2 (타인 정보 노출) | I3 (금전 손실·무결성 훼손) |
|---|---|---|---|
| **L3** 인증된 일반 사용자가 단순 요청으로 가능 | MEDIUM | HIGH | HIGH |
| **L2** 특정 조건·타이밍 필요 | LOW | MEDIUM | HIGH |
| **L1** 내부자·복합 조건 필요 | LOW | LOW | MEDIUM |

각 시나리오에 L/I 근거를 한 줄씩 적는다. 매핑 필드: `owasp`(예: API1:2023), `cwe`(예: CWE-639), `kr_weakness`(행안부 SW 보안약점 항목명, 예: "부적절한 인가") — 매핑은 원문을 확인한 뒤 기입하고, 확인 못 한 값은 비워 둔다.

### SC-01. 타인 거래내역 조회(객체 수준 접근제어/BOLA)

- **사전조건:** A, B 계좌가 각각 존재한다.
- **요청:** A 토큰으로 B의 계좌 `GET /api/accounts/102/transactions`.
- **기대 결과:** `403`; B의 거래 데이터가 절대 반환되지 않는다.
- **안전 모드:** 서버가 계좌 소유자와 요청 사용자 ID를 비교 → PASS.
- **취약 비교 모드:** 계좌 ID만으로 접근을 허용하는 격리 로직 → FAIL.
- **주요 설명:** OWASP API1:2023 BOLA 사례.
- **위험도(프로젝트 내부 등급):** HIGH.
- **수정 방향:** 모든 객체 ID 접근 경로에서 소유권/권한을 서버 측에서 확인.

### SC-02. 잘못된 송금 금액(0원 및 음수) — v1.2: 핵심 시나리오에서 하향, 세부 테스트 T06·T07로 유지

> 아래 내용은 T06·T07의 기준으로 계속 사용한다. 대시보드·보고서의 '핵심 시나리오' 집계에는 넣지 않고 '세부 테스트'로 표시한다.

- **요청:** A → B `amount_krw=-10000`와 `amount_krw=0` 각각 실행.
- **기대 결과:** `422`, 원래 잔액 변동 없음, 신규 송금 기록 없음.
- **안전 모드:** Pydantic 입력검증 및 서비스 계층 방어 → PASS.
- **취약 비교 모드:** 별도 격리 로직에서 음수/0을 잘못 받아들이는 동작 재현 → FAIL.
- **주의:** 최종적으로는 API의 실제 응답/DB 상태에 근거해 판정한다. 단순 하드코딩된 실패 메시지만 반환하는 방식은 금지.
- **위험도:** HIGH (내부 학습용 등급).

### SC-03. 동시 송금 경쟁 조건(TOCTOU) — v1.1 교체

- **배경:** "잔액 검사 누락"은 실제로 드문 결함이다. 실무에서 더 현실적인 결함은 **검사는 하지만 검사와 차감이 원자적이지 않아** 동시 요청에서 잔액 이상이 출금되는 경우다.
- **사전조건:** B 잔액 500,000원. 각 요청은 **서로 다른 request_id**(멱등성과 구분).
- **요청:** B 토큰으로 B → A 300,000원 송금 2건을 **동시에** 전송(`threading.Barrier`로 시작 시점 정렬, 각 스레드는 독립 DB 연결 사용, 파일 기반 임시 SQLite).
- **기대 결과(안전 기준):** 정확히 1건 `201`, 1건 `409`(잔액 부족). B 잔액 200,000원, A 잔액 1,300,000원, 송금 기록 1건, 전체 잔액 합 보존, 어떤 계좌도 음수 아님.
- **안전 모드:** `BEGIN IMMEDIATE`로 쓰기 직렬화 **또는** `UPDATE accounts SET balance_krw = balance_krw - ? WHERE id = ? AND balance_krw >= ?` 조건부 차감 후 영향 행 수 확인 → PASS.
- **취약 비교 모드:** `SELECT balance` → 검사 → (테스트 전용 짧은 지연으로 경쟁 구간을 결정적으로 재현) → 별도 트랜잭션에서 `UPDATE` → 두 요청 모두 검사 통과 → FAIL.
- **DB 제약과의 관계:** 취약 모드가 두 번째 차감에서 `CHECK(balance_krw >= 0)`에 막히면 그 사실 그대로 기록한다. 이 경우 관측 가능한 위반(예: 두 요청 모두 201을 받았으나 기록·잔액 불일치, 또는 500 응답)을 근거로 판정하고, 마이너스 잔액이 생겼다고 주장하지 않는다. 결정적 재현을 위해 취약 모드 전용 스키마(CHECK 없음)를 쓰는 경우 문서에 명시한다.
- **재현성 요구:** 같은 시나리오를 20회 반복 실행해 결과가 매번 같은지 테스트로 확인한다(플래키 금지).
- **위험도:** HIGH (L2 × I3).
- **수정 방향:** 잔액 검증과 차감을 하나의 원자적 연산/직렬화된 트랜잭션으로 묶는다.
- **단순 잔액 초과**(1,000,000원 보유자가 1,200,000원 송금 → 409, DB 불변)는 세부 테스트 **T08**로 유지한다.

### SC-04. 중복 송금(멱등성)

- **요청:** 같은 `request_id`와 같은 송금 데이터를 2번 전송.
- **기대 결과:** 첫 번째 `201`, 두 번째 `200`, **송금 기록 1건**, 총 출금 1회.
- **안전 모드:** 유일키·페이로드 검사 및 트랜잭션 적용 → PASS.
- **취약 비교 모드:** 요청 식별을 하지 않아 이중 출금이 발생하는 동작 → FAIL.
- **추가 반례:** 같은 `request_id`에 다른 금액을 넣으면 `409`, 입출금 0회 추가.
- **위험도:** HIGH.

### SC-05. 권한 없는 관리자 기능 호출 (BFLA) — v1.2 추가

- **배경:** OWASP API5:2023 Broken Function Level Authorization. 객체(계좌)가 아니라 **기능(관리자 API)** 단위 권한 검사 누락. 관리자 API 경로는 앱 화면에 없어도 추측·유출로 쉽게 알려진다.
- **요청:** 고객 A 토큰으로 `POST /api/admin/accounts/102/freeze` (B 계좌 지급정지 시도).
- **기대 결과(안전 기준):** `403`, 102 계좌 `status='ACTIVE'` 유지, 감사 로그 `ACCESS_DENIED` 1건.
- **양성 대조(positive control):** 운영자 토큰으로 같은 요청 → `200`, `FROZEN`. 이 대조가 실패하면 검사 자체를 ERROR로 처리(권한 검사가 아니라 기능 고장일 수 있으므로).
- **안전 모드:** `require_admin` 의존성으로 role 확인 → PASS.
- **취약 비교 모드:** "인증된 사용자인지"만 확인하고 role은 확인하지 않음 → 고객도 지급정지 가능 → FAIL.
- **위험도:** HIGH (L3 × I3 — 타인 계좌 거래 중단). 매핑: OWASP API5:2023, CWE-285.
- **수정 방향:** 관리 기능 라우터 전체에 서버 측 역할 검사를 기본값으로 적용(기본 거부).

### SC-06. 요청에 필드 끼워넣기 (BOPLA / Mass Assignment) — v1.2 추가

- **배경:** OWASP API3:2023 Broken Object Property Level Authorization. 서버가 요청 JSON을 그대로 DB에 반영하면, 사용자가 원래 바꿀 수 없는 속성(잔액, 소유자, 상태)까지 바뀐다.
- **요청:** 고객 A 토큰으로 `PATCH /api/accounts/101` 본문 `{"nickname":"생활비","balance_krw":99999999}`. 추가로 `{"nickname":"x","owner_user_id":2}`, `{"nickname":"x","status":"ACTIVE"}` 변형.
- **기대 결과(안전 기준):** `422`, 101 계좌의 `balance_krw`·`owner_user_id`·`status`·`nickname` 모두 불변, 전체 잔액 합 불변.
- **양성 대조:** `{"nickname":"생활비"}`만 보내면 `200`, nickname만 변경. 실패 시 ERROR.
- **안전 모드:** 허용 필드만 정의한 Pydantic 모델(`extra="forbid"`) + 고정된 UPDATE 문(`SET nickname = ?`) → PASS.
- **취약 비교 모드:** 요청 dict의 키를 그대로 컬럼으로 반영(컬럼명은 화이트리스트 없이 사용하되 **SQL 값은 파라미터 바인딩**, 컬럼명은 실제 컬럼 목록과 대조해 SQL 문법 오류만 피함) → 잔액 변경됨 → FAIL.
- **위험도:** HIGH (L3 × I3). 매핑: OWASP API3:2023, CWE-915.
- **수정 방향:** 입력 DTO에 허용 필드만 정의, ORM/DB 갱신은 명시적 필드만.

### 보조 세부 테스트(최소 8~12개 목표)

| ID | 검사 항목 | 안전 모드 기대 결과 |
|---|---|---|
| T01 | 정상 20,000원 송금 | 201, 잔액 총합 보존 |
| T02 | A가 A의 거래내역 조회 | 200 |
| T03 | A가 B의 거래내역 조회 | 403 |
| T04 | 토큰 미제공 | 401 |
| T05 | 잘못된 토큰 | 401 |
| T06 | 음수 금액 | 422, DB 불변 |
| T07 | 0원 송금 | 422, DB 불변 |
| T08 | 잔액보다 큰 송금 | 409, DB 불변 |
| T09 | 동일 요청 2회 | 1회 출금, 동일 거래 ID |
| T10 | 동일 요청 ID·다른 금액 | 409, 추가 출금 없음 |
| T11 | 다른 고객 계좌에서 출금 | 403 |
| T12 | 자기 계좌로 송금 | 400, DB 불변 |
| T13 (선택) | 존재하지 않는 계좌 | 404 |
| T14 (선택) | 거래 전후 잔액 합 보존 | 참 |
| T15 (선택) | 정수가 아닌 금액 `100.5`/`true` | 422 |
| T16 (v1.1) | 서버 내부 예외 발생 시 | 500 본문에 스택트레이스·로컬 경로·SQL 미포함 |
| T17 (v1.1) | A가 B 계좌 조회(403) | `audit_log`에 `ACCESS_DENIED` 1건, 토큰 원문·전체 계좌번호 미저장 |
| T18 (v1.1) | A가 101 외 계좌 3개를 연속 조회(403/404) | `DET-01` 경보 1건 / 2회까지는 경보 없음 |
| T19 (v1.1) | `GET /api/demo/users` | 404 (엔드포인트 미존재) |
| T20 (v1.2) | 운영자 토큰으로 지급정지 / 고객 토큰으로 지급정지 | 200 FROZEN / 403 상태 불변 |
| T21 (v1.2) | 지급정지 계좌에서 송금 | 409, 잔액·기록 불변 |
| T22 (v1.2) | 계좌 별칭 변경(정상 / 타인 계좌 / 잔액 필드 포함) | 200 / 403 / 422 + DB 불변 |

**테스트 작성 규칙:** 각 테스트는 독립된 임시 DB 및 시드 데이터를 사용한다. 데이터베이스 변경·응답 코드·송금 기록 수를 모두 검증한다. 취약 비교 모드와 안전 모드에 동일한 안전성 검사를 적용한다. AssertionError에 의한 기준 위반과 예외로 인한 테스트 ERROR를 혼동하지 않는다.

---

## 8. 정적 코드 분석(SAST) 요구사항

### 8.1 Semgrep을 왜 쓰는가?

소스를 실행하지 않고 위험한 코드 패턴을 찾는다. 예: 동적 문자열 실행, 위험한 셸 호출, TLS 검증 비활성화, 하드코딩된 더미 비밀번호 예제. 은행의 계좌 소유권이나 중복 송금 같은 **업무 규칙 오류는 이 규칙만으로 탐지한다고 주장하지 않는다.**

### 8.2 검사 대상

```text
fixtures/code/
  vulnerable_example.py      # 실제 실행하지 않는 취약 패턴 실습 파일
  fixed_example.py           # 동일 기능의 안전한 수정 예시
rules/
  bankguard.yml              # 최소 4개 로컬 Semgrep 규칙 (v1.1)
```

**v1.1:** 고정된 로컬 대상 3곳을 각각 스캔한다 — `fixtures/code/`, `backend/services/insecure_lab.py`, `backend/`(안전 코드, `insecure_lab.py` 제외 결과도 별도 표기). 대상 목록은 코드에 상수로 고정하고 사용자 입력을 받지 않는다.

파일 이름이 `vulnerable_example.py`라 하더라도 외부 요청이나 셸 실행이 **실제 수행되어서는 안 된다**. 단지 Semgrep에 읽히는 샘플 코드로 두고, 다른 모듈에서 import하지 않는다. 민감한 문자열은 `DEMO_ONLY_NOT_A_REAL_SECRET` 같은 가짜 값으로 한다.

### 8.3 규칙 (v1.1 — 금융 맥락으로 교체)

| 규칙 | 탐지 패턴 | 매핑(원문 확인 후 기입) | 비고 |
|---|---|---|---|
| `BG-SAST-001` | `sqlite3` `execute()`/`executescript()`에 f-string·`%`·`+`·`.format()`으로 조립한 SQL 전달 | CWE-89, "SQL 삽입" | 파라미터 바인딩(`?`)은 미탐지여야 함 |
| `BG-SAST-002` | 금액 관련 이름(`amount`, `balance`, `*_krw`)에 `float(...)` 사용 또는 float 리터럴 대입 | CWE-681 계열(정밀도) — 금융 특화 커스텀 규칙 | 오탐 가능성 README 명시 |
| `BG-SAST-003` | `logging`/`print`에 `token`, `account_no`, `password` 등 민감 이름 변수를 그대로 출력 | CWE-532 | |
| `BG-SAST-004` | `requests.*(..., verify=False)` 또는 하드코딩된 비밀 문자열(`*_SECRET`, `password = "..."`) | CWE-295 / CWE-798 | 가짜 값 `DEMO_ONLY_NOT_A_REAL_SECRET`만 사용 |
| (선택) `BG-SAST-005` | `eval(...)`, `subprocess.*(..., shell=True)` | CWE-95 / CWE-78 | v1.0 규칙 유지 시 |

각 규칙마다 **탐지돼야 하는 샘플과 탐지되면 안 되는 샘플**을 fixtures에 두고 테스트로 확인한다.

이 규칙들이 특정 버전의 Semgrep에서 문법적으로 유효한지 **직접 검증**하고, 안전 샘플에서 의도치 않은 탐지가 발생하는지 확인한다. 단순한 패턴 매칭 결과를 확정된 취약점으로 표현하지 말고 **탐지된 의심 항목(검토 필요)** 이라고 표기한다.

### 8.4 CLI 및 파싱 계약

CLI 예시(설치된 Semgrep 버전에 맞춰 검증):

```powershell
semgrep scan --config rules/bankguard.yml --json fixtures/code
```

- 파이썬에서 `subprocess.run(["semgrep", "scan", "--config", ...], shell=False, ...)`처럼 **리스트 인자**로 실행한다.
- 실행 디렉터리·규칙 파일·대상 폴더를 프로젝트 내부의 **고정된 신뢰 경로**로 제한한다.
- 실행 타임아웃 예: 120초. 실패·미설치·JSON 파싱 오류는 `SCAN_ERROR`, 발견 0건은 `0 findings`로 구분한다.
- Semgrep JSON의 `results` 목록에서 규칙 ID, 파일 경로, 시작 라인, 메시지, severity를 추출한다.
- 임의 사용자 파일 업로드/스캔 기능은 P0 범위에서 제외한다.

### 8.5 화면 표시 예시(가짜 데이터로 하드코딩 금지)

| 룰 | 파일/행 | 위험 설명 | 결과 |
|---|---|---|---|
| BG-SAST-001 | `vulnerable_example.py:12` | `eval`은 안전하지 않은 입력과 함께 쓰이면 위험 | DETECTED |
| BG-SAST-002 | `vulnerable_example.py:20` | `shell=True` 사용 검토 필요 | DETECTED |
| BG-SAST-003 | `fixed_example.py` | TLS 검사 비활성화 패턴 미탐지 | NOT_FOUND |

표의 행 번호는 **UI 디자인 예시**다. 실제 프로그램에서는 Semgrep 응답의 원래 값을 출력한다. 탐지 없음은 '그 규칙에 해당하는 패턴을 찾지 못했다'는 뜻이지 전체 코드의 안전성을 보장하지 않는다.

### 8.6 SAST ↔ 동적 테스트 탐지 범위 비교표 (v1.1, P0)

같은 결함을 두 방법이 각각 잡는지 **실제 실행 결과로** 채운다. 예상값을 미리 써 넣지 않는다.

| 결함 | 위치 | 동적 테스트(SC/T) 결과 | Semgrep 결과 | 해석 |
|---|---|---|---|---|
| BOLA(소유권 검사 누락) | insecure_lab | (실행 결과) | (실행 결과) | |
| 음수/0 금액 허용 | insecure_lab | | | |
| 경쟁 조건(비원자적 차감) | insecure_lab | | | |
| 멱등성 미처리 | insecure_lab | | | |
| BFLA(역할 검사 누락) | insecure_lab | | | |
| Mass Assignment(요청 키 그대로 반영) | insecure_lab | | | |
| SQL 문자열 조립 | fixtures / insecure_lab | | | |
| 금액 float | fixtures | | | |

목적: "정적분석만으로 업무 로직 결함을 보장할 수 없고, 동적 테스트만으로 코드 패턴 결함을 다 찾을 수 없다"를 데이터로 보여 준다. 표는 `artifacts/`의 실행 결과 JSON에서 생성한다.

---

## 9. 공통 검사 결과 데이터 구조

프론트 UI/JSON 내보내기/보고서가 같은 모델을 사용한다.

### API 보안 결과 예

```json
{
  "run_id": "uuid",
  "run_at": "2026-10-27T06:00:00Z",
  "target": "isolated-demo-bank",
  "mode": "secure",
  "total": 4,
  "pass": 4,
  "fail": 0,
  "error": 0,
  "skip": 0,
  "items": [
    {
      "id": "SC-01",
      "name": "타인 거래내역 조회 차단",
      "risk": "HIGH",
      "status": "PASS",
      "expected": "403 및 타인 데이터 비공개",
      "observed": "403, 데이터 비공개 확인",
      "description": "계좌 소유권 검사",
      "fix_guide": "API에서 요청 사용자와 계좌 owner_user_id 비교",
      "evidence": "응답 코드와 격리된 테스트 DB 조회 결과",
      "likelihood": "L3",
      "impact": "I2",
      "owasp": "API1:2023",
      "cwe": "CWE-639",
      "kr_weakness": "부적절한 인가"
    }
  ]
}
```

### 정적 분석 결과 예

```json
{
  "scanner": "semgrep-ce",
  "scan_status": "COMPLETED",
  "target": "fixtures/code",
  "finding_count": 1,
  "findings": [
    {
      "rule_id": "BG-SAST-001",
      "file": "fixtures/code/vulnerable_example.py",
      "line": 12,
      "severity": "WARNING",
      "message": "eval 사용 검토 필요",
      "review_status": "NEEDS_REVIEW"
    }
  ]
}
```

**정의:** `risk`는 BankGuard 내부 학습용 정성 등급이며 CVSS 인증 점수가 아니다. 검사 실패·도구 실패·탐지 0건을 모두 다른 상태로 유지한다. 결과 파일에 외부 실제 고객정보를 기록하지 않는다.

---

## 10. Streamlit UI 설계

### 권장 레이아웃(1개 앱, 4개 탭)

```text
┌──────────────────────────────────────────────────────────────┐
│  BANKGUARD  |  BANK API SECURITY LAB                       │
│  '가상 은행 API의 취약점을 자동 검증합니다'                    │
├──────────────────────────────────────────────────────────────┤
│ [개요] [API 보안 테스트] [정적 코드 분석] [개선 비교·보고서]    │
├──────────────────────────────────────────────────────────────┤
│  (요약 카드)       검사 12개  통과 10  실패 2  오류 0         │
│  [API 보안 테스트 실행]    [Semgrep 분석 실행]              │
│                                                              │
│  SC-01 타인 조회        FAIL   HIGH                         │
│      기대: 403 / 관측: 200 / 해결: 계좌 소유권 검증         │
│  SC-02 잘못된 금액      PASS   HIGH                         │
│                                                              │
│  [취약 버전]  →  [수정 버전]    전후 비교                    │
└──────────────────────────────────────────────────────────────┘
```

화면에 적힌 숫자는 구성 예시이며 실제 코드는 검사 결과를 연결해야 한다.

### 10.1 탭 ① 프로젝트 소개 / 개요

- 프로젝트 목적 2~3문장
- 은행 IT 보안 직무와의 연결 설명
- 가상 사용자 3명 및 더미 계좌 상태 보기(안전 서버만 조회)
- 테스트 범위 경고: 로컬 전용 / 실제 금융 서비스 아님
- 최근 실행의 전체 건수, PASS, FAIL, ERROR 요약 (미실행이면 **미실행** 표시)

### 10.2 탭 ② API 보안 테스트

- 모드 선택: `취약 버전(격리 실습)` / `안전 버전(수정 후)`
- 버튼: `보안 시나리오 실행`
- 4개 핵심 시나리오 결과 카드 또는 표
- 항목 펼치기: 목적, 사용한 테스트 요청(민감하지 않은 더미 데이터), 예상/실제 동작, 위험, 해결 방법
- 실행 중 스피너·오류 메시지 처리
- 취약 버전 검사라도 인터넷으로 취약 서버를 열지 말고 인프로세스 테스트로만 실행

### 10.3 탭 ③ 정적 분석

- 버튼: `Semgrep 정적 분석 실행`
- 대상 폴더와 룰 개수 표시
- 발견 건수, 파일명, 라인, 룰 ID, 위험 설명
- `vulnerable_example.py` 와 `fixed_example.py` 비교
- Semgrep 미설치 시 '미설치'라고 안내하고 설치 명령 제공. 가짜 분석 결과 표시 금지.

### 10.4 탭 ④ 수정 전후 비교 / 보고서

- 동일 시나리오에 대한 취약 모드·안전 모드 결과 나란히 보기
- 개선 여부: `FAIL → PASS` (실제 양쪽 실행 결과가 존재할 때만)
- 실행 환경, 검사시각, 개별 결과, 제한사항 정리
- Markdown/JSON 결과 내보내기는 쉬우면 구현; PDF는 선택
- '모든 취약점 제거' 대신 '정의된 검사 범위 내 개선 확인'이라고 표현

### UX 세부 조건

- 날짜/시간 한국어 표시; 금액은 쉼표 및 `원` 붙여 표시.
- FAIL은 보안 조건 미충족, ERROR는 검사 불능임을 도움말로 설명.
- 초기 결과 없는 경우 표에 임의 PASS/FAIL 예시를 넣지 않는다. **아직 검사를 실행하지 않았습니다**라고 표시한다.
- CSS 작업은 최소한. Streamlit 기본 컴포넌트 우선.

---

## 11. 파일 및 폴더 구조 (제안)

```text
bankguard/
├─ README.md
├─ CLAUDE.md                   # 작업 규칙: 이 문서를 참조
├─ requirements.txt
├─ .gitignore
├─ backend/
│  ├─ __init__.py
│  ├─ main.py                   # 안전 모드만 공개하는 FastAPI 진입점
│  ├─ factory.py                # create_app; 검사 전용 취약 모드 격리
│  ├─ config.py
│  ├─ db.py                     # 연결, 스키마, 트랜잭션
│  ├─ seed.py                   # (v1.1) 더미 사용자·계좌 상수 + 시드 함수 (대시보드도 import)
│  ├─ audit.py                  # (v1.1) 감사 로그 기록·마스킹
│  ├─ detection.py              # (v1.1) DET-01 계좌 열거 의심 탐지
│  ├─ schemas.py                # Pydantic 입력/출력
│  ├─ auth_demo.py              # 토큰→더미 사용자 변환
│  ├─ repository.py
│  └─ services/
│     ├─ transfers.py          # 안전한 송금 구현
│     └─ insecure_lab.py       # 외부 라우터로 노출 금지, 테스트 전용
├─ frontend/
│  ├─ __init__.py
│  └─ app.py                    # Streamlit 앱
├─ scanners/
│  ├─ __init__.py
│  ├─ api_runner.py             # 고정 시나리오 실행
│  ├─ sast_runner.py            # Semgrep CLI 호출/파싱
│  └─ models.py                 # 검사 결과 타입
├─ rules/
│  └─ bankguard.yml
├─ fixtures/
│  └─ code/
│     ├─ vulnerable_example.py
│     └─ fixed_example.py
├─ tests/
│  ├─ conftest.py               # 임시 DB fixture, TestClient
│  ├─ test_api_contract.py
│  ├─ test_security_scenarios.py
│  ├─ test_transfer_invariants.py
│  ├─ test_runner.py
│  └─ test_semgrep_integration.py
├─ artifacts/                   # 실제 실행에서 생성되며 gitignore 대상
│  └─ .gitkeep
├─ docs/
│  ├─ architecture.md
│  ├─ threat_model.md           # (v1.1) 데이터 흐름 + STRIDE 1페이지
│  ├─ test_matrix.md
│  ├─ coverage_matrix.md        # (v1.1) SAST ↔ 동적 테스트 비교표 (실행 결과에서 생성)
│  ├─ demo_script.md
│  └─ limitations.md
├─ scanners/report.py           # (v1.1) 실무형 진단 보고서 Markdown 생성
├─ requirements-sast.txt        # (v1.1) Semgrep 전용 (별도 가상환경)
└─ .github/
   └─ workflows/
      └─ security-check.yml    # (v1.1 P0) pytest + Semgrep 보안 게이트
```

**폴더가 많아 구현이 느려지면** `repository.py`나 `config.py` 등은 합쳐도 된다. 다만 `backend`/`scanners`/`frontend`/`tests`/`fixtures`의 관심사 분리는 지킨다.

---

## 12. 검사 구현 전략 — 형식적인 시연이 되지 않도록

### API 실행 기반 검사 설계

- `backend.factory.create_app(mode="secure", db_path=...)`로 안전 앱을 구성.
- `backend.factory.create_app(mode="vulnerable", db_path=...)`는 **별도의 격리 테스트 코드에서만** 구성하도록 하고, `backend.main`은 호출하지 않는다.
- `scanners/api_runner.py`는 고정된 `SC-01~SC-04`를 실행한다.
- 각 시나리오는 독립된 임시 DB를 초기화하고 `TestClient`로 실제 FastAPI 라우트를 호출한다.
- 시나리오 정의에는 `scenario_id`, `title`, `expected_secure_behavior`, `risk`, `fix_guide`, `execute(client, db)`에 해당하는 구조를 사용한다.
- 단순히 어떤 모드를 선택했는지 보고 `PASS` 또는 `FAIL`을 반환하지 않는다. 응답 코드·본문·DB 상태에 대해 실제로 검증한다.
- `pytest tests/ -q`는 정상 API 계약, 시나리오 평가기, DB 원자성, SAST 파서를 검증한다. 취약 비교 코드가 안전성 기준에 실패하는 것 자체는 **시연의 정상 기대치**이며, '전체 CI 테스트 실패'로 오인하지 않도록 `tests`의 검증 기준을 분리한다. 예를 들어 `test_runner.py`에서 취약 모드의 결과가 `FAIL`, 안전 모드가 `PASS`임을 assert 한다.
- pytest 실패/성공 건수와 대시보드의 보안 결과 건수는 동일한 개념이 아님을 문서화한다.

### 중요 보안/견고성 규칙

- 가능한 한 `X-Demo-Token`을 API 의존성으로 공통 검증한다.
- UI가 표시한 사용자 ID를 신뢰하지 말고 서버에서 토큰에 연결된 user_id로 소유권을 검증한다.
- 요청 금액은 `StrictInt` 또는 `Field(strict=True, gt=0, le=10_000_000)` 수준으로 강제하고, bool도 제외한다.
- UUID 필드와 idempotency 충돌은 일관되게 처리한다.
- SQL 쿼리는 **파라미터 바인딩(`?`)** 사용. 문자열로 사용자 입력을 SQL에 결합하지 않는다.
- 계좌 갱신은 한 트랜잭션에서만 수행하고, 실패 시 rollback.
- 결과 표시용으로 subprocess 사용 시 `shell=True` 금지, 파일 경로 제한, 타임아웃 설정.
- 예외 발생 시 민감한 로컬 경로나 상세 스택을 UI에 무분별하게 노출하지 않는다. 개발 콘솔에는 디버깅 가능한 로그를 남긴다.
- 실습용 취약 코드에는 실행 경로와 사용 범위를 명확히 주석으로 표시한다.

---

## 13. 8개 개발일 계획 — 일별 작업 순서와 통과 기준

### DAY 1 — 개발 환경, 프로젝트 골격, API 헬스체크

**목표:** 빈 폴더에서 실행 가능한 FastAPI + Streamlit + Git 저장소.

1. Python 3.11/3.12, pip, git, `semgrep --version` 확인.
2. 가상환경 `.venv` 생성, 의존성 설치, `.gitignore` 작성.
3. 프로젝트 폴더 구조 및 README 초안.
4. `GET /health` 구현, `http://127.0.0.1:8000/docs` 접근 확인.
5. Streamlit 첫 화면에 프로젝트 한 줄 설명 표시.
6. `python -m pytest -q`의 최소 스모크 테스트 성공.

**완료 조건:** 터미널 두 개에서 API 및 대시보드가 각각 켜지고 헬스체크가 200 응답을 준다.

**DAY 1 실제 결과(2026-10-27):** Linux VM(Ubuntu 22.04, Python 3.12.15)에서 pytest 9 passed, uvicorn `/health`·`/docs` 200, Streamlit 200, semgrep 1.182.1 확인. Windows PowerShell 실행과 git 초기화는 미완료(사용자 PC에서 진행).

### DAY 2 — 가상 은행과 정상 송금 API (+ 감사 로그 기반)

1. SQLite 스키마(`users`/`accounts`/`transfers`/`audit_log`) 및 시드(A/B/C), `backend/seed.py`에 시드 상수.
2. `X-Demo-Token` 처리(공통 의존성)와 사용자 계좌 조회.
3. 거래 내역 조회 시 소유권 검증(403/404/401).
4. 안전 송금 API: 금액 검사(StrictInt, 1~10,000,000), 자기 계좌 400, 잔액 검증·차감 원자화(조건부 UPDATE 또는 BEGIN IMMEDIATE), 중복 요청 제어(request_id + payload_fingerprint).
5. 인증 실패·권한 거부·송금 결과를 `audit_log`에 기록(마스킹).
6. 정상 송금·중복 요청·T12·T17·T19 테스트부터 구현.

**완료 조건:** A가 B에게 20,000원 송금 후 잔액이 980,000원/520,000원이 되고 동일 요청 재전송 시 잔액이 그대로이다. 403 시도가 감사 로그에 남는다.

### DAY 3 — 핵심 보안 검사 ① 권한 (객체·기능·속성) — v1.2 재구성

1. v1.2 스키마/시드 추가(role, status, nickname, 운영자 계정) + 지급정지 API(6.6), 별칭 변경 API(6.7), 지급정지 계좌 출금 409.
2. `secure`/`vulnerable` 격리 모드 설계 및 검증(취약 모드는 TestClient + 임시 DB 전용).
3. SC-01 BOLA, SC-05 BFLA, SC-06 Mass Assignment 시나리오 구현(양성 대조 포함).
4. T06·T07(0원·음수), T20~T22 세부 테스트.
5. 각 모드의 실제 응답/DB 상태를 `PASS/FAIL/ERROR`로 평가.

**완료 조건:** SC-01, SC-05, SC-06에서 격리 취약 모드는 FAIL, 안전 모드는 PASS를 실제 검사로 보여준다. 양성 대조가 깨지면 ERROR로 표시된다.

### DAY 4 — 핵심 보안 검사 ② 잔액 / 멱등성

1. SC-03 동시 송금 경쟁 조건(취약: 비원자적 검사-차감 / 안전: 조건부 UPDATE 또는 BEGIN IMMEDIATE), T08 단순 잔액 초과.
2. SC-04 동일 송금 요청 중복 검증 및 ID 충돌 검사.
3. `tests/test_transfer_invariants.py`에 잔액 보존·기록 1건·실패 시 DB 불변 테스트.
4. 전체 5종 핵심 시나리오(SC-01·03·04·05·06)를 공통 구조로 실행. SC-03은 20회 반복해도 결과가 같은지 확인.

**완료 조건:** 5종 모두 실제 비교 가능. 테스트 재실행 결과가 데이터 초기화나 스레드 타이밍 때문에 달라지지 않는다.

### DAY 5 — Semgrep 연동과 로컬 규칙

1. Semgrep 설치/버전 확인(별도 가상환경).
2. 8.3의 금융 맥락 규칙별 '탐지돼야 함 / 탐지되면 안 됨' 샘플 작성.
3. `rules/bankguard.yml` 작성 후 규칙 검증. 대상: fixtures, insecure_lab.py, backend(안전 코드).
4. CLI JSON을 읽고 정규화하는 `sast_runner.py` 구현.
5. 탐지 건수·파일·라인·룰 ID가 실제 출력과 일치하는지 확인.
6. 오류/미설치/탐지 없음 경계 조건 구현.

**완료 조건:** 취약 샘플에서는 의도한 탐지가 나오고 수정 샘플에서는 해당 패턴이 줄거나 사라진다. UI 데이터는 실제 Semgrep JSON에서 유래한다.

### DAY 6 — Streamlit 대시보드

1. 4개 탭과 기본 카드 UI 구현.
2. 버튼 클릭 시 API 시나리오 검사 실행 및 표 표시.
3. SAST 실행·결과 표 연동.
4. 검사 전 '미실행'·검사 중 진행 상태·실패 시 ERROR 메시지 구분.
5. 위험도 표시, 상세 설명 펼치기, 원화 표시.
6. `docs/threat_model.md` 작성(데이터 흐름 + STRIDE 표, 코드 없음).

**완료 조건:** 다른 파일/터미널을 열지 않아도 대시보드에서 검사 시작 → 결과를 확인할 수 있다.

### DAY 7 — 수정 전후 비교, 탐지, 보고서, CI 게이트

1. 핵심 5종(SC-01·03·04·05·06)을 취약·안전 모드로 각각 실행하여 결과 비교.
2. `FAIL→PASS` 건수 계산. 결과 없거나 ERROR면 개선 성공으로 집계하지 않는다.
3. `DET-01` 계좌 열거 탐지 규칙 + T18, 대시보드에 경보 표시.
4. SAST ↔ 동적 테스트 비교표(8.6)를 실행 결과에서 생성.
5. 실무형 진단 보고서 Markdown 생성(`scanners/report.py`): 점검항목/위험도(L×I)/취약여부/근거/조치권고/이행점검 결과/매핑.
6. CI 보안 게이트(`.github/workflows/security-check.yml`): pytest + Semgrep, 안전 코드(`backend/`, insecure_lab 제외)에서 신규 탐지 시 실패.
7. 주요 에러/설치 미비/DB 잠김 상황을 점검.

**완료 조건:** 한 번의 시연에서 문제 재현, 원인 표시, 수정 버전 재검증, 탐지 경보, 보고서 생성이 자연스럽게 이어진다.

### DAY 8 — 안정화, 문서, 발표 시연

1. 빈 환경에서 `requirements.txt` 설치 → API/UI 실행 재현.
2. `pytest` 전체 수행 및 결과 기록, Semgrep 실제 스캔 수행.
3. 주요 기능 화면 캡처(가능한 경우), 깔끔한 README 작성.
4. `docs/demo_script.md`에 3분/5분 발표 대본 및 클릭 순서.
5. `docs/limitations.md`에 실습 한계·보안 도구 오탐/미탐·실서비스 비적합성 명시.
6. 마감 전 작동하는 버전 커밋.

**완료 조건:** 타인이 README대로 설치해 실행하고, 시나리오 및 정적 분석 결과를 반복 확인할 수 있다.

### 개발 일정이 밀릴 때

- **DAY 4 종료 시** 핵심 4종이 동작하지 않으면 UI 작업 중단, 테스트부터 완성.
- **DAY 5 종료 시** Semgrep 설치 실패면 Windows 설치 원인 파악 → WSL/도커로 대체. 수동 하드코딩으로 넘어가지 말 것.
- **DAY 7까지** P0가 불안정하면 PDF/고급 CSS/위협 모델링 분량을 줄인다. CI 게이트는 pytest만이라도 유지한다.

---

## 14. 수용 기준(Acceptance Criteria)

아래를 **모두 만족해야 P0 완료**라고 판단한다.

### 환경·실행

- [ ] `python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000` 실행 가능
- [ ] `python -m streamlit run frontend/app.py` 실행 가능
- [ ] `/health` 200, Swagger `/docs` 접근 가능
- [ ] 외부 API 키나 인터넷 계좌 접근 없이 로컬에서 완전 시연 가능

### 보안 로직

- [ ] 타인 거래 조회는 403, 타인 정보 미노출
- [ ] 음수/0/비정수 송금은 거절, DB 불변
- [ ] 잔액 초과는 거절, DB 불변
- [ ] 동시 송금 2건에서 잔액 이상 출금 없음(안전 모드), 취약 모드에서는 위반 재현, 20회 반복 결과 동일
- [ ] 401/403/송금 결과가 감사 로그에 마스킹되어 기록, DET-01 경보가 실제 로그에서 생성
- [ ] `GET /api/demo/users` 미존재, 500 응답에 내부 정보 미노출
- [ ] (v1.2) 고객 토큰의 관리자 API 호출은 403·상태 불변, 운영자 토큰은 200
- [ ] (v1.2) 계좌 별칭 변경 요청에 다른 필드가 섞이면 422·DB 불변, 지급정지 계좌 출금은 409
- [ ] 정상 송금은 출금·입금·기록이 하나의 원자적 단위로 처리
- [ ] 동일 요청 재시도는 한 번만 출금
- [ ] 동일 request_id에 다른 데이터는 409
- [ ] API 검사에서 취약과 안전 버전 차이가 실제로 확인됨
- [ ] 취약 모드는 공개 서버로 노출되지 않음

### 검사 엔진

- [ ] API 검사 결과는 실제 HTTP 응답과 DB로 판정
- [ ] Semgrep 설치/실행이 실제로 수행됨
- [ ] 금융 맥락 로컬 룰 4개 이상 검증됨(탐지/미탐지 샘플 모두)
- [ ] SAST ↔ 동적 테스트 비교표가 실제 실행 결과로 생성됨
- [ ] GitHub Actions 보안 게이트가 실제로 1회 이상 실행됨(성공 및 의도적 실패 확인)
- [ ] Semgrep 탐지 위치·룰 ID·메시지가 JSON에서 파싱됨
- [ ] 0건 탐지와 도구 오류를 구분
- [ ] 테스트 결과가 실행 전에는 미실행으로 표시됨

### 문서·시연

- [ ] README: 소개/구조/설치/실행/검증/한계
- [ ] 테스트 매트릭스: 시나리오별 요청·기대·실제·근거
- [ ] 실무형 진단 보고서(Markdown), `docs/threat_model.md`
- [ ] README에 'AI 활용 내역 / 본인이 설계·검증·수정한 부분' 구분 섹션, '향후 확장' 2~3줄
- [ ] 3분 시연 순서 및 스크린샷(가능 시)
- [ ] 정확한 실행 결과와 미완성 사항 명시

---

## 15. 오류 상황 및 대응 요구

| 상황 | 화면 또는 실행에서 취할 행동 |
|---|---|
| FastAPI 서버 미실행 | 앱 소개는 보여주고, API 연결 오류 및 시작 명령 안내 |
| Semgrep 미설치 | '정적 분석 실행 불가' + 설치 안내, 결과 0건으로 위장하지 않음 |
| Semgrep 룰 YAML 오류 | `SCAN_ERROR` 및 개발 콘솔에 상세 오류 |
| pytest/시나리오 단언 실패 | 해당 보안 항목 `FAIL` 또는 검사 무결성 오류를 명확하게 분류 |
| DB 파일 잠김 | 재시도/타임아웃/트랜잭션 개선, 오류를 숨기지 않음 |
| 임시 DB 생성 실패 | `ERROR` 기록, 이전 검사 PASS 재사용 금지 |
| 사용자 계좌/토큰 오류 | 규정한 HTTP 상태 코드로 응답 |
| 검사 버튼 중복 클릭 | 중복 실행 방지 및 진행 상태 명시 |
| 검사 결과 파싱 실패 | 사용자에게 검사 불가를 알리고 로그 확인 안내 |

---

## 16. 로컬 실행 명령(Windows PowerShell 우선)

프로젝트 루트에서 실행:

```powershell
# 1) 환경 확인
python --version
git --version

# 2) 가상환경
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3) 필요한 패키지 설치
python -m pip install --upgrade pip
python -m pip install -r requirements.txt

# 4) 별도 터미널 A: API 실행
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

# 5) 별도 터미널 B: 웹 대시보드 실행
python -m streamlit run frontend/app.py

# 6) 자동 테스트
python -m pytest tests -q

# 7) 정적 분석 (Semgrep 설치 후)
semgrep --version
semgrep scan --config rules/bankguard.yml --json fixtures/code
```

PowerShell 스크립트 정책으로 가상환경 활성화가 제한되면 사용자 PC 정책을 임의로 광범위 변경하지 말고 `\.venv\Scripts\python.exe`를 직접 호출하는 경로를 안내한다. Git Bash나 WSL에서는 활성화 명령/경로가 다르므로 OS별 명령을 README에 분리한다. Windows의 `py -3.12` 등은 실제 설치 인터프리터 목록을 확인한 후 사용할 것.

**주의:** `requirements.txt`는 Claude가 실제 코드에 맞춰 생성한다. 따라서 문서의 설치 명령은 *구현 후* 실행 가능한 형태로 보장해야 한다.

---

## 17. README.md에 반드시 포함할 내용

1. 스크린샷/짧은 소개: 무엇을 만들었나?
2. 은행 IT 보안 직무 연계: API 검사 / SAST / 보안 시나리오 설계
3. 정상 vs 비교용 취약 모드 차이 및 격리 방식
4. 설치 전 준비(Python, Semgrep, Git)
5. 실행 명령과 화면 접근 주소
6. API 목록 및 요청 예시(더미 데이터)
7. 보안 테스트 시나리오와 결과 해석(PASS/FAIL/ERROR)
8. 정적 분석 규칙과 탐지 결과, 오탐·미탐 가능성
9. 검증 결과(`pytest`, Semgrep 버전·명령·실행일)
10. 핵심 구현 의사결정(트랜잭션, 멱등성, 소유권, 입력검증)
11. 제한사항(실제 인증 아님, 금융 서비스 운영 불가, 전체 보안성 보장 안 됨)
12. 프로젝트 기간/개인 담당 범위/개발 과정에서 해결한 문제
13. (v1.1) AI 활용 내역과 본인이 직접 설계·검증·수정한 부분의 구분
14. (v1.1) SAST ↔ 동적 테스트 비교표, 감사 로그·DET-01 탐지 설명
15. (v1.1) 향후 확장 2~3줄(미구현임을 명시)

---

## 18. 포트폴리오 및 발표 관점 체크포인트

### 발표에서 반드시 보여줄 데모 흐름(3~5분)

1. **문제 정의(30초):** 은행 송금 API의 접근제어·거래 무결성 결함은 중요한 위험이다.
2. **실습 환경(30초):** 가상 고객 3명·로컬 테스트 전용, 실제 금융 데이터 없음.
3. **취약 비교 모드 검사(60초):** 4개 항목 중 FAIL 사례를 실제 실행해 보여준다.
4. **수정된 안전 모드 검사(60초):** 동일 시나리오가 PASS로 바뀌고 DB 잔액/거래 건수가 올바름을 설명한다.
5. **정적 코드 분석(40초):** Semgrep 룰/파일/행 출력 및 수정 샘플 비교.
6. **의미와 한계(20초):** AppSec 업무 흐름을 재현했고, 정적 분석만으로 업무 로직 전체를 보장할 수 없음을 설명한다.

### 면접 예상 질문과 대답의 핵심

- **왜 BankGuard를 만들었나요?** → 금융 거래 API의 안전 조건을 직접 정의하고 자동 검증하기 위해.
- **왜 정적 분석과 API 테스트를 같이 쓰나요?** → 코드 패턴과 런타임 비즈니스 로직의 탐지 범위가 다르기 때문.
- **BOLA가 무엇인가요?** → 사용자가 다른 사람의 객체 ID를 넣었을 때 서버가 소유권을 검증하지 않는 결함.
- **송금에서 중요한 설계는?** → 금액·권한 검사, 원자성, 잔액 보존, 중복 요청 멱등성.
- **AI로 코딩했다면 본인의 역할은?** → 보안 시나리오와 수용 기준 정의, 검사 설계, 결과 검증, 버그 분석.
- **한계는?** → 실제 은행 인증/규제/운영환경과 다르며 정의된 테스트 및 SAST 룰 범위만 검증.

---

## 19. Claude에 매 개발일 제공할 단계별 프롬프트

아래 프롬프트를 하나씩 주면 범위가 통제되고 오류 추적이 쉽다. 이전 단계가 검증된 후 다음을 진행한다.

### 시작 프롬프트 (처음 한 번)

```text
첨부한 BANKGUARD_CLAUDE_MASTER_SPEC.md를 이 프로젝트의 최상위 요구사항으로 읽어 줘.
우리는 Windows 환경에서 10일(실제 8일) 동안 1인 바이브 코딩으로 BankGuard를 완성할 거야.
프로젝트의 목표는 은행 API 보안 테스트 + Semgrep 정적 분석 + Streamlit 대시보드야.
우선 P0만 구현하고, 실습용 취약 코드는 외부에 공개되지 않는 TestClient 환경에서만 실행되도록 해.
지금은 DAY 1만 진행해. 실제 프로젝트 파일을 생성하고 실행/테스트 명령을 제공해.
코드를 작성하거나 수정할 때마다 파일 목록, 변경 요약, 실제 검증 여부를 알려 줘.
내가 다음 단계라고 하기 전에 무리하게 DAY 2~8까지 한 번에 작성하지 마.
```

### DAY 2 프롬프트

```text
명세서 5~6장과 DAY 2를 기준으로 안전 모드 은행 API를 구현해.
더미 계좌 3개, 서버 측 소유권 검증, 금액은 원 단위 정수, SQLite 트랜잭션,
request_id 멱등성을 구현하고, 정상 송금·잔액 검증·중복 재요청 테스트를 작성해.
실제 테스트 결과와 DB 값까지 확인해 줘.
```

### DAY 3~4 프롬프트

```text
명세서 7장/12장을 기준으로 SC-01~SC-04 실행 기반 보안 검사기를 구현해.
취약 버전은 외부 API가 아닌 격리된 TestClient에서만 생성해.
각 시나리오는 임시 DB로 초기화하고 HTTP 응답+DB 상태로 판정해.
취약 버전 FAIL / 안전 버전 PASS가 실제로 재현되는지 증거를 남겨 줘.
테스트 오류(ERROR)와 보안 위반(FAIL)을 혼동하지 마.
```

### DAY 5 프롬프트

```text
명세서 8장을 기준으로 Semgrep CE를 연동해.
로컬 YAML 규칙 3개 이상과 취약/안전 샘플을 만들고 실제 CLI JSON 결과를 파싱해.
탐지 파일·라인·규칙·메시지를 보여 주고, 도구 미설치/실행 오류는 SCAN_ERROR로 처리해.
결과를 하드코딩하지 말고, Semgrep 명령과 실제 출력 요약을 보여 줘.
```

### DAY 6~7 프롬프트

```text
명세서 9~10장을 기준으로 Streamlit 4개 탭을 구현하고 기존 검사기를 연결해.
사용자가 버튼을 눌러 API 테스트와 Semgrep을 실행하고 PASS/FAIL/ERROR 및
위험 원인, 수정 가이드, 취약/안전 모드 비교를 볼 수 있어야 해.
실제 데이터와 화면만 연결하고 필요 이상의 UI 라이브러리는 추가하지 마.
```

### DAY 8 프롬프트

```text
BankGuard 최종 품질점검을 해 줘. 핵심 기능을 삭제하거나 가짜 결과로 대체하지 말고
빈 환경 설치 방법, 전체 pytest, Semgrep 로컬 스캔, 버튼별 동작을 점검해.
README, docs/demo_script.md, docs/limitations.md를 완성해.
실행하지 못한 검증은 명확히 표시하고 미해결 문제를 우선순위별로 정리해.
최종 발표용 3분 시연 순서를 알려 줘.
```

### 공통 디버깅 프롬프트

```text
지금 나타난 오류를 재현하고 원인을 먼저 분석해 줘.
수정할 파일과 수정 이유를 설명한 다음 최소 변경으로 해결해.
기존에 통과하던 테스트가 깨지지 않는지 다시 확인해.
명세서의 P0 범위에서 벗어나는 새 기능을 추가하지 마.
```

---

## 20. 마지막 작업 보고 형식 (Claude 응답 표준)

각 작업일 종료 시 아래 형식으로 보고한다.

```markdown
## DAY N 결과
- 완료한 기능:
- 생성/수정한 파일:
- 실제 실행한 명령:
- 테스트 결과: (성공 N / 실패 N / 미실행, 사실에 근거)
- 실행 캡처 또는 출력 증거:
- 남은 오류/제약:
- 다음 작업 3가지:
- P0 진행률: (완료 조건에 근거하여 설명; 임의 퍼센트 금지)
```

변경 내역과 검증 결과를 과장하지 말고, 사용자가 이해할 수 있도록 용어를 간결하게 설명한다.

---

## 21. 공식 참고 자료 (개발 중 확인용)

- OWASP API Security Top 10 (API1:2023 BOLA 등): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP API Security Project: https://owasp.org/www-project-api-security/
- OWASP Developer Guide — Semgrep: https://devguide.owasp.org/en/05-implementation/05-static-analysis/01-semgrep/
- Semgrep CE 제품/플랫폼별 설치: https://semgrep.dev/products/community-edition/
- Semgrep 로컬 CLI 문서: https://semgrep.dev/docs/category/local-and-cli-scans/
- Semgrep 규칙 작성: https://semgrep.dev/docs/writing-rules/overview/
- FastAPI 테스트: https://fastapi.tiangolo.com/tutorial/testing/
- FastAPI 테스트 의존성 교체: https://fastapi.tiangolo.com/advanced/testing-dependencies/
- pytest JUnit 보고서: https://docs.pytest.org/en/stable/how-to/output.html
- Streamlit 공식 문서: https://docs.streamlit.io/

> **핵심:** 이 프로젝트는 실제 은행 해킹 도구가 아니라, **로컬 가상 은행 API의 안전성 검증을 재현하는 학습·포트폴리오용 AppSec 프로젝트**이다. 최종 성과는 화려한 화면이 아니라 재현 가능한 테스트와 정직한 진단 근거로 증명한다.
