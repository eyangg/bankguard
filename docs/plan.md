# BankGuard 개발 계획 (PLAN) — v2.0

> 기준 문서: `BANKGUARD_CLAUDE_MASTER_SPEC.md` v2.0 장(V0~V9). 이 문서와 명세가 충돌하면 명세가 우선입니다.
> 수업 문서 흐름: MVP → PRD → SPEC → **PLAN**(이 문서)

## 1. 계획의 목적

이 문서는 BankGuard를 **어떤 순서로 개발할지** 정한 순서표입니다.
v1.x 계획(DAY 1~8)은 10/28~10/29 오전에 끝났고, 남은 기간(10/30 ~ 11/6 오전)에는 수업 필수 스택(**FastAPI · React · TypeScript · Supabase**)으로 옮기면서 보안 기능을 넓힙니다.

## 2. 개발 원칙

- 한 번의 요청에서는 **Phase 하나**만 진행합니다. Phase 안에서도 결과를 확인할 수 있는 작은 작업으로 나눕니다.
- Phase를 시작하기 전에 AI는 **사람이 해야 할 일, 필요한 값, 결정할 내용**을 먼저 알려줍니다.
- Phase가 끝나면 다음 세 가지를 해야 다음 Phase로 넘어갑니다.
  1. 자동 테스트 통과(실제 실행 결과로 보고, 실행하지 못한 것은 "미검증")
  2. **사람이 직접 화면·결과 확인**
  3. `docs/learning_log.md`에 내가 이해한 내용 3줄 작성 → 그다음 커밋·푸시
- 명세에 없는 기능은 추가하지 않습니다. 확장(X1~X4)은 Phase E가 끝난 뒤에만 합니다.
- 비밀값(DB 접속 정보, 암호화 키, 시연 비밀번호)은 `.env`에만 둡니다. 화면 코드와 `VITE_*` 변수에는 절대 두지 않습니다.
- 브라우저는 Supabase에 직접 접속하지 않습니다. DB는 FastAPI만 접근합니다.
- 화면 코드는 TypeScript(`.ts`/`.tsx`)로만 작성합니다.

## 3. 프로젝트 구조 (v2.0 목표)

```text
bankguard/
├─ backend/            # FastAPI (안전 모드 공개 진입점, 인증, 송금, 감사 로그, 탐지)
│  └─ services/        # 송금, 취약 비교 구현(insecure_lab — 테스트 전용)
├─ frontend/           # Vite + React + TypeScript (Streamlit은 Phase D에서 제거)
├─ database/
│  └─ migrations/      # 0001_*.sql … (테이블, RLS, 권한 회수)
├─ scanners/           # 시나리오·SAST·SCA·탐지 실행기, 보고서 (CLI·CI 전용)
├─ rules/              # Semgrep 규칙
├─ fixtures/code/      # 정적 분석 샘플
├─ tests/              # pytest (기본: 임시 SQLite / -m postgres: 테스트용 Supabase)
├─ artifacts/          # 실행 결과 JSON·보고서 (git 제외)
├─ docs/               # mvp.md, prd.md, spec.md, plan.md, learning_log.md, 기타 문서
└─ .github/workflows/  # CI 보안 게이트
```

## 4. 전체 개발 순서

| Phase | 만드는 결과 | 예상 시간 | 사람이 할 일 | 넘어가기 위한 핵심 조건 |
|---|---|---|---|---|
| A | 진행 중 작업 마무리 + 수업 산출물 문서 | 0.5~1시간 | 문서 읽고 확인 | SC-07·SCA 테스트 통과·커밋, docs 4종 존재 |
| B | Supabase PostgreSQL 전환 + SC-08 + PostgreSQL 경쟁 조건 | 2~3시간 | **Supabase 프로젝트 2개 생성, `.env` 입력** | 시연 DB에 데이터 저장, SC-08 PASS, `-m postgres` 실행 |
| C | 진짜 로그인 + 송금 OTP + SC-09 | 2~3시간 | OTP 앱으로 직접 송금해 보기 | 기존 시나리오 회귀 PASS, SC-09 FAIL→PASS |
| D | Figma 화면 → React + TypeScript | 5~7시간 | **Figma로 화면 그리기**, 브라우저 확인 | `npm run build` 성공, 화면에서 로그인→송금→내역 |
| E | 통합·CI·README·발표 준비 | 1~2시간 | 시연 리허설 | v2.0 완료 기준(명세 V8) 전부 체크 |
| X1~X4 | 확장 (남는 시간에 순서대로) | 각 1~3시간 | 결과 확인 | 각 항목 완료 조건 |

## 5. Phase별 상세 계획

### Phase A. 진행 중 작업 마무리 + 수업 산출물

**목표:** 미커밋 작업을 정리하고, 수업 형식 문서를 만든다.

**작업**
1. 진행 중인 SC-07(`backend/throttle.py`, `tests/test_auth_throttle.py`)과 SCA(`scanners/sca_runner.py`, `requirements-sca.txt`, `tests/test_sca_runner.py`)를 마무리하고 전체 pytest를 실행한다.
2. 마스터 명세에서 쉬운 말로 뽑아 `docs/mvp.md`, `docs/prd.md`, `docs/spec.md`를 만든다(새 기능 추가 금지, v2.0 기준 반영).
3. `docs/learning_log.md`를 만들고 형식(날짜 / Phase / 이해한 것 3줄 / 아직 모르는 것)을 정한다.

**사람이 할 일:** 세 문서를 읽고 틀린 내용 표시.

**완료 조건:** pytest 전체 통과, 문서 4종(mvp·prd·spec·plan) 존재.

**커밋 예:** `Phase A: SC-07 로그인 시도 제한·SCA 점검 마무리, 수업 산출물 문서(mvp·prd·spec·plan)`

### Phase B. Supabase PostgreSQL 전환

**목표:** 운영(시연) 데이터를 Supabase에 저장하고, DB 직접 접근이 막혀 있음을 점검으로 증명한다.

**작업**
1. 연결 계층이 `BANKGUARD_DB_URL`로 SQLite/PostgreSQL을 선택하도록 바꾼다. 운영 서버는 PostgreSQL 설정이 없으면 시작을 거부한다(SQLite로 자동 전환 금지).
2. `database/migrations/0001_*.sql`에 테이블, RLS 활성화, `anon`·`authenticated` 권한 회수를 넣고 적용 스크립트를 만든다.
3. `.env.example`에 입력할 항목과 설명을 쓴다(실제 값은 사람이 입력).
4. SC-08 설정 점검(RLS 전부 켜짐 + API 역할 권한 없음)을 시나리오 실행기에 추가한다.
5. `pytest -m postgres`로 테스트용 DB에서 SC-03 경쟁 조건(취약 FAIL / 안전 PASS)을 재현한다. DB 설정이 없으면 SKIP으로 보고한다.

**사람이 할 일:** Supabase 가입, **시연용·테스트용 프로젝트 2개** 만들기, Session pooler 접속 정보를 `.env`에 입력(채팅에 붙여 넣지 않기).

**완료 조건:** 앱으로 송금한 데이터가 Supabase Table Editor에 보임, SC-08 PASS, `-m postgres` 실제 실행 결과 기록, 기본 pytest는 여전히 오프라인으로 통과.

**커밋 예:** `Phase B: Supabase PostgreSQL 전환, RLS·권한 회수 마이그레이션, SC-08 점검, PostgreSQL 경쟁 조건 재현`

### Phase C. 로그인과 송금 2차 인증

**목표:** 가짜 토큰을 없애고 실제 은행 구조에 가까운 인증을 만든다.

**작업**
1. 회원가입·로그인(Argon2id), 서버 측 세션(httpOnly·SameSite=Strict 쿠키, 만료, 로그아웃), CSRF 토큰.
2. 로그인에 SC-07 시도 제한 연결.
3. 송금을 '대기 생성 → OTP 확인 후 실행' 2단계로 바꾼다(TOTP, 재사용 거절, 5분 만료).
4. SC-09(2차 인증 단계 건너뛰기) 취약 구현과 시나리오 추가.
5. `X-Demo-Token`을 운영 경로에서 제거하고, 기존 시나리오 하네스를 로그인 세션 기반으로 옮긴다.

**사람이 할 일:** OTP 앱(예: 휴대폰 인증 앱)에 시연 계정을 등록하고 직접 송금해 보기.

**완료 조건:** SC-01·03·04·05·06 회귀 PASS/FAIL 유지, SC-09 취약 FAIL → 안전 PASS, 비밀번호·OTP 시크릿이 DB·로그에 평문으로 없음.

**커밋 예:** `Phase C: 로그인·세션·CSRF, 송금 OTP 2차 인증, SC-09 2차 인증 우회 시나리오`

### Phase D. Figma → React + TypeScript

**목표:** 수업 필수 스택으로 화면을 만들고 Streamlit을 대체한다.

**작업**
1. (사람) Figma로 화면 설계: 로그인·회원가입, 내 계좌, 거래내역, 송금+OTP, 별칭 변경, 관리자 지급정지, 보안 점검 결과.
2. `frontend/`에 Vite + React + TypeScript(strict) 프로젝트 생성, Vite proxy로 `/api` 연결.
3. 은행 화면 구현 → 보안 점검 결과 화면(관리자, 읽기 전용) 구현.
4. React 화면이 Streamlit과 같은 정보를 보여주는지 확인한 뒤 Streamlit 파일·테스트 제거.

**사람이 할 일:** Figma 작업, 브라우저에서 모든 화면 직접 확인, Network 탭에서 Supabase 도메인 요청이 없는지 확인.

**완료 조건:** `npm run build` 성공(타입 검사 포함), 화면에서 로그인 → 송금(OTP) → 거래내역, 점검 결과 화면에 실제 artifacts 결과 표시.

**커밋 예:** `Phase D: React+TypeScript 화면(은행·보안 점검 결과), Streamlit 제거`

### Phase E. 통합, CI, 문서, 발표 준비

**작업**
1. CI에 프론트 빌드·타입 검사·`npm audit` 추가, 전체 점검 재실행 후 진단 보고서 갱신.
2. README·데모 대본·한계 문서를 v2.0 기준으로 갱신(실행 방법: 백엔드·프론트 터미널 2개 + `.env`).
3. 명세 V8 완료 기준 전부 체크.

**사람이 할 일:** 시연 리허설 1회, 모의 면접(“이 줄은 왜 이렇게 했나요?”).

**커밋 예:** `Phase E: CI 프론트 검사 추가, 진단 보고서·README·시연 문서 v2.0 갱신`

## 6. 확장 목록 (Phase E 이후, 순서대로)

| ID | 내용 | 완료 조건 |
|---|---|---|
| X1 | CSRF로 송금시키기(SC-10)·XSS 점검 | 취약(TestClient 전용) FAIL → 안전 PASS |
| X2 | 이상거래 탐지 확장(DET-02~04) + 가상 트래픽 | 규칙별 탐지율·오탐률 표 |
| X3 | Semgrep 정밀도·재현율, TypeScript 규칙, 로컬 ZAP | 수치 표와 실행 기록 |
| X4 | 클라우드 배포(안전 모드만) + 보안 헤더 점검 | 배포 주소에서 점검 실행 경로 없음 확인 |

## 7. 날짜별 목표

| 날짜 | 목표 |
|---|---|
| 10/30(금) | Phase A, Phase B |
| 11/2(월) | Phase C, Figma 화면 설계 |
| 11/3(화) | Phase D |
| 11/4(수) | Phase E, X1 |
| 11/5(목) | X2 (여유 시 X3) |
| 11/6(금) 오전 | 최종 점검, 오후 산출물 정리·발표 |

## 8. 진행 기록

- [x] v1.x DAY 1~8 완료 (10/28~10/29, 커밋 1f00d7e~d8c479f)
- [ ] Phase A
- [ ] Phase B
- [ ] Phase C
- [ ] Phase D
- [ ] Phase E
- [ ] X1 / X2 / X3 / X4
