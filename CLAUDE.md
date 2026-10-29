# CLAUDE.md — BankGuard 코딩 에이전트 작업 규칙

## 최우선 참조 문서

- `BANKGUARD_CLAUDE_MASTER_SPEC.md`(**v2.0**)가 제품 명세와 완료 기준의 단일 출처다. 우선순위: **v2.0 장 > v1.2 표 > v1.1 표 > 본문.**
- 개발 순서는 `docs/plan.md`(Phase A~E, 확장 X1~X4)를 따른다.

## 프로젝트 핵심

- 목적: 금융권 IT 보안 부서 지원용 1인 포트폴리오, 바이브코딩 수업 개별 사이드 프로젝트(11/6 발표).
- **필수 스택(수업 고정): FastAPI · React · TypeScript · Supabase.** 화면 코드는 `.ts`/`.tsx`만 쓴다(`.jsx`/`.js` 금지).
- 기타: Python 3.12, pytest(기본은 임시 SQLite, `-m postgres`는 테스트용 Supabase), Semgrep CE(`.venv-semgrep`), pip-audit(`.venv-sca`).

## 현재 진행 상태

- v1.x DAY 1~8 완료(10/28~10/29, 커밋 1f00d7e~d8c479f): 안전 송금 API, 핵심 시나리오 SC-01·03·04·05·06(취약 FAIL→안전 PASS), Semgrep 규칙 4개, DET-01, 진단 보고서, CI 게이트, Streamlit 대시보드, README.
- 미커밋: SC-07 로그인 시도 제한(`backend/throttle.py`), SCA(`scanners/sca_runner.py`) → Phase A에서 마무리.
- 다음: `docs/plan.md`의 Phase A.

## 구현 규칙

1. 한 번의 요청에서는 Phase 하나만 진행한다. **Phase 시작 전에 사람이 해야 할 일·필요한 값·결정할 내용을 먼저 알려준다.**
2. Phase가 끝나면 테스트 결과를 보고하고 멈춘다. 사람의 화면 확인과 `docs/learning_log.md` 작성 후 "다음"이라고 하기 전에는 다음 Phase로 넘어가지 않는다.
3. **안전 모드만 네트워크로 노출한다.** 취약 비교 구현은 TestClient + 임시 SQLite에서만 만든다. 점검 실행(시나리오·Semgrep·pip-audit)은 CLI·CI 전용이고, 웹은 결과를 관리자만 읽기 전용으로 본다.
4. **브라우저는 Supabase에 직접 접속하지 않는다.** Supabase 키와 DB 접속 정보를 프론트 코드나 `VITE_*` 변수에 두지 않는다. 모든 테이블은 RLS 활성화 + `anon`·`authenticated` 권한 회수.
5. 비밀값은 `.env`에만 둔다. 코드·문서·로그·답변에 출력하지 않는다. `.env.example`에는 항목과 설명만 둔다.
6. 실제 실행되지 않은 검사를 PASS/FAIL로 보고하지 않는다. 실행하지 못한 것은 "미검증", 설정이 없어 건너뛴 것은 "SKIP"으로 구분한다.
7. 금액 정수화, 소유권 검사, 트랜잭션 원자성, 송금 멱등성, 서버 측 OTP 검증을 우선한다.
8. `subprocess`는 쉘 없이 고정된 로컬 대상에만 쓴다.
9. 명세에 없는 기능·도구를 임의로 추가하지 않는다. 확장(X1~X4)은 Phase E 이후에만.
10. 개발환경은 Windows + VS Code. 명령은 PowerShell 기준, `.\.venv\Scripts\python.exe`를 직접 호출한다(실행 정책 변경 금지).
11. git 커밋·푸시는 사용자가 요청할 때만, 관련 변경만 담는다.
12. 한국어로, 변경 파일·실행 명령·결과·남은 문제를 짧게 보고한다.

## 작업 종료 응답 형식

- 완료한 것
- 추가·변경 파일
- 실제 실행한 명령과 결과
- 사람이 확인할 것
- 남은 문제와 다음 Phase
