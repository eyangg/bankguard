# CLAUDE.md — BankGuard 코딩 에이전트 작업 규칙

## 최우선 참조 문서

프로젝트 루트의 `BANKGUARD_CLAUDE_MASTER_SPEC.md`(**v1.2**)를 **제품 명세 및 수용 기준의 단일 출처**로 사용한다. 문서 맨 앞 변경 요약 표가 본문과 충돌하면 표가 우선이며, v1.2 표 > v1.1 표 > 본문 순이다. 명세의 P0 요구사항을 먼저 구현한다.

## 프로젝트 핵심

- 목적: 금융권 IT 보안 부서 지원용 1인 포트폴리오.
- 기간: 총 10일 중 실제 코딩 8일 (하루 약 7~9시간).
- 스택: Python 3.12, FastAPI, SQLite(sqlite3), pytest, HTTPX, Semgrep CE(별도 가상환경), Streamlit.
- P0: 가상 송금 API + 5종 핵심 보안 시나리오(SC-01 BOLA, SC-03 동시 송금 경쟁 조건, SC-04 멱등성, SC-05 BFLA, SC-06 Mass Assignment; SC-02 금액은 세부 테스트 T06·T07로 하향) + 감사 로그·DET-01 탐지 + 금융 맥락 SAST 4개 이상 + SAST↔동적 비교표 + 대시보드 + 진단 보고서 + CI 게이트 + README.

## 현재 진행 상태

- DAY 1 완료(2026-10-27): `backend/config.py`, `backend/factory.py`(create_app, secure 외 모드 거절), `backend/main.py`(안전 모드 고정), `GET /health`, `frontend/app.py`, `tests/test_smoke.py`(9개).
  - Linux VM(Ubuntu 22.04, Python 3.12.15)에서 pytest 9 passed, uvicorn/streamlit 200 확인.
  - Windows 환경 구성(.venv, .venv-semgrep) 및 git 첫 커밋 완료(1f00d7e).
- DAY 2 진행 중(미커밋): db/seed/schemas/auth_demo/audit/repository/routes/services/transfers + 테스트. **v1.2 변경은 DAY 2 범위를 바꾸지 않는다** — DAY 2를 원래 기준대로 끝내고 커밋한 뒤, v1.2 추가분(role/status/nickname, 지급정지·별칭 API, SC-05·SC-06)은 DAY 3에서 구현한다.

## 구현 규칙

1. **안전한 API**만 네트워크로 노출한다. 취약 비교 구현은 임시 DB 및 인프로세스 `TestClient` 환경에서만 실행한다.
2. 모든 계좌·인증 문자열은 허구의 테스트 데이터다. 실은행이나 제3자 시스템에 요청하지 않는다.
3. 정적 분석과 동적 API 테스트를 혼동하지 않는다.
4. 실제 실행되지 않은 검사에서 PASS/FAIL 결과를 조작하지 않는다. 실행하지 않은 테스트를 통과했다고 말하지 않는다.
5. 금액 정수화, 소유권 검사, DB 트랜잭션 원자성, 송금 멱등성을 우선한다.
6. `subprocess`는 쉘 호출 없이 고정된 로컬 대상에만 쓴다.
7. 작게 구현 → 검증 → 사용자에게 보고 → 다음 단계로 진행한다. 사용자가 "다음"이라고 하기 전에 다음 DAY로 넘어가지 않는다.
8. 한국어로 설명하고 모든 변경 파일·테스트 상태를 기록한다.
9. UI, 기능, 도구를 임의로 확장하지 않는다. P1은 P0 완성 후에만, '향후 확장'은 구현하지 않는다.
10. 개발환경은 Windows + VS Code. 명령은 PowerShell 기준으로 안내하고 `.\.venv\Scripts\python.exe`를 직접 호출한다(실행 정책 변경 금지).
11. semgrep은 `requirements.txt`에 넣지 않는다(`requirements-sast.txt`, `.venv-semgrep`).
12. git 커밋은 사용자가 요청할 때만 한다.

## 작업 종료 응답 형식

- 오늘 완료한 기능
- 추가·변경 파일
- 실제 실행·검증 명령 및 결과
- 미해결 오류와 제한사항
- 다음 작업
