# BankGuard — 가상 은행 API 보안 점검 랩

> 가상의 은행 계좌·송금 API를 대상으로 **보안 시나리오를 자동 실행**하고, Python 소스코드를 **Semgrep으로 정적 분석**해
> 위험 사항과 **수정 전후 검증 결과**를 한 화면과 진단 보고서로 보여주는 **로컬 전용** 보안 점검 프로젝트입니다.
> 실제 금융 서비스가 아니며, 모든 사용자·계좌·토큰은 허구의 더미 데이터입니다. 검사와 시연은 외부 서비스에 요청하지 않습니다
> (예외: 별도 명령인 의존성 점검(SCA)만 PyPI 취약점 DB를 조회합니다).

- 제품 명세(단일 출처): [`BANKGUARD_CLAUDE_MASTER_SPEC.md`](BANKGUARD_CLAUDE_MASTER_SPEC.md) · 작업 규칙: [`CLAUDE.md`](CLAUDE.md)
- 문서: [위협 모델](docs/threat_model.md) · [테스트 매트릭스](docs/test_matrix.md) · [시연 대본](docs/demo_script.md) · [한계](docs/limitations.md)
- **스크린샷은 아직 저장소에 없습니다**(화면 육안 확인과 캡처는 사람이 해야 하는 항목). 촬영 목록은 [시연 대본](docs/demo_script.md#캡처-체크리스트-직접-촬영)에 있습니다.

## 1. 무엇을 만들었나

| 구성 | 내용 |
|---|---|
| 가상 은행 API (FastAPI + SQLite) | 계좌 조회, 거래내역, 계좌 별칭 변경, 송금, 운영자 지급정지. 소유권 검사·역할 검사·금액 정수화·DB 트랜잭션·멱등성·인증 시도 횟수 제한을 갖춘 **안전 구현** |
| 동적 API 보안 시나리오 | 핵심 6종(SC-01 BOLA, SC-03 동시 송금 경쟁 조건, SC-04 멱등성, SC-05 BFLA, SC-06 Mass Assignment, SC-07 인증 무차별 대입 — SC-07은 P0 완료 후 추가한 P1) + 세부 1종(SC-02 금액 검증). 취약 구현과 안전 구현에 같은 시나리오를 실행해 **FAIL→PASS**를 확인 |
| 정적 분석 | Semgrep CE + 금융 맥락 로컬 규칙 4개(SQL 문자열 조립, 금액 float, 민감정보 로그, TLS 검증 해제·하드코딩 비밀값) |
| SAST ↔ 동적 비교표 | 같은 결함 코드에 대해 두 방법이 각각 무엇을 잡고 놓쳤는지 실제 실행 결과로 생성 |
| 감사 로그 + 탐지 DET-01 | 인증 실패·권한 거부·송금 결과를 마스킹해 기록하고, 계좌 열거 의심을 실제 로그로 탐지 |
| Streamlit 대시보드 | ① 개요 ② API 보안 테스트 ③ 정적 코드 분석 ④ 개선 비교·보고서 |
| 진단 보고서 + CI 게이트 | Markdown 보고서 생성, GitHub Actions에서 pytest + Semgrep 보안 게이트 + 의존성 점검 |
| 의존성 취약점 점검(SCA, P1) | pip-audit으로 앱 가상환경에 설치된 패키지(간접 의존성 포함)의 알려진 취약점 점검. 별도 명령·CI에서만 실행(인터넷 필요) |

## 2. 은행 IT·애플리케이션 보안 직무와의 연결

| 직무 업무 | 이 프로젝트에서 한 일 |
|---|---|
| API 취약점 점검 | OWASP API Security 2023(API1 BOLA, API2 인증, API3 속성 수준 권한, API5 BFLA)과 CWE에 매핑한 시나리오 설계·자동 실행·판정 |
| 소스코드 정적 분석 | Semgrep 규칙 작성, 취약/수정 샘플로 탐지·미탐지 검증, 오탐·미탐 한계 분석 |
| 보안 개선 이행점검 | 취약 버전 FAIL → 수정(안전) 버전 PASS를 같은 시나리오로 재검증하고 개선 건수를 집계 |
| 보안 관제·탐지 | 감사 로그 설계와 계좌 열거 탐지 규칙(DET-01), 탐지의 한계(오탐·미탐) 명시 |
| 보고 | 점검항목·위험도·근거·조치 권고·이행점검 결과를 담은 진단 보고서와 위협 모델(STRIDE) |
| 개발 파이프라인 보안 | CI 보안 게이트(안전 코드에 새 탐지가 생기면 실패), 오픈소스 의존성의 알려진 취약점 점검(SCA) |

## 3. 안전 모드와 비교용 취약 모드, 그리고 격리 방식

- **공개 서버(`backend/main.py`)는 안전 모드로 고정**되어 있습니다. 취약 구현은 네트워크로 노출되지 않습니다.
- 취약 구현(`backend/services/insecure_lab.py`)은 **결함 하나당 구현 하나**이고, 안전 코드와 **결함 부분만** 다릅니다.
  (결함을 켜고 끄는 스위치 방식은 쓰지 않았습니다. 실제 취약점 패턴의 모양과 맞는 비교 코드를 만들기 위해서입니다.)
  각 구현 위 주석에 "어떤 실제 버그 패턴인지 + 근거 사례"를 적었습니다.
- 취약 구현은 **시스템 임시 폴더의 새 DB + 인프로세스 `TestClient`**에서만 생성됩니다(경로 제한, 지연 import, 한 번에 결함 하나).
  격리 테스트(`tests/test_lab_isolation.py`)와 AST diff 형태 테스트(`tests/test_lab_diff_shape.py`)가 이를 확인합니다.

### 취약 ↔ 수정, 실제로 무엇이 다른가 (요약)

| 시나리오 | 취약 구현의 결함 | 안전 구현의 수정 | 취약 버전 FAIL 근거 |
|---|---|---|---|
| SC-01 BOLA | 계좌 소유자와 요청 사용자를 비교하지 않음 | 토큰의 user_id와 계좌 owner를 비교, 403 | 타인 거래내역이 200으로 반환됨 |
| SC-03 경쟁 조건 | 잔액 SELECT → 파이썬 계산 → 덮어쓰기, 트랜잭션 없음(lost update) | `BEGIN IMMEDIATE` + 조건부 UPDATE로 확인·차감 원자화 | 동시 2건 모두 201, 잔액 합계가 늘어남(돈 복제) |
| SC-04 멱등성 | 클라이언트 request_id를 저장·확인하지 않음 | request_id 유일키 + payload_fingerprint | 같은 요청 2회가 모두 별도 거래로 처리(이중 출금) |
| SC-05 BFLA | 관리 기능에 역할 검사 없음 | 관리 라우터 전체에 역할 검사(기본 거부) | 고객 토큰으로 타인 계좌 지급정지 성공 |
| SC-06 Mass Assignment | 요청 본문을 그대로 모델/UPDATE에 반영 | 허용 필드만(`extra=forbid`) + 고정 UPDATE | 끼워 넣은 balance·owner·status가 반영됨 |
| SC-07 인증 무차별 대입 | 인증 실패를 세지 않음(DAY 7까지의 인증 코드와 같음) | 클라이언트별 실패 5회 → 5분 창 동안 429, 시도 선예약으로 동시 요청도 제한 | 틀린 토큰 7개 뒤 8번째 추측(실제 토큰)이 200으로 통과 |
| SC-02 금액(세부) | 서버 모델이 일반 int를 받음(검증은 클라이언트에만 있다고 가정) | `StrictInt` + 범위 검증 + DB `CHECK` | 0원·음수 송금이 수락됨 |

실제 결과 값은 [테스트 매트릭스](docs/test_matrix.md)에 있습니다.

## 4. 준비물과 설치

- Python 3.12 (**3.12.10 Windows / 3.12.15 Linux에서만 검증**했습니다. 3.11은 시도하지 않았습니다.)
- Git
- Semgrep CE 1.182.1 — **앱과 별도 가상환경**에 설치합니다(아래 "의존성 분리 이유").
- (선택, P1) pip-audit 2.10.1 — 의존성 점검용. 이것도 **별도 가상환경**(`.venv-sca`)에 설치합니다.
- 인터넷은 **설치할 때와 의존성 점검(SCA)을 실행할 때만** 필요합니다. 대시보드 실행과 시연은 오프라인으로 됩니다. 단, API 서버의 `/docs`(Swagger UI)는 화면 스크립트를
  CDN에서 불러오므로 인터넷이 없으면 빈 화면이 될 수 있습니다(대시보드와는 무관).

### Windows PowerShell

```powershell
cd C:\경로\bankguard          # ⚠️ 경로를 짧게 두세요 (아래 "Windows 주의 — 긴 경로")
py -0p                                   # 설치된 Python 목록 확인 후 3.12 사용
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Semgrep 전용 가상환경 (앱과 분리)
py -3.12 -m venv .venv-semgrep
.\.venv-semgrep\Scripts\python.exe -m pip install -r requirements-sast.txt
.\.venv-semgrep\Scripts\semgrep.exe --version        # 1.182.1

# (선택) 의존성 점검 전용 가상환경 (앱 환경을 바깥에서 점검하기 위해 분리)
py -3.12 -m venv .venv-sca
.\.venv-sca\Scripts\python.exe -m pip install -r requirements-sca.txt
```

`Activate.ps1`이 실행 정책 때문에 막히면 정책을 바꾸지 말고 위처럼 `.\.venv\Scripts\python.exe`를 직접 호출하세요.

**Windows 주의 — 스마트 앱 컨트롤(SAC):** SAC가 켜져 있으면 서명되지 않은 `semgrep.exe`가 "애플리케이션 제어 정책에서 차단"
오류로 실행되지 않습니다(설치 자체는 성공). 이 PC에서는 코드 무결성 이벤트 3077/3033으로 확인했습니다. Windows 보안 → 앱 및
브라우저 컨트롤 → 스마트 앱 컨트롤 설정에서 끄면 해결되지만 **한 번 끄면 되돌릴 수 없으니** 본인 PC에서만 판단하세요.
`python -m semgrep`은 안내 문구만 출력하므로 우회 수단이 아닙니다. 설치/실행이 끝내 안 되면 WSL 또는 Docker로 대체하며,
결과를 임의로 만들지 않습니다.

**Windows 주의 — 긴 경로:** Windows는 기본적으로 경로를 260자로 제한합니다(`LongPathsEnabled`=0). 프로젝트를 깊은 폴더
(예: 임시 폴더 아래 여러 단계)에 두면 Streamlit 패키지 설치 중 `OSError: [Errno 2] No such file or directory`로 실패할 수 있습니다.
`C:\bankguard`처럼 짧은 경로를 쓰세요. (이 현상은 2026-10-29 빈 환경 재현 중 실제로 겪었습니다.)

### Linux / WSL / macOS

```bash
cd bankguard
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
python3.12 -m venv .venv-semgrep
.venv-semgrep/bin/python -m pip install -r requirements-sast.txt
python3.12 -m venv .venv-sca                                   # (선택) 의존성 점검
.venv-sca/bin/python -m pip install -r requirements-sca.txt
```

macOS는 검증하지 않았습니다(Linux는 Ubuntu 22.04 VM과 GitHub Actions `ubuntu-latest`에서 확인).

## 5. 실행과 접속 주소

```powershell
# 터미널 A — API (안전 모드만 공개)
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
#   http://127.0.0.1:8000/health  → {"status":"ok","service":"BankGuard API"}
#   http://127.0.0.1:8000/docs    → Swagger 문서

# 터미널 B — 대시보드
.\.venv\Scripts\python.exe -m streamlit run frontend/app.py
#   브라우저가 자동으로 열리지 않습니다. http://127.0.0.1:8501 을 직접 여세요.
#   (검사 버튼은 API 서버(터미널 A) 없이도 동작합니다. API를 켜 두면 ① 개요에 실시간 잔액이 표시됩니다.)

# 자동 테스트
.\.venv\Scripts\python.exe -m pytest -q
```

DB 파일은 처음 요청이 올 때 자동 생성되고(`ensure_db`), 시드 데이터(가상 고객 3명 + 운영자 1명)가 들어갑니다.

### 정적 분석(Semgrep) 직접 실행

앱은 `scanners/sast_runner.py`가 고정된 대상 3곳(`fixtures/code`, `backend/services/insecure_lab.py`, `backend/`에서 insecure_lab 제외)을
스캔합니다. 같은 명령을 손으로 실행해 볼 수도 있습니다.

```powershell
$env:PYTHONUTF8 = "1"   # ⚠️ 한국어 Windows 필수 (아래 설명)
.\.venv-semgrep\Scripts\semgrep.exe scan --config rules/bankguard.yml --metrics=off --disable-version-check fixtures/code
```

> **Windows 주의 — 인코딩:** 규칙 파일(`rules/bankguard.yml`)의 설명과 메시지는 UTF-8 한글입니다. 한국어 Windows는 기본
> 인코딩이 cp949라서 `PYTHONUTF8=1` 없이 실행하면 Semgrep이 규칙 파일을 읽다 `UnicodeDecodeError`로 종료합니다
> (종료 코드 2, `--quiet`를 쓰면 메시지도 안 보입니다). `sast_runner`는 자식 프로세스에 이 값을 자동으로 설정합니다.

## 6. API 목록과 요청 예시 (더미 데이터)

인증은 헤더 `X-Demo-Token` 하나입니다. 아래 토큰은 학습용 가상 문자열이며 **실제 인증이 아닙니다**.

| 사용자 | 토큰 | 역할 | 계좌(잔액) |
|---|---|---|---|
| 가상 고객 A | `demo-token-a` | customer | 101 (1,000,000원) |
| 가상 고객 B | `demo-token-b` | customer | 102 (500,000원) |
| 가상 고객 C | `demo-token-c` | customer | 103 (2,000,000원) |
| 가상 운영자 | `demo-token-admin` | admin | — |

| 메서드 · 경로 | 설명 | 주요 응답 |
|---|---|---|
| `GET /health` | 상태 확인(인증 없음) | 200 |
| `GET /api/accounts` | 내 계좌 목록 | 200 / 401 |
| `GET /api/accounts/{id}/transactions` | 내 계좌 거래내역 | 200 / 401 / 403(타인) / 404 |
| `PATCH /api/accounts/{id}` | 계좌 별칭 변경(허용 필드는 `nickname` 하나) | 200 / 403 / 404 / 422(그 외 필드) |
| `POST /api/transfers` | 송금(멱등) | 201 신규 / 200 재전송 / 400·403·404 / 409 충돌·잔액 부족·지급정지 / 422 |
| `POST /api/admin/accounts/{id}/freeze` | 운영자 전용 지급정지 | 200 / 403(고객) / 404 |

```powershell
# 내 계좌 조회
curl.exe -H "X-Demo-Token: demo-token-a" http://127.0.0.1:8000/api/accounts

# 타인(B) 거래내역 조회 → 403 (안전 모드)
curl.exe -H "X-Demo-Token: demo-token-a" http://127.0.0.1:8000/api/accounts/102/transactions

# 송금 (request_id는 UUID. 같은 값으로 다시 보내면 200으로 같은 거래를 돌려주고 출금은 1회)
curl.exe -X POST http://127.0.0.1:8000/api/transfers -H "Content-Type: application/json" -H "X-Demo-Token: demo-token-a" `
  -d '{\"from_account_id\":101,\"to_account_id\":102,\"amount_krw\":20000,\"request_id\":\"3f2b8c1e-5a47-4d0e-9b1a-0c6d2e7f8a91\"}'
```

금액은 정수 원 단위(`StrictInt`, 0 초과 10,000,000 이하)이고 소수·문자열·불리언은 422입니다. `/api/demo/users` 같은 사용자 목록 노출 API는 없습니다.

## 7. 보안 테스트 시나리오와 결과 해석

각 시나리오는 **독립된 임시 DB와 새 앱**에서 실제 HTTP 요청(인프로세스)을 보내고, **응답 코드와 DB 상태로만** 판정합니다.
실제 결과(요청·기대·실제·근거)는 [테스트 매트릭스](docs/test_matrix.md)에 있고, 다시 만들려면 `python -m scanners.report`를 실행합니다.

| 상태 | 의미 |
|---|---|
| ✅ PASS | 안전 기준을 만족했다(정상 요청은 성공하는 양성 대조도 확인) |
| ❌ FAIL | 안전 기준 위반이 응답/DB로 확인됨(취약 동작) |
| ⚠️ ERROR | 결함 때문이 아닌 오류(5xx, 예외, 양성 대조 실패). 취약/안전 판정에 쓰지 않음 |
| 미실행 | 아직 실행하지 않음. 이전 결과를 재사용하거나 가짜 결과로 채우지 않음 |

개선 집계는 **취약 버전 FAIL과 안전 버전 PASS가 둘 다 실제로 확인된 시나리오만** 셉니다. 한쪽이 ERROR/미실행이면 "판정 불가"입니다.

| ID | 점검 | 위험도(L×I) | 매핑 |
|---|---|---|---|
| SC-01 | 타인 거래내역 조회 차단 (BOLA) | HIGH (L3×I2) | API1:2023 · CWE-639 |
| SC-03 | 동시 송금 경쟁 조건 차단 | HIGH (L2×I3) | CWE-362 / CWE-367 |
| SC-04 | 중복 송금 방지 (멱등성) | HIGH (L3×I3) | CWE-837 |
| SC-05 | 고객의 관리자 기능 호출 차단 (BFLA) | HIGH (L3×I3) | API5:2023 · CWE-285 |
| SC-06 | 요청 필드 끼워넣기 차단 (Mass Assignment) | HIGH (L3×I3) | API3:2023 · CWE-915 |
| SC-07 (P1) | 인증 무차별 대입 차단 (시도 횟수 제한) | HIGH (L2×I3) | API2:2023 · CWE-307 |
| SC-02 (세부) | 잘못된 금액 차단 (0원·음수) | HIGH (L3×I3) | CWE-602 / CWE-20 |

위험도는 프로젝트 내부 학습용 3×3 기준이며 **CVSS 인증 점수가 아닙니다**.

## 8. 정적 분석 규칙, 탐지 결과, 오탐·미탐

| 규칙 | 찾는 것 | CWE |
|---|---|---|
| BG-SAST-001 | SQL 문자열 조립(f-string, `%`, `+`, `.format`) | CWE-89 |
| BG-SAST-002 | 금액 이름의 변수/필드에 float 사용 | CWE-1339 |
| BG-SAST-003 | 토큰·계좌번호 등 민감정보의 로그/print 출력 | CWE-532 |
| BG-SAST-004 | `verify=False` TLS 검증 해제, 하드코딩 비밀값 | CWE-295 / CWE-798 |

- `fixtures/code/vulnerable_example.py`는 규칙이 탐지해야 하는 줄을 `# EXPECT`로 표시하고, `fixed_example.py`는 탐지 0건(근접한 안전 패턴 포함)이어야 합니다. 둘 다 테스트가 확인합니다.
- Semgrep 결과는 **검토가 필요한 의심 항목**이지 확정 취약점이 아닙니다. 탐지 0건은 "그 규칙의 패턴을 찾지 못했다"는 뜻이며 안전 보증이 아닙니다. 도구 오류는 `SCAN_ERROR`로 0건과 구분합니다.
- 오탐 예: 값이 내부 상수인 SQL 조립. 미탐 예: 다른 함수에서 조립해 넘긴 SQL, 이름에 단서가 없는 float 금액 변수, `requests` 외 클라이언트의 TLS 검증 해제.
- **업무 로직 결함(소유권·역할·동시성·멱등성·Mass Assignment·금액 검증 누락·인증 시도 제한 누락)은 이 규칙으로 탐지하지 못합니다.** 아래 비교표가 이를 실제 결과로 보여 줍니다.

## 9. 검증 결과

| 날짜 | 환경 | 명령 | 결과 |
|---|---|---|---|
| 2026-10-27 | Ubuntu 22.04 VM, Python 3.12.15 | `python -m pytest -q` (DAY 1 시점) | 9 passed |
| 2026-10-27 | 동일 | uvicorn `/health`·`/docs`, streamlit `/_stcore/health`·`/` | 200 / 200 / 200 / 200 |
| 2026-10-28 | Windows 11, Python 3.12.10, Semgrep 1.182.1 | `sast_runner.run_sast()` (실제 Semgrep) | fixtures 17건 · insecure_lab 1건 · backend(lab 제외) 0건, SCAN_ERROR 0 |
| 2026-10-29 | 동일 | `.\.venv\Scripts\python.exe -m pytest -q` (Linux 호환 수정 후) | **294 passed**, 1 warning |
| 2026-10-29 | 동일 | `python -m scanners.report` (전체 검사 실제 실행, SC-07 추가 전) | 핵심 5개 모두 FAIL→PASS 개선 확인, Semgrep 18건(검토 필요), 스캔 오류 0, DET-01 PASS |
| 2026-10-29 | GitHub Actions `ubuntu-latest`, Python 3.12.15 | 첫 실행 (run #1, 커밋 0a21589) | **실패** — `tests/test_sast_runner.py`의 경로 정규화 테스트 1건. Linux에서 `Path`가 역슬래시를 구분자로 보지 않는 것이 원인. `_relative_posix` 수정(4986913) |
| 2026-10-29 | 동일 | 수정 후 `master` (run #2, 커밋 4986913) | **성공** — pytest 294개, 보안 게이트 단계 성공 |
| 2026-10-29 | 동일 | 의도적 실패 브랜치 `ci-fail-demo` (run #3, 안전 코드에 가짜 비밀 문자열 추가) | **실패** — pytest 단계에서 실패, 보안 게이트 단계는 건너뜀 (아래 참고) |
| 2026-10-29 | **빈 환경 재현** — `git archive HEAD`로 커밋된 파일만 `C:\bgclean`에 풀고 새 `.venv`·`.venv-semgrep` 생성 (Windows 11, Python 3.12.10) | 위 "설치" 절 명령 그대로: `pip install -r requirements.txt`, `pip install -r requirements-sast.txt`, `semgrep --version` | 설치 성공, Semgrep 1.182.1, `pytest -q` **294 passed**(205초) |
| 2026-10-29 | 동일 빈 환경 | uvicorn(포트 8010)·streamlit(포트 8511) 실행 후 HTTP 확인 | `/health` 200 `{"status":"ok",...}`, `/docs` 200, `/_stcore/health` 200, 대시보드 `/` 200 (화면 육안 확인은 사람이 해야 함) |
| 2026-10-29 | 동일 | 깊은 임시 폴더(경로 260자 초과)에서 같은 설치 | **실패** — Streamlit 내부 파일 경로가 정확히 260자, `LongPathsEnabled`=0. 짧은 경로로 해결(설치 절 참고) |
| 2026-10-29 | 메인 개발 환경 | README의 `curl.exe` 예시를 실제 API에 전송 | 거래내역 타인 조회 403, 송금 201, 같은 `request_id` 재전송 200(`idempotent_replay: true`) |
| 2026-10-29 | Windows 11, Python 3.12.10, Semgrep 1.182.1 (SC-07·SCA 추가 후) | `.\.venv\Scripts\python.exe -m pytest -q` | **332 passed** |
| 2026-10-29 | 동일 | `python -m scanners.ci_gate` | `GATE PASS` — 안전 모드 PASS 7 / FAIL 0 / ERROR 0, Semgrep 탐지 18건(취약 샘플·취약 구현), 안전 코드 0건, 스캔 오류 0 |
| 2026-10-29 | 동일 | `python -m scanners.report` | 핵심 6개 모두 FAIL→PASS(SC-07: 취약 `[401×7, 200]` / 안전 `[401×5, 429×3]`, Retry-After 300), DET-01 PASS |
| 2026-10-29 | 동일, pip-audit 2.10.1 (`.venv-sca`) | `python -m scanners.sca_runner` (pip 업그레이드 전) | 패키지 54개 점검, **`pip 25.0.1`에서 알려진 취약점 6건**(PYSEC-2026-1795 등, 수정 버전 25.3~26.2), 종료 코드 1. 앱 의존성 자체는 0건 |
| 2026-10-29 | 동일 | `pip install --upgrade pip`(26.2.2) 후 다시 실행 | 패키지 54개 점검, 0건, 종료 코드 0 (조치 → 이행점검 확인) |
| 2026-10-29 | 동일 | 새 캐시 폴더 + 접속 불가 프록시로 오프라인 재현 | pip-audit 종료 코드 1, JSON 없음 → 실행기는 `SCAN_ERROR`(BAD_JSON, 인터넷 필요 안내)로 분류. 단, 기본 캐시가 남아 있으면 오프라인이어도 최근 조회 결과로 완료됨 |
| — | GitHub Actions (SC-07·SCA·게이트 단계 변경 후) | push 후 실행 | **미검증** (push 필요) |
| — | Windows 10, macOS, Python 3.11 | 위 전체 | **미검증** |

> **CI 의도적 실패 확인에 대해:** run #3은 실패로 끝나 "안전 코드에 새 탐지가 생기면 CI가 실패한다"는 결과와 일치합니다.
> 다만 **실패한 단계는 전용 보안 게이트 단계가 아니라 그 앞의 pytest 단계**였습니다(저장소 전체에 게이트를 실행하는 테스트
> `test_gate_passes_on_the_real_repository`가 pytest에 포함돼 있기 때문일 가능성이 높지만, 실패한 테스트 이름은 로그로 확인하지 않았습니다).
> 이후 워크플로를 바꿔 보안 게이트·SCA 단계는 pytest가 실패해도 실행되게 했습니다(`if: ${{ !cancelled() }}`, 작업 전체 실패 판정은 그대로). 바뀐 워크플로의 실제 실행은 아직 미검증입니다.

## 10. 핵심 구현 의사결정

- **금액은 정수 원 단위(`StrictInt`)로만 받는다.** float는 정밀도 오류와 `NaN/Infinity` 문제가 있고, Pydantic의 엄격 정수로 `true`/`1.5`/`"100"`을 거절합니다. DB에도 `CHECK (amount_krw > 0)`를 둬 이중 방어합니다.
- **소유권은 서버가 판단한다.** 토큰에서 얻은 user_id와 계좌의 owner_user_id를 비교합니다. 없는 계좌 404 / 남의 계좌 403으로 구분 응답하므로(명세 6.4) 열거가 가능하다는 점은 인정하고, 흔적을 감사 로그로 남겨 DET-01로 탐지합니다.
- **송금은 하나의 원자적 트랜잭션이다.** `BEGIN IMMEDIATE` 안에서 `UPDATE ... SET balance = balance - ? WHERE id = ? AND balance >= ? AND status = 'ACTIVE'` 조건부 UPDATE로 확인과 차감을 한 번에 하고, 출금·입금·기록을 단일 COMMIT으로 묶습니다.
- **멱등성:** 클라이언트가 보낸 `request_id`(UUID)를 유일키로 저장하고 `payload_fingerprint`(출금·입금·금액)를 함께 둡니다. 같은 요청 재전송은 200으로 같은 거래를 돌려주고, 같은 ID에 다른 내용은 409입니다.
- **권한은 기본 거부.** 관리자 라우터 전체에 역할 검사 의존성을 걸어 새 관리 경로가 검사를 빠뜨리기 어렵게 했습니다.
- **인증 시도 횟수 제한(SC-07):** 같은 클라이언트 주소가 5분 안에 5번 실패하면 6번째 요청부터 `429 + Retry-After`이고, 잠금 중에는 **맞는 토큰도 검사하지 않습니다**(검사하면 추측이 계속 됩니다). '확인 → 실패 기록' 사이에 동시 요청이 끼어드는 경쟁 조건을 막으려고 `BEGIN IMMEDIATE` 안에서 횟수 확인과 시도 예약을 한 번에 하고, 성공하면 예약을 지웁니다(동시 20건 테스트에서 실제 토큰 검사는 정확히 5건). 성공해도 실패 횟수를 초기화하지 않습니다(초기화하면 공격자가 자기 정상 토큰을 섞어 우회). `X-Forwarded-For`처럼 요청자가 바꿀 수 있는 헤더는 신뢰하지 않습니다.
- **오류 처리:** 500은 내부 정보 없이 일반 메시지만, DB 잠금은 오류를 숨기지 않고 `503 + Retry-After`로 알립니다.
- **검사의 정직성:** 판정은 응답과 DB 상태로만 하고, 양성 대조가 깨지면 ERROR로 분리하며, 실행하지 않은 검사는 "미실행"으로 둡니다.

## 11. SAST ↔ 동적 테스트 탐지 범위 비교 (2026-10-29 실제 실행 결과)

같은 결함 코드(`insecure_lab.py`)에 대해 두 방법이 각각 무엇을 잡았는지입니다. 값은 `python -m scanners.report`가 실제로 실행한 결과에서
옮긴 것이며 대시보드 ④탭에서 다시 생성할 수 있습니다. (SC-07 행은 P1로 추가한 것이며, 나머지 8행은 2026-10-28 첫 실행과 같은 판정)

| 결함 | 동적 테스트(취약 / 안전) | Semgrep | 해석 |
|---|---|---|---|
| BOLA(소유권 검사 누락) | SC-01 FAIL / PASS | 미탐지(겨냥한 규칙 없음) | 동적 테스트만 탐지 |
| 음수/0 금액 허용 | SC-02 FAIL / PASS | 미탐지(겨냥한 규칙 없음) | 동적 테스트만 탐지 |
| 경쟁 조건(비원자적 차감) | SC-03 FAIL / PASS | 미탐지(겨냥한 규칙 없음) | 동적 테스트만 탐지 |
| 멱등성 미처리 | SC-04 FAIL / PASS | 미탐지(겨냥한 규칙 없음) | 동적 테스트만 탐지 |
| BFLA(역할 검사 누락) | SC-05 FAIL / PASS | 미탐지(겨냥한 규칙 없음) | 동적 테스트만 탐지 |
| Mass Assignment | SC-06 FAIL / PASS | 이 결함은 미탐지(같은 코드에서 SQL 조립 BG-SAST-001만 탐지) | 동적 테스트만 결함을 재현 |
| 인증 시도 횟수 제한 없음 | SC-07 FAIL / PASS | 미탐지(겨냥한 규칙 없음) | 동적 테스트만 탐지 |
| SQL 문자열 조립 | 해당 시나리오 없음 | 탐지(BG-SAST-001 · 7건 · 검토 필요) | 정적 분석만 탐지. 실제 악용 가능성은 사람이 판단 |
| 금액 float | 해당 시나리오 없음 | 탐지(BG-SAST-002 · 4건 · 검토 필요) | 정적 분석만 탐지 |

**읽는 법:** 업무 로직 결함(위 7행)은 소스 패턴 규칙으로 잡히지 않고, 반대로 코드 패턴 결함(아래 2행)은 실행 시나리오가 없습니다.
정적 분석만으로 업무 로직을 보장할 수 없고 동적 테스트만으로 코드 패턴을 모두 찾을 수도 없다는 것을 데이터로 보여 줍니다.
SC-06 행처럼 같은 코드에서 다른 규칙이 탐지돼도 **그 결함 자체를 탐지한 것으로 세지 않습니다.**

### 감사 로그와 탐지 규칙 DET-01 (계좌 열거 의심)

인증 실패·권한 거부·송금 결과는 `audit_log`에 기록됩니다. 토큰은 원문이 아니라 SHA-256 앞 12자리 지문만, 계좌번호는
`DEMO-1**`처럼 마스킹해서 저장하고, 송금이 롤백돼도 거절 기록은 남습니다.

**규칙:** 같은 사용자가 최근 `5분` 안에 서로 다른 계좌 ID `3개` 이상에서 `ACCESS_DENIED`/`NOT_FOUND`를 받으면 경보를 냅니다
(임계값은 `backend/config.py`의 설정값). 경보는 **실제 감사 로그를 조회한 결과로만** 만들어집니다(2회까지 무경보, 3번째에 경보 1건).

- 같은 계좌를 반복해서 틀리는 경우는 '서로 다른 계좌'가 아니라 경보가 나지 않습니다(재시도 오탐 완화).
- **오탐:** 정상 사용자가 계좌 ID를 여러 번 잘못 입력하거나 한 토큰을 여러 사람이 공유하면 경보가 날 수 있습니다.
- **미탐:** 임계값 아래로 천천히 시도하거나(5분 창 밖으로 분산) 토큰을 바꿔 가며 시도하면 놓칩니다. **탐지이지 차단이 아닙니다.**
- 대시보드 ④탭의 `DET-01 탐지 검증 실행` 버튼으로 격리된 앱에서 위 시나리오를 실제로 재현해 볼 수 있습니다.

## 12. 진단 보고서와 CI 보안 게이트

```powershell
# 모든 검사(취약→안전→정적 분석→DET-01)를 실제로 실행하고 artifacts/에 JSON과 Markdown 보고서를 저장
.\.venv\Scripts\python.exe -m scanners.report
#   → artifacts/diagnosis_report.md, artifacts/coverage_matrix.json, artifacts/latest_*.json
# 검사를 다시 하지 않고 저장된 최근 결과로만 보고서를 만들기
.\.venv\Scripts\python.exe -m scanners.report --from-artifacts

# CI와 같은 보안 게이트를 로컬에서 실행 (통과 0 / 실패 1)
.\.venv\Scripts\python.exe -m scanners.ci_gate

# (P1) 의존성 취약점 점검 — 인터넷 필요. 결과는 artifacts/latest_sca.json, 다음 보고서 7장에 실행 시각과 함께 실림
.\.venv\Scripts\python.exe -m scanners.sca_runner     # 0 = 알려진 취약점 없음 / 1 = 발견 / 2 = 점검 불가
```

SCA는 **대시보드의 전체 검사에 넣지 않았습니다.** PyPI 취약점 DB를 인터넷으로 조회해야 해서(설치된 패키지 이름·버전 전송),
"인터넷 없이 로컬에서 완전 시연" 기준을 지키기 위해서입니다. 점검 대상은 requirements 파일이 아니라 **앱 가상환경에 실제 설치된
패키지**(간접 의존성과 pip 자체 포함)이며, pip-audit은 별도 가상환경에서 `PIPAPI_PYTHON_LOCATION`으로 앱 환경을 바깥에서 점검합니다.

대시보드 ④탭에서도 같은 보고서를 내려받을 수 있습니다. 보고서는 점검항목 · 위험도(L×I) · 취약 여부 · 근거 · 조치 권고 ·
이행점검 결과 · 매핑을 담고, 실행하지 않은 부분은 '미실행'으로 적습니다.

**보안 게이트(`.github/workflows/security-check.yml`)는 아래 중 하나라도 해당하면 실패합니다.**
- 안전 코드(`backend/`, `insecure_lab.py` 제외)에서 Semgrep 탐지가 있거나, 스캔이 오류(SCAN_ERROR)로 끝남
- 취약 샘플에서 규칙이 탐지하지 못하거나(규칙이 망가짐), 수정 샘플에서 오탐이 남
- 안전 모드의 핵심 시나리오가 하나라도 PASS가 아님
- (P1) pip-audit이 설치된 의존성에서 알려진 취약점을 찾거나, 점검 자체가 불가능함(별도 단계)

보안 게이트와 SCA 단계는 pytest가 실패해도 실행되도록 해서, 어떤 검사가 무엇을 막았는지 단계별로 보이게 했습니다.

Actions 실행 기록은 위 "9. 검증 결과" 표를 보세요.

### 의존성 분리 이유 (2026-10-27 실제 확인)

`semgrep 1.182.1`은 `opentelemetry-api==1.37.x`를 고정하고 `fastapi 0.162.0`은 `opentelemetry-api>=1.44.0`을 요구해
같은 가상환경에서 충돌합니다. 함께 설치하면 pip/uv가 semgrep을 1.79.0(구버전)으로 내려 설치합니다.
BankGuard는 Semgrep을 `subprocess`(리스트 인자, `shell=False`)로 CLI만 호출하므로 환경을 분리해도 기능 손실이 없습니다.

## 13. 폴더 구조

```text
bankguard/
├─ backend/        # FastAPI. main.py=안전 모드 공개 진입점, factory.py=create_app, routes/services/repository/audit/detection/throttle
│  └─ services/    #   transfers.py(안전 송금), insecure_lab.py(비교용 취약 구현 — 임시 DB·인프로세스 전용)
├─ scanners/       # API 시나리오 실행기, race_harness, Semgrep 실행기, SCA(pip-audit) 실행기, DET-01 실행기, 비교, 보고서, CI 게이트
├─ rules/          # Semgrep 로컬 규칙 (bankguard.yml)
├─ fixtures/code/  # 정적 분석 샘플 (취약 / 수정)
├─ frontend/       # Streamlit 대시보드 (app.py, tabs.py, helpers.py, services.py)
├─ tests/          # pytest
├─ docs/           # threat_model.md, test_matrix.md, demo_script.md, limitations.md
├─ .github/workflows/security-check.yml   # CI 보안 게이트
└─ artifacts/      # 실행 산출물 (git 제외)
```

## 14. 프로젝트 기간, 담당 범위, 개발 중 해결한 문제

- **기간:** 총 10일 계획 중 코딩 8일(DAY 1~8). 개발은 2026-10-27에 시작했습니다. 1인 프로젝트이며 요구사항 정의·설계 결정·검증·문서는 본인이 맡았습니다.
- **개발 중 실제로 해결한 문제**
  - Windows 스마트 앱 컨트롤이 서명되지 않은 `semgrep.exe`를 차단 → 원인을 코드 무결성 이벤트로 확인, 우회하지 않고 SAC 해제 후 재검증.
  - 한국어 Windows(cp949)에서 UTF-8 규칙 파일을 읽지 못해 Semgrep 종료 코드 2 → `PYTHONUTF8=1`을 자식 프로세스에 주입하고 회귀 테스트 추가.
  - Semgrep과 FastAPI의 `opentelemetry-api` 버전 충돌 → 가상환경 분리.
  - 대시보드에서 버튼을 눌러도 결과가 한 번 늦게 보이는 문제 → 작업 예약/실행 구조(job 패턴)로 변경.
  - Linux CI에서만 나타난 경로 정규화 실패(Windows 전용으로 통과하던 테스트) → 정규화 수정.
  - 긴 경로(260자)에서 Streamlit 설치 실패 → 짧은 경로 안내를 문서화.

## 15. AI 활용 내역과 본인이 설계·검증·수정한 부분

> 아래는 개발 기록을 바탕으로 정리한 **초안**입니다. 제출 전에 실제 본인의 기여와 다르면 직접 고쳐 주세요.

| 구분 | 내용 |
|---|---|
| AI(Claude Code)가 한 일 | 명세에 따른 코드 초안 작성(백엔드·시나리오 러너·Semgrep 실행기·대시보드·보고서·CI 워크플로), 테스트 작성, 오류 로그 분석과 수정안 제시, 문서 초안 |
| 본인이 정한 것 | 프로젝트 목적과 명세(범위·수용 기준·보안 시나리오 선정), 바이브코딩 진행 방식(단계별로 구현 → 검증 → 확인 후 다음 단계), 안전 모드만 공개하는 격리 원칙 |
| 본인이 판단·수정한 것 | 결함을 켜고 끄는 스위치 방식의 취약 구현 제안을 **채택하지 않고**, 결함 1개당 취약 구현 1개로 바꾸게 함. 경쟁 조건 지연을 취약 코드가 아니라 테스트 쪽에 두도록 지시. 설치 실패 시 우회하지 말고 원인만 보고하도록 지시. 대시보드 화면을 직접 확인한 뒤 세부 사항 수정 지시 |
| 본인이 직접 실행·확인한 것 | Windows 환경에서 설치/실행, 스마트 앱 컨트롤 해제, GitHub 저장소 생성과 push, Actions 실행 결과 확인 및 실패 로그 전달, 대시보드 화면 육안 확인 |
| AI 산출물에 대한 검증 | 실제 실행으로만 PASS/FAIL 판정, 자동 테스트로 회귀 확인. 단 AI가 작성한 코드는 본인이 모든 줄을 독립 검토했다고 말할 수 없는 부분이 있음 |

## 16. 제한사항

- 실제 은행 인증·규제·운영 환경과 다르며, 정의된 테스트와 SAST 규칙 범위만 검증합니다. 실서비스에 쓸 수 없습니다.
- 대신 은행 API에서 실제로 쓰는 통제 중 **서버 측 소유권 검사, 역할 기반 기능 권한(기본 거부), 원자적 송금 트랜잭션, 송금 멱등성,
  인증 시도 횟수 제한(잠금), 마스킹된 감사 로그와 이상 징후 탐지, 오류 정보 비노출, 의존성 취약점 점검**을 학습용 규모로 재현했습니다.
- `X-Demo-Token`은 학습용 가상 사용자 식별일 뿐 실제 인증 체계(비밀번호·다중 인증·세션 만료·전자서명)가 아닙니다.
  인증 실패 횟수 제한은 있지만 일반 요청량 제한(대량 호출 방어)과 TLS는 구현하지 않았습니다.
- 자세한 한계(검사 범위, SAST 오탐·미탐, DET-01 한계, 알려진 미조치 사항)는 [`docs/limitations.md`](docs/limitations.md)에 있습니다.

## 17. 향후 확장 (아이디어만 기록, 구현하지 않음)

- 이 송금 API를 '도구'로 호출하는 금융 AI 에이전트(예: "B에게 5만 원 보내 줘"를 처리하는 상담 챗봇)의 보안 점검으로 넓힐 수 있습니다.
- 두 계층으로 나눠 봅니다. 모델 계층에서는 탈옥·프롬프트 주입 시도를 탐지하고(캡스톤 프로젝트인 한국어 LLM 탈옥 시도 및 방어와 연결), 실행 계층에서는 에이전트가 모델의 판단과 무관하게 이 프로젝트의 소유권·역할·멱등성 검사를 통과해야만 송금하게 합니다.
- BankGuard의 시나리오(BOLA·BFLA·멱등성)를 그대로 "에이전트가 속았을 때도 서버가 막는가"를 검증하는 기준으로 재사용할 수 있습니다.
