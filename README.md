# BankGuard — 가상 은행 API 보안 점검 랩 (작업 중 초안)

> 가상의 은행 계좌·송금 API를 대상으로 보안 시나리오를 자동 실행하고, Python 소스코드를 Semgrep으로 정적 분석해
> 위험 사항과 수정 전후 검증 결과를 한 화면에서 보여주는 **로컬 전용** 보안 점검 플랫폼입니다.
> 실제 금융 서비스가 아니며, 모든 사용자·계좌·토큰은 허구의 더미 데이터입니다.

- 제품 명세(단일 출처): [`BANKGUARD_CLAUDE_MASTER_SPEC.md`](BANKGUARD_CLAUDE_MASTER_SPEC.md)
- 작업 규칙: [`CLAUDE.md`](CLAUDE.md)

## 진행 현황

| DAY | 내용 | 상태 |
|---|---|---|
| 1 | 개발 환경, 프로젝트 골격, `GET /health`, Streamlit 첫 화면, 스모크 테스트 | 완료 (Linux·Windows 검증) |
| 2 | SQLite 스키마·시드, 안전 송금 API, 감사 로그 기록 | 완료 (Windows pytest 64 passed, 실서버 확인) / 탐지 규칙 DET-01은 DAY 7 예정 |
| 3 | v1.2 스키마(role/status/nickname)·지급정지·별칭 변경 API, 취약/안전 격리 모드, SC-01·SC-05·SC-06 판정 | 완료 (Windows pytest 112 passed, 실서버 확인) |
| 4 | SC-03 동시 송금 경쟁 조건, SC-04 멱등성, SC-02(T06·T07) 취약 구현, 핵심 5종+세부 1종 공통 실행 | 완료 (Windows pytest 151 passed) |
| 5 | Semgrep 로컬 규칙(BG-SAST-001~004)·샘플·`sast_runner` 결과 파싱 | 완료 (Windows pytest 191 passed, 실제 Semgrep 1.182.1 스캔 확인) |
| 6 | Streamlit 대시보드(① 개요 · ② API 보안 테스트 · ③ 정적 코드 분석), 위협 모델 `docs/threat_model.md` | 완료 (Windows pytest 210 passed) — ④ 개선 비교·보고서 탭은 DAY 7 |
| 7 | 수정 전후 비교(FAIL→PASS 집계), 탐지 DET-01, SAST↔동적 비교표, 진단 보고서, CI 게이트 | 예정 |
| 8 | 안정화·문서·시연 | 예정 |

## 준비물

- Python 3.12 (3.11도 가능 목표)
- Git
- Semgrep CE 1.182.1 — **앱과 별도 가상환경**에 설치 (아래 "의존성 분리 이유" 참고)

## 설치 — Windows PowerShell (✅ 2026-10-28 Windows 11 + Python 3.12.10에서 실행 확인)

확인한 범위: `pytest -q` 9 passed, uvicorn `/health`·`/docs` 200, Streamlit 응답 200, `semgrep --version` 1.182.1.
Semgrep 규칙 스캔은 규칙 파일 작성(DAY 5) 이후 검증합니다. Streamlit은 HTTP 응답까지만 확인했습니다.

```powershell
cd C:\Users\aicam\vibe\bankguard
py -0p                                   # 설치된 Python 목록 확인 후 3.12 사용
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# Semgrep 전용 가상환경 (앱과 분리)
py -3.12 -m venv .venv-semgrep
.\.venv-semgrep\Scripts\python.exe -m pip install -r requirements-sast.txt
.\.venv-semgrep\Scripts\semgrep.exe --version
```

`Activate.ps1`이 실행 정책 때문에 막히면 정책을 바꾸지 말고 위처럼 `.\.venv\Scripts\python.exe`를 직접 호출하세요.
Windows 네이티브 Semgrep 설치가 실패하면 WSL 또는 Docker로 대체합니다(결과를 임의로 만들지 않음).

**Windows 주의 — 스마트 앱 컨트롤(SAC):** SAC가 켜져 있으면 서명되지 않은 `semgrep.exe`가
"애플리케이션 제어 정책에서 차단" 오류로 실행되지 않습니다(설치 자체는 성공). 이 PC에서는 코드 무결성 이벤트 3077/3033으로 확인했습니다.
Windows 보안 → 앱 및 브라우저 컨트롤 → 스마트 앱 컨트롤 설정에서 끄면 해결되며, 한 번 끄면 되돌릴 수 없으니 본인 PC에서만 판단하세요.
`python -m semgrep`은 안내 문구만 출력하므로 우회 수단이 아닙니다.

## 설치 — Linux / WSL / macOS (✅ 2026-10-27 Ubuntu 22.04 + Python 3.12.15에서 실행 확인)

```bash
cd bankguard
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
python3.12 -m venv .venv-semgrep
.venv-semgrep/bin/python -m pip install -r requirements-sast.txt
```

## 실행

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

### 정적 분석(Semgrep) 직접 실행

앱은 `scanners/sast_runner.py`가 고정된 대상 3곳(`fixtures/code`, `backend/services/insecure_lab.py`,
`backend/`)을 스캔합니다. 같은 명령을 손으로 실행해 볼 수도 있습니다.

```powershell
$env:PYTHONUTF8 = "1"   # ⚠️ 한국어 Windows 필수 (아래 설명)
.\.venv-semgrep\Scripts\semgrep.exe scan --config rules/bankguard.yml --metrics=off --disable-version-check fixtures/code
```

> **Windows 주의 — 인코딩:** 규칙 파일(`rules/bankguard.yml`)의 설명과 메시지는 UTF-8 한글입니다. 한국어 Windows는 기본
> 인코딩이 cp949라서 `PYTHONUTF8=1` 없이 실행하면 Semgrep이 규칙 파일을 읽다 `UnicodeDecodeError`로 종료합니다
> (종료 코드 2, `--quiet`를 쓰면 메시지도 안 보입니다). `sast_runner`는 자식 프로세스에 이 값을 자동으로 설정합니다.

Semgrep 결과는 **검토가 필요한 의심 항목**이지 확정 취약점이 아닙니다. 탐지 0건은 "그 규칙의 패턴을 찾지 못했다"는 뜻이며
코드가 안전하다는 보증이 아닙니다. 특히 소유권 검사 누락, 경쟁 조건, 멱등성 같은 **업무 로직 결함은 이 규칙으로 탐지하지
못합니다**(실행 기반 시나리오가 담당).

## 의존성 분리 이유 (2026-10-27 실제 확인)

`semgrep 1.182.1`은 `opentelemetry-api==1.37.x`를 고정하고 `fastapi 0.162.0`은 `opentelemetry-api>=1.44.0`을 요구해
같은 가상환경에서 충돌합니다. 함께 설치하면 pip/uv가 semgrep을 1.79.0(구버전)으로 내려 설치합니다.
BankGuard는 Semgrep을 `subprocess`(리스트 인자, `shell=False`)로 CLI만 호출하므로 환경을 분리해도 기능 손실이 없습니다.

## 폴더 구조 (DAY 1 시점)

```text
bankguard/
├─ backend/        # FastAPI (main.py=안전 모드 공개 진입점, factory.py=create_app)
├─ frontend/       # Streamlit 대시보드
├─ scanners/       # (DAY 3~5) API 시나리오 실행기, Semgrep 실행기
├─ rules/          # (DAY 5) Semgrep 로컬 규칙
├─ fixtures/code/  # (DAY 5) 정적분석 샘플 코드
├─ tests/          # pytest
├─ artifacts/      # 실행 산출물 (git 제외)
└─ docs/           # 문서
```

## 검증 기록

| 날짜 | 환경 | 명령 | 결과 |
|---|---|---|---|
| 2026-10-27 | Ubuntu 22.04 VM, Python 3.12.15 | `python -m pytest -q` | 9 passed, 1 warning |
| 2026-10-27 | 동일 | uvicorn 실행 후 `GET /health`, `GET /docs` | 200 / 200 |
| 2026-10-27 | 동일 | streamlit 실행 후 `/_stcore/health`, `/` | 200 / 200 |
| 2026-10-28 | Windows 11, Python 3.12.10, Semgrep 1.182.1 | `.\.venv\Scripts\python.exe -m pytest -q` | 191 passed, 1 warning |
| 2026-10-28 | 동일 | `sast_runner.run_sast()` (실제 Semgrep) | fixtures 17건 · insecure_lab 1건 · backend(lab 제외) 0건, SCAN_ERROR 0 |
| 2026-10-28 | 동일 | `.\.venv\Scripts\python.exe -m pytest -q` (대시보드 AppTest 포함) | 210 passed, 1 warning |
| 2026-10-28 | 동일 | `streamlit run frontend/app.py` 후 `/_stcore/health`, `/` | 200 / 200 (화면 육안 확인은 사용자 확인 필요) |
| 2026-10-27 | 동일 | `semgrep --version` | 1.182.1 |
| — | Windows 10 PowerShell | 위 전체 | **미검증** |

## 제한사항

- 실제 은행 인증·규제·운영 환경과 다르며, 정의된 테스트와 SAST 규칙 범위만 검증합니다.
- `X-Demo-Token`은 학습용 가상 사용자 식별일 뿐 실제 인증 체계가 아닙니다(DAY 2부터).
