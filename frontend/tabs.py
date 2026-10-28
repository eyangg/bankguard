"""대시보드 탭 렌더링. 표시하는 모든 결과는 세션에 저장된 '실제 실행 결과'뿐이며, 예시 PASS/FAIL을 넣지 않는다."""
from __future__ import annotations

import logging

import streamlit as st

from backend.config import API_BASE_URL
from backend.seed import SEED_ACCOUNTS, SEED_USERS
from frontend import helpers, services
from scanners import sast_runner

logger = logging.getLogger("bankguard.frontend")

NOT_RUN = "아직 검사를 실행하지 않았습니다."


def init_state() -> None:
    st.session_state.setdefault("api_results", {})  # {"secure": 결과 dict, "vulnerable": 결과 dict}
    st.session_state.setdefault("sast_run", None)


# ============================================================================================
# 사이드바
# ============================================================================================

def render_sidebar() -> None:
    with st.sidebar:
        st.header("BankGuard")
        st.caption("로컬 전용 · 허구의 더미 데이터")
        ok, message = _api_health()
        st.subheader("가상 은행 API 서버")
        if ok:
            st.success(message)
        else:
            st.warning(message)
            st.caption(
                "검사 버튼은 API 서버 없이도 동작합니다(인프로세스 격리 실행). "
                "서버 계좌 현황을 보려면 터미널에서 아래 명령을 실행하세요."
            )
            st.code(
                ".\\.venv\\Scripts\\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000",
                language="powershell",
            )
        with st.expander("결과 상태 읽는 법", expanded=False):
            st.markdown(
                "- **통과(PASS)**: 사전에 정한 안전한 동작을 지켰다.\n"
                "- **취약 동작 확인(FAIL)**: 안전 조건을 위반하는 동작이 실제로 관측됐다.\n"
                "- **검사 불능(ERROR)**: 서버 오류·도구 실패·사전 대조 실패로 안전성 판단 자체가 불가능하다. "
                "FAIL(보안 위반)과 다르다.\n"
                "- **미실행**: 아직 실행하지 않았다."
            )


def _api_health() -> tuple[bool, str]:
    import httpx

    try:
        resp = httpx.get(f"{API_BASE_URL}/health", timeout=1.5)
    except httpx.HTTPError:
        return False, "연결할 수 없음 (꺼져 있음)"
    if resp.status_code == 200 and resp.json().get("status") == "ok":
        return True, f"정상 응답 (HTTP {resp.status_code})"
    return False, f"예상과 다른 응답 (HTTP {resp.status_code})"


# ============================================================================================
# ① 개요
# ============================================================================================

def render_overview() -> None:
    st.subheader("프로젝트 소개")
    st.markdown(
        "**BankGuard는 가상의 은행 계좌·송금 API를 대상으로 보안 시나리오를 자동 실행하고, "
        "Python 소스코드를 Semgrep으로 정적 분석해 위험 사항과 수정 전후 검증 결과를 한 화면에서 보여주는 "
        "로컬 보안 점검 플랫폼입니다.**"
    )
    st.markdown(
        "금융권 IT 보안·애플리케이션 보안 업무의 흐름 — **진단 → 조치 → 이행점검** — 을 작게 재현합니다. "
        "송금 API의 접근제어·입력검증·동시성·멱등성을 *실행으로* 검증하고(동적 테스트), "
        "코드의 위험 패턴을 *읽어서* 찾으며(정적 분석), 두 방법이 각각 무엇을 잡고 놓치는지 비교합니다."
    )
    st.warning(
        "로컬 학습·포트폴리오용 실습 환경입니다. 실제 금융 서비스가 아니며 모든 사용자·계좌·토큰은 허구의 더미 데이터입니다. "
        "취약 버전은 인터넷에 열지 않고, 격리된 임시 DB와 인프로세스 테스트 클라이언트 안에서만 실행합니다."
    )

    st.subheader("가상 고객과 계좌")
    live = services.fetch_live_accounts()
    rows = _account_rows(live)
    st.dataframe(rows, hide_index=True, width="stretch")
    if live is None:
        st.caption(
            "API 서버가 꺼져 있어 **시드(초기) 값**을 표시합니다. 서버를 켜면 실시간 잔액으로 바뀝니다."
        )
    else:
        st.caption("실행 중인 로컬 API 서버(안전 모드)에서 방금 조회한 **실시간 잔액**입니다.")

    st.subheader("최근 검사 실행 요약")
    api_results = st.session_state["api_results"]
    sast_run = st.session_state["sast_run"]
    if not api_results and sast_run is None:
        st.info(NOT_RUN)
        return
    columns = st.columns(3)
    for column, mode in zip(columns[:2], ("vulnerable", "secure")):
        with column:
            st.markdown(f"**API 보안 테스트 · {helpers.MODE_LABELS[mode]}**")
            result = api_results.get(mode)
            if result is None:
                st.caption("미실행")
                continue
            counts = helpers.summarize(helpers.tier_items(result["items"], "core"))
            sub = st.columns(4)
            sub[0].metric("핵심", counts["total"])
            sub[1].metric("통과", counts["PASS"])
            sub[2].metric("취약", counts["FAIL"])
            sub[3].metric("오류", counts["ERROR"])
            st.caption(f"실행 {helpers.format_kst(result['run_at'])}")
    with columns[2]:
        st.markdown("**정적 분석 · Semgrep**")
        if sast_run is None:
            st.caption("미실행")
        else:
            sub = st.columns(2)
            sub[0].metric("탐지(검토 필요)", sast_run["total_findings"])
            sub[1].metric("스캔 오류", sast_run["scan_errors"])
            st.caption(f"실행 {helpers.format_kst(sast_run['run_at'])}")


def _account_rows(live: dict[int, list[dict]] | None) -> list[dict]:
    rows = []
    accounts_by_owner = {}
    for account in SEED_ACCOUNTS:
        accounts_by_owner.setdefault(account.owner_user_id, []).append(account)
    for user in SEED_USERS:
        role = "운영자" if user.role == "admin" else "고객"
        if user.role == "admin":
            rows.append({"이름": user.display_name, "역할": role, "계좌 ID": "-", "계좌번호": "계좌 없음",  # 열 타입을 문자열로 통일
                         "잔액": "-", "기준": "-"})
            continue
        if live is not None:
            for account in live.get(user.user_id, []):
                rows.append({"이름": user.display_name, "역할": role, "계좌 ID": str(account["id"]),
                             "계좌번호": account["account_no"],
                             "잔액": helpers.format_krw(account["balance_krw"]), "기준": "실시간(API)"})
        else:
            for account in accounts_by_owner.get(user.user_id, []):
                rows.append({"이름": user.display_name, "역할": role, "계좌 ID": str(account.account_id),
                             "계좌번호": account.account_no,
                             "잔액": helpers.format_krw(account.balance_krw), "기준": "시드 초기값"})
    return rows


# ============================================================================================
# ② API 보안 테스트
# ============================================================================================

def render_api_tab() -> None:
    st.subheader("API 보안 시나리오 실행")
    st.caption(
        "각 시나리오는 독립된 임시 DB와 새 앱에서 실제 요청을 보내고, **응답 코드와 DB 상태**로 판정합니다. "
        "정상 사용이 되는지 먼저 확인하는 양성 대조가 깨지면 PASS/FAIL이 아니라 ERROR로 표시합니다."
    )
    label = st.radio("실행 모드", list(helpers.MODE_LABELS.values()), horizontal=True, key="api_mode")
    mode = next(key for key, value in helpers.MODE_LABELS.items() if value == label)
    if mode == "vulnerable":
        st.warning(
            "취약 버전은 시나리오마다 결함 **하나**만 붙인 앱을 임시 폴더의 새 DB로 만들어 **인프로세스**에서만 실행합니다. "
            "네트워크에 열리지 않습니다."
        )

    if st.button("보안 시나리오 실행", type="primary", key="run_api"):
        _run_api(mode)

    result = st.session_state["api_results"].get(mode)
    if result is None:
        st.info(f"{NOT_RUN} (**{label}** 미실행)")
        return
    _render_api_result(result)


def _run_api(mode: str) -> None:
    progress = st.progress(0.0, text="검사 준비 중...")

    def on_progress(done: int, total: int, name: str) -> None:
        text = "검사 완료" if name == "완료" else f"검사 중 ({done + 1}/{total}): {name}"
        progress.progress(done / total, text=text)

    try:
        st.session_state["api_results"][mode] = services.run_api_checks(mode, on_progress)
    except Exception:  # 상세 예외(경로 등)는 화면에 내지 않고 콘솔 로그에 남긴다
        logger.exception("API 보안 시나리오 실행 실패")
        st.session_state["api_results"].pop(mode, None)
        st.error("검사를 실행하지 못했습니다(ERROR). 터미널 로그를 확인하세요. 이 상태는 보안 위반(FAIL)이 아닙니다.")
    finally:
        progress.empty()


def _render_api_result(result: dict) -> None:
    st.caption(
        f"{helpers.MODE_LABELS[result['mode']]} · 실행 {helpers.format_kst(result['run_at'])} · "
        f"소요 {result['duration_sec']}초 · 실행 ID {result['run_id'][:8]}"
    )
    core = helpers.tier_items(result["items"], "core")
    detail = helpers.tier_items(result["items"], "detail")

    st.markdown("#### 핵심 시나리오")
    counts = helpers.summarize(core)
    cols = st.columns(4)
    cols[0].metric("핵심 검사", counts["total"])
    cols[1].metric("보안 기준 통과", counts["PASS"])
    cols[2].metric("취약 동작 확인", counts["FAIL"])
    cols[3].metric("검사 불능(ERROR)", counts["ERROR"])
    for item in core:
        _render_item(item)

    if detail:
        st.markdown("#### 세부 테스트")
        st.caption("명세 v1.2에 따라 핵심 집계에서 제외하고 세부 테스트로 표시합니다.")
        for item in detail:
            _render_item(item)


def _render_item(item: dict) -> None:
    title = f"{item['id']} · {item['name']} — {helpers.colored_status(item['status'])}"
    with st.expander(title, expanded=item["status"] in ("FAIL", "ERROR")):
        if item["status"] == "PASS":
            st.success(f"**관측:** {item['observed']}")
        elif item["status"] == "FAIL":
            st.error(f"**관측:** {item['observed']}")
        elif item["status"] == "ERROR":
            st.warning(
                f"**관측:** {item['observed']}\n\n"
                "이 항목은 검사 자체가 불가능했다는 뜻이며 **보안 위반(FAIL)이 아닙니다.**"
            )
        else:
            st.info(f"**관측:** {item['observed']}")
        st.markdown(f"**위험도:** {helpers.risk_text(item['risk'], item['likelihood'], item['impact'])}")
        st.markdown(f"**검사 목적:** {item['description']}")
        st.markdown(f"**안전 기준(기대):** {item['expected']}")
        st.markdown(f"**실제 근거:** {item['evidence']}")
        st.markdown(f"**해결 방법:** {item['fix_guide']}")
        mapping = " · ".join(v for v in (item["owasp"], item["cwe"]) if v)
        st.caption(f"매핑: {mapping}" if mapping else "매핑: 해당 OWASP 항목 없음 / 원문 확인 전")


# ============================================================================================
# ③ 정적 코드 분석
# ============================================================================================

def render_sast_tab() -> None:
    st.subheader("Semgrep 정적 코드 분석")
    st.caption(
        "소스를 실행하지 않고 위험한 코드 **패턴**을 찾습니다. 결과는 확정 취약점이 아니라 "
        "**검토가 필요한 의심 항목**입니다. 소유권 검사 누락·경쟁 조건·중복 송금 같은 업무 로직 결함은 "
        "이 규칙으로 탐지하지 않으며, 그 영역은 ②탭의 실행 기반 시나리오가 담당합니다."
    )
    targets = [t.name for t in sast_runner.TARGETS]
    st.markdown("**검사 대상(고정):** " + " · ".join(f"`{name}`" for name in targets))

    if st.button("Semgrep 정적 분석 실행", type="primary", key="run_sast"):
        _run_sast()

    run = st.session_state["sast_run"]
    if run is None:
        st.info(f"{NOT_RUN} (정적 분석 미실행)")
        return
    _render_sast_result(run)


def _run_sast() -> None:
    try:
        with st.spinner("Semgrep 실행 중... (대상 3곳, 수 초~수십 초)"):
            st.session_state["sast_run"] = services.run_static_analysis()
    except Exception:
        logger.exception("정적 분석 실행 실패")
        st.session_state["sast_run"] = None
        st.error("정적 분석을 실행하지 못했습니다(SCAN_ERROR). 터미널 로그를 확인하세요.")


def _render_sast_result(run: dict) -> None:
    st.caption(
        f"실행 {helpers.format_kst(run['run_at'])} · 소요 {run['duration_sec']}초 · "
        f"Semgrep {run['semgrep_version'] or '버전 불명'} · 실행 파일 출처: {run['semgrep_bin_source']}"
    )
    cols = st.columns(3)
    cols[0].metric("적용 규칙", run["rules_count"])
    cols[1].metric("탐지(검토 필요)", run["total_findings"])
    cols[2].metric("스캔 오류(SCAN_ERROR)", run["scan_errors"])

    with st.expander(f"규칙 {run['rules_count']}개 설명", expanded=False):
        for rule in run["catalog"]:
            st.markdown(f"**{rule['rule_id']}** · {rule['severity']} · {', '.join(rule['cwe'])}")
            st.caption(rule["message"])

    for target in run["targets"]:
        _render_sast_target(target, run["rule_ids"])


def _render_sast_target(target: dict, rule_ids: list[str]) -> None:
    st.markdown(f"#### {target['target']}")
    if target["scan_status"] == sast_runner.SCAN_ERROR:
        st.error(f"**스캔 오류(SCAN_ERROR · {target['error_kind']})** — {target['error_message']}")
        st.caption("스캔이 실패한 것이지 '탐지 0건'이 아닙니다. 가짜 결과는 표시하지 않습니다.")
        return

    st.caption(f"스캔 파일 {len(target['files_scanned'])}개 · 탐지 {target['finding_count']}건")
    if target["finding_count"] == 0:
        st.info(
            "0 findings — 이 규칙들의 패턴을 찾지 못했다는 뜻이며, 코드 전체가 안전하다는 보증이 아닙니다."
        )
    else:
        st.dataframe(helpers.finding_rows(target), hide_index=True, width="stretch")

    if target["target"] == "fixtures/code" and len(target["files_scanned"]) > 1:
        st.markdown("**취약 샘플 ↔ 수정 샘플 비교** (규칙 × 파일)")
        matrix = sast_runner.rule_matrix(target, rule_ids)
        st.dataframe(helpers.matrix_table(matrix), hide_index=True, width="stretch")
        st.caption("미탐지(패턴 없음) = 그 규칙의 패턴을 찾지 못했다는 뜻이지 코드가 안전하다는 보증이 아닙니다.")


# ============================================================================================
# ④ 수정 전후 비교 / 보고서
# ============================================================================================

def render_compare_tab() -> None:
    st.subheader("수정 전후 비교 · 보고서")
    st.info(
        "이 탭은 **DAY 7에 구현 예정**입니다 (취약↔안전 FAIL→PASS 집계, SAST↔동적 테스트 비교표, 진단 보고서 내려받기). "
        "아직 실행하지 않은 비교 결과를 미리 보여 주지 않습니다."
    )
    st.markdown(
        "지금도 **②탭**에서 `취약 버전`과 `안전 버전`을 각각 실행해 같은 시나리오의 결과를 직접 비교해 볼 수 있습니다."
    )
