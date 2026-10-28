"""검사 실행 결과를 artifacts/ 폴더에 JSON으로 저장·읽기 (명세 8.6, 11장).

- artifacts/는 git 제외 대상(.gitignore)이며 실제 실행에서만 생성된다.
- 저장은 '가장 최근 결과' 한 벌(latest_*.json)만 유지한다. 과거 결과와 비교하는 기능은 P1이다.
- 대시보드는 시작할 때 이 파일을 자동으로 읽어 화면에 채우지 않는다(이전 PASS를 현재 결과로 오인하지 않도록).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from backend.config import PROJECT_ROOT

ARTIFACTS_DIR = PROJECT_ROOT / "artifacts"
ENV_DIR = "BANKGUARD_ARTIFACTS_DIR"  # 테스트가 사용자의 실제 결과 파일을 덮어쓰지 않도록 저장 위치를 바꾸는 설정
KINDS = ("api_vulnerable", "api_secure", "sast", "det01")


def default_dir() -> Path:
    configured = os.environ.get(ENV_DIR)
    return Path(configured) if configured else ARTIFACTS_DIR


def _path(kind: str, directory: Path) -> Path:
    if kind not in KINDS:
        raise ValueError(f"알 수 없는 결과 종류입니다: {kind!r}")
    return directory / f"latest_{kind}.json"


def save_json(kind: str, data: dict, directory: Path | None = None) -> Path:
    directory = directory or default_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = _path(kind, directory)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def load_json(kind: str, directory: Path | None = None) -> dict | None:
    path = _path(kind, directory or default_dir())
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def save_text(name: str, text: str, directory: Path | None = None) -> Path:
    if "/" in name or "\\" in name or name.startswith("."):
        raise ValueError("파일 이름에 경로를 쓸 수 없습니다.")
    directory = directory or default_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def load_bundle(directory: Path | None = None) -> dict:
    """저장된 최근 결과를 모아 보고서 입력(bundle)으로 만든다. 없는 종류는 None."""
    return {kind: load_json(kind, directory) for kind in KINDS}
