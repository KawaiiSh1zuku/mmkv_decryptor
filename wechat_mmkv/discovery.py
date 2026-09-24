from __future__ import annotations

import os
from pathlib import Path

from .errors import MMKVError


def default_wechat_users_root() -> Path:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        raise MMKVError("APPDATA is unavailable; pass --wechat-users-root or --app-dir")
    return Path(appdata) / "Tencent" / "xwechat" / "radium" / "users"


def validate_store_id(store_id: str) -> str:
    value = store_id.strip()
    if not value:
        raise MMKVError("store ID must not be empty")
    if value in {".", ".."} or "\0" in value:
        raise MMKVError("store ID must be a file name, not a path")
    if any(separator in value for separator in ("/", "\\")):
        raise MMKVError("store ID must not contain path separators")
    if any(character in value for character in '<>:"|?*'):
        raise MMKVError("store ID contains unsupported file-name characters")
    return value


def validate_appid(appid: str) -> None:
    """Backward-compatible alias for callers using the old API name."""
    validate_store_id(appid)


def _store_files(path: Path, store_id: str) -> list[Path]:
    files: list[Path] = []
    for directory in path.glob("usrmmkvstorage*"):
        candidate = directory / store_id
        if directory.is_dir() and candidate.is_file():
            files.append(candidate)
    return files


def _candidate_mtime(path: Path, store_id: str) -> float:
    files = _store_files(path, store_id)
    return max((item.stat().st_mtime for item in files), default=0.0)


def locate_app_directory(
    store_id: str,
    *,
    app_dir: Path | None = None,
    wechat_users_root: Path | None = None,
) -> Path:
    store_id = validate_store_id(store_id)
    if app_dir is not None:
        selected = Path(app_dir).expanduser().resolve()
        if not selected.is_dir():
            raise MMKVError(f"app directory not found: {selected}")
        return selected

    root = Path(wechat_users_root or default_wechat_users_root()).expanduser()
    if not root.is_dir():
        raise MMKVError(f"WeChat users root not found: {root}")
    candidates: list[Path] = []
    for local_root in root.glob("*/applet/local"):
        if not local_root.is_dir():
            continue
        for path in local_root.iterdir():
            if path.is_dir() and _store_files(path, store_id):
                candidates.append(path)
    if not candidates:
        raise MMKVError(
            f"no local WeChat MMKV storage found for {store_id} under {root}"
        )
    return max(candidates, key=lambda path: _candidate_mtime(path, store_id)).resolve()
