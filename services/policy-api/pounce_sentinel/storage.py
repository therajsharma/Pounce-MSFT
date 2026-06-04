from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pounce_sentinel import cosmos_storage


def audit_path() -> Path:
    return Path(os.getenv("POUNCE_SENTINEL_AUDIT_PATH", ".pounce-sentinel/verdicts.jsonl"))


def feed_state_path() -> Path:
    return Path(os.getenv("POUNCE_SENTINEL_FEED_STATE_PATH", ".pounce-sentinel/feed-state.json"))


def storage_backend() -> str:
    return "cosmos" if cosmos_storage.is_configured() else "local-file"


def append_verdict(verdict: dict[str, Any]) -> None:
    if cosmos_storage.is_configured():
        cosmos_storage.append_verdict(verdict)
        return

    _append_jsonl(verdict)


def append_exception(exception: dict[str, Any]) -> None:
    if cosmos_storage.is_configured():
        cosmos_storage.append_exception(exception)
        return

    _append_jsonl(exception)


def list_recent_verdicts(limit: int = 50) -> list[dict[str, Any]]:
    if cosmos_storage.is_configured():
        return cosmos_storage.list_recent_verdicts(limit)

    return _list_recent_jsonl(limit)


def read_feed_state() -> dict[str, Any] | None:
    if cosmos_storage.is_configured():
        return cosmos_storage.read_feed_state()

    path = feed_state_path()
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def write_feed_state(state: dict[str, Any]) -> None:
    if cosmos_storage.is_configured():
        cosmos_storage.write_feed_state(state)
        return

    path = feed_state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _append_jsonl(record: dict[str, Any]) -> None:
    path = audit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True))
        handle.write("\n")


def _list_recent_jsonl(limit: int = 50) -> list[dict[str, Any]]:
    path = audit_path()
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records[-limit:]
