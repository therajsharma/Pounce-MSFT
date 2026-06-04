from __future__ import annotations

from datetime import UTC, datetime
from urllib.error import HTTPError
from unittest import mock

import pytest

from pounce_sentinel import feeds


class FakeResponse:
    def __init__(self, *, chunks: list[bytes] | None = None, headers: dict[str, str] | None = None) -> None:
        self._chunks = list(chunks or [])
        self.headers = headers or {}

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        return False

    def read(self, _size: int = -1) -> bytes:
        if self._chunks:
            return self._chunks.pop(0)
        return b""


class FakeOpener:
    def __init__(self, result: object) -> None:
        self._result = result

    def open(self, *_args: object, **_kwargs: object) -> object:
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


def test_normalize_feed_artifact_promotes_legacy_package_items() -> None:
    feed = feeds.normalize_feed_artifact(
        {
            "items": [
                {
                    "id": "legacy-1",
                    "severity": "critical",
                    "reason": "Known bad package.",
                    "match": {"type": "package", "ecosystem": "npm", "name": "Demo", "version": "1.2.3"},
                }
            ]
        },
        observed_at="2026-06-04T00:00:00Z",
        default_source="seed",
    )

    item = feed["items"][0]
    assert item["match"] == {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.2.3"}
    assert item["action"] == "block"
    assert item["source"] == "seed"


def test_active_feed_items_skip_revoked_and_expired_records() -> None:
    items = [
        _feed_item("active", {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.0.0"}),
        {
            **_feed_item("revoked", {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "2.0.0"}),
            "revoked_at": "2026-06-02T00:00:00Z",
        },
        {
            **_feed_item("expired", {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "3.0.0"}),
            "expires_at": "2026-06-02T00:00:00Z",
        },
    ]

    active = feeds.active_feed_items(items, at=datetime(2026, 6, 4, tzinfo=UTC))

    assert [item["id"] for item in active] == ["active"]


def test_match_package_items_normalizes_pypi_names() -> None:
    item = _feed_item(
        "pypi-demo",
        {"type": "package_exact", "ecosystem": "pypi", "name": "demo-package", "version": "1.0.0"},
    )

    matches = feeds.match_package_items([item], "python", "Demo_Package", "1.0.0")

    assert [item["id"] for item in matches] == ["pypi-demo"]


def test_runtime_feed_prefers_remote_then_cache_then_local_then_seed(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    monkeypatch.setenv("POUNCE_FEED_STALE_AFTER_HOURS", "6")
    local_feed = _feed("local", "local-demo")
    remote_cache_feed = _feed("remote-cache", "remote-cache-demo")
    remote_live_feed = _feed("remote-live", "remote-live-demo")

    feeds.persist_feed_cache(local_feed, fetched_at="2026-06-04T00:00:00Z", fetched_from="local_sync")
    feeds.persist_feed_cache(
        remote_cache_feed,
        fetched_at="2026-06-04T00:00:00Z",
        fetched_from="https://feed.example/intel.json",
        cache_kind="remoteCache",
    )

    with mock.patch("pounce_sentinel.feeds.load_remote_feed", return_value=remote_live_feed):
        remote = feeds.runtime_feed("https://feed.example/intel.json")

    with mock.patch("pounce_sentinel.feeds.load_remote_feed", side_effect=feeds.IntelUnavailable("timeout")):
        remote_cache = feeds.runtime_feed("https://feed.example/intel.json")

    (tmp_path / "feed-state.json").write_text(
        '{"localSync": {"feed": %s, "fetched_at": "2026-06-04T00:00:00Z", "fetched_from": "local_sync"}}'
        % __import__("json").dumps(local_feed),
        encoding="utf-8",
    )
    with mock.patch("pounce_sentinel.feeds.load_remote_feed", side_effect=feeds.IntelUnavailable("timeout")):
        local = feeds.runtime_feed("https://feed.example/intel.json")

    (tmp_path / "feed-state.json").unlink()
    with mock.patch("pounce_sentinel.feeds.load_remote_feed", side_effect=feeds.IntelUnavailable("timeout")):
        seed = feeds.runtime_feed("https://feed.example/intel.json")

    assert remote["selected_from"] == "remote"
    assert remote_cache["selected_from"] == "remote_cache"
    assert local["selected_from"] == "local_sync_cache"
    assert seed["selected_from"] == "seed"
    assert any(item["code"] == "feed_refresh_failed" for item in remote_cache["warnings"])


def test_runtime_feed_warns_when_selected_feed_is_stale(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    monkeypatch.setenv("POUNCE_FEED_STALE_AFTER_HOURS", "1")
    feeds.persist_feed_cache(_feed("local", "demo"), fetched_at="2026-06-01T00:00:00Z", fetched_from="local_sync")

    with mock.patch("pounce_sentinel.feeds.now_utc", return_value=datetime(2026, 6, 4, tzinfo=UTC)):
        context = feeds.runtime_feed()

    assert context["selected_from"] == "local_sync_cache"
    assert any(item["code"] == "feed_stale" for item in context["warnings"])


def test_load_remote_feed_rejects_non_https_urls() -> None:
    with pytest.raises(feeds.IntelUnavailable, match="https URL"):
        feeds.load_remote_feed("http://feed.example/intel.json")


def test_load_remote_feed_rejects_redirects() -> None:
    redirect = HTTPError("https://feed.example/intel.json", 302, "Found", {}, None)
    with mock.patch("pounce_sentinel.feeds.build_opener", return_value=FakeOpener(redirect)):
        with pytest.raises(feeds.IntelUnavailable, match="redirects are not allowed"):
            feeds.load_remote_feed("https://feed.example/intel.json")


def test_load_remote_feed_rejects_oversized_responses() -> None:
    oversized = FakeResponse(headers={"Content-Length": str(feeds.MAX_HTTP_RESPONSE_BYTES + 1)})
    with mock.patch("pounce_sentinel.feeds.build_opener", return_value=FakeOpener(oversized)):
        with pytest.raises(feeds.IntelUnavailable, match="response limit"):
            feeds.load_remote_feed("https://feed.example/intel.json")


def test_feed_status_rows_include_dynamic_health_fields(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    feeds.persist_feed_cache(_feed("local", "demo"), fetched_at="2026-06-04T00:00:00Z", fetched_from="local_sync")

    rows = feeds.feed_status_rows(feeds.runtime_feed())

    assert rows[0]["selectedFrom"] == "local_sync_cache"
    assert rows[0]["trustState"] == "local_sync_cache"
    assert rows[0]["activeItemCount"] >= 1


def _feed(source: str, package_name: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-06-04T00:00:00Z",
        "sources": [{"name": source, "status": "ok", "item_count": 1, "synced_at": "2026-06-04T00:00:00Z"}],
        "items": [_feed_item(f"{source}:1", {"type": "package_exact", "ecosystem": "npm", "name": package_name, "version": "1.0.0"})],
    }


def _feed_item(item_id: str, match: dict[str, str]) -> dict[str, object]:
    return {
        "id": item_id,
        "kind": "malicious_package",
        "match": match,
        "action": "block",
        "confidence": 1.0,
        "reason": "Test item.",
        "source": "test",
        "source_refs": [{"kind": "test", "id": item_id}],
        "published_at": "2026-06-01T00:00:00Z",
        "modified_at": "2026-06-01T00:00:00Z",
        "first_seen": "2026-06-01T00:00:00Z",
        "last_seen": "2026-06-01T00:00:00Z",
    }

