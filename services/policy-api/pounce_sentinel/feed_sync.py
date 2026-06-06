from __future__ import annotations

from typing import Any

from pounce_sentinel import storage
from pounce_sentinel.feed_ingestion import github_malware_items_since, osv_malware_items_since
from pounce_sentinel.feeds import FEED_SCHEMA_VERSION, iso_now, normalize_feed_artifact, persist_feed_cache


def sync_public_intelligence() -> dict[str, Any]:
    state = storage.read_feed_state() or {}
    sync_state = state.get("syncState") if isinstance(state.get("syncState"), dict) else {}
    source_state = sync_state.get("sources") if isinstance(sync_state.get("sources"), dict) else {}
    existing = _existing_local_items(state)
    items_by_id = {str(item["id"]): item for item in existing if isinstance(item, dict) and item.get("id")}
    sources: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    github_state = source_state.get("github_advisory") if isinstance(source_state.get("github_advisory"), dict) else {}
    try:
        github_items, github_source = github_malware_items_since(github_state.get("last_modified"))
        for item in github_items:
            items_by_id[str(item["id"])] = item
        sources.append(github_source)
    except Exception as exc:
        sources.append({"name": "github_advisory", "status": "failed", "synced_at": iso_now(), "item_count": 0})
        warnings.append({"code": "github_advisory_sync_failed", "detail": str(exc), "selected_from": "local_sync_cache"})

    osv_state = source_state.get("osv") if isinstance(source_state.get("osv"), dict) else {}
    try:
        osv_items, osv_source = osv_malware_items_since(osv_state.get("last_modified"))
        for item in osv_items:
            items_by_id[str(item["id"])] = item
        sources.append(osv_source)
    except Exception as exc:
        sources.append({"name": "osv", "status": "failed", "synced_at": iso_now(), "item_count": 0})
        warnings.append({"code": "osv_sync_failed", "detail": str(exc), "selected_from": "local_sync_cache"})

    generated_at = iso_now()
    feed = normalize_feed_artifact(
        {
            "schema_version": FEED_SCHEMA_VERSION,
            "generated_at": generated_at,
            "sources": sources,
            "items": sorted(items_by_id.values(), key=lambda item: str(item.get("id", ""))),
        },
        observed_at=generated_at,
        default_source="local_sync_cache",
    )
    persist_feed_cache(feed, fetched_at=generated_at, fetched_from="local_sync", cache_kind="localSync")

    updated_state = storage.read_feed_state() or {}
    updated_state["syncState"] = {
        "updated_at": generated_at,
        "sources": {
            source["name"]: {"last_modified": source.get("last_modified")}
            for source in sources
            if isinstance(source, dict) and source.get("name")
        },
        "warnings": warnings,
    }
    updated_state["lastSync"] = {
        "status": "degraded" if warnings else "ok",
        "syncedAt": generated_at,
        "warnings": warnings,
        "itemCount": len(feed.get("items", [])),
    }
    storage.write_feed_state(updated_state)
    return feed


def _existing_local_items(state: dict[str, Any]) -> list[dict[str, Any]]:
    local_sync = state.get("localSync") if isinstance(state.get("localSync"), dict) else {}
    feed = local_sync.get("feed") if isinstance(local_sync.get("feed"), dict) else {}
    items = feed.get("items") if isinstance(feed.get("items"), list) else []
    return [item for item in items if isinstance(item, dict)]

