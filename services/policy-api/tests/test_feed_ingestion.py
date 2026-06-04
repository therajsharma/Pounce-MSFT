from __future__ import annotations

from unittest import mock

from pounce_sentinel import storage
from pounce_sentinel.feed_ingestion import (
    github_malware_items_since,
    normalize_osv_advisory,
    on_demand_osv_items,
    osv_malware_items_since,
    parse_link_header,
)
from pounce_sentinel.feed_sync import sync_public_intelligence


def test_parse_link_header_extracts_next_url() -> None:
    links = parse_link_header('<https://api.github.com/advisories?after=cursor-2>; rel="next"')

    assert links["next"].endswith("after=cursor-2")


def test_github_malware_ingestion_uses_modified_filter_and_pagination() -> None:
    first_headers = {"Link": '<https://api.github.com/advisories?after=cursor-2>; rel="next"'}
    first_page = [
        {
            "ghsa_id": "GHSA-first",
            "type": "malware",
            "summary": "Malware package.",
            "description": "Calls https://evil.example/install.sh.",
            "published_at": "2026-06-01T00:00:00Z",
            "updated_at": "2026-06-02T00:00:00Z",
            "references": ["https://github.com/advisories/GHSA-first"],
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "demo"}, "vulnerable_version_range": "=1.2.3"}
            ],
        }
    ]
    second_page = [
        {
            "ghsa_id": "GHSA-second",
            "type": "malware",
            "summary": "Withdrawn malware package.",
            "description": "Contact 203.0.113.4.",
            "published_at": "2026-06-03T00:00:00Z",
            "updated_at": "2026-06-04T00:00:00Z",
            "withdrawn_at": "2026-06-05T00:00:00Z",
            "references": ["https://github.com/advisories/GHSA-second"],
            "vulnerabilities": [
                {"package": {"ecosystem": "npm", "name": "demo-two"}, "vulnerable_version_range": "<2.0.0"}
            ],
        }
    ]
    calls: list[str] = []

    def fake_request_json(url: str, **_kwargs: object) -> tuple[object, dict[str, str]]:
        calls.append(url)
        if len(calls) == 1:
            return first_page, first_headers
        return second_page, {}

    with mock.patch("pounce_sentinel.feed_ingestion.request_json", side_effect=fake_request_json):
        items, source = github_malware_items_since("2026-05-31T00:00:00Z")

    assert "modified=%3E%3D2026-05-31T00%3A00%3A00Z" in calls[0]
    assert calls[1].endswith("after=cursor-2")
    assert source["last_modified"] == "2026-06-04T00:00:00Z"
    assert any(item["match"]["type"] == "package_exact" for item in items)
    assert any(item.get("revoked_at") == "2026-06-05T00:00:00Z" for item in items)


def test_osv_malware_sync_reads_modified_id_csv_and_expands_malware_ids() -> None:
    csv_payload = "\n".join(
        [
            "2026-06-04T00:00:00Z,https://osv.dev/vulnerability/MAL-2026-1",
            "2026-06-03T00:00:00Z,https://osv.dev/vulnerability/GHSA-non-malware",
        ]
    )
    advisory = {
        "id": "MAL-2026-1",
        "summary": "Known bad package.",
        "published": "2026-06-01T00:00:00Z",
        "modified": "2026-06-04T00:00:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.2.3"]}],
    }

    with mock.patch("pounce_sentinel.feed_ingestion.request_text", return_value=(csv_payload, {})), mock.patch(
        "pounce_sentinel.feed_ingestion.osv_vuln",
        return_value=advisory,
    ):
        items, source = osv_malware_items_since(None)

    assert source["last_modified"] == "2026-06-04T00:00:00Z"
    assert items[0]["id"].startswith("MAL-2026-1:npm:demo")
    assert items[0]["action"] == "block"


def test_on_demand_osv_items_normalizes_malware_as_block_and_vulnerabilities_as_warn() -> None:
    malware = {
        "id": "MAL-2026-1",
        "summary": "Known bad package.",
        "published": "2026-06-01T00:00:00Z",
        "modified": "2026-06-04T00:00:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.2.3"]}],
    }
    vulnerability = {
        "id": "GHSA-demo",
        "summary": "Regular vulnerability.",
        "published": "2026-06-01T00:00:00Z",
        "modified": "2026-06-04T00:00:00Z",
        "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.2.3"]}],
    }

    with mock.patch("pounce_sentinel.feed_ingestion.request_json", return_value=({"results": [{"vulns": [{"id": "MAL-2026-1"}, {"id": "GHSA-demo"}]}]}, {})), mock.patch(
        "pounce_sentinel.feed_ingestion.osv_vuln",
        side_effect=[malware, vulnerability],
    ):
        items = on_demand_osv_items("npm", "demo", "1.2.3")

    actions = {item["id"].split(":", 1)[0]: item["action"] for item in items if item["match"]["type"] == "package_exact"}
    assert actions["MAL-2026-1"] == "block"
    assert actions["GHSA-demo"] == "warn"


def test_normalize_osv_advisory_adds_url_indicators() -> None:
    advisory = {
        "id": "MAL-2026-1",
        "summary": "Known bad package.",
        "details": "Downloads https://evil.example/install.sh.",
        "affected": [{"package": {"ecosystem": "npm", "name": "demo"}, "versions": ["1.2.3"]}],
    }

    items = normalize_osv_advisory(advisory, observed_at="2026-06-04T00:00:00Z", action="block")

    assert any(item["match"]["type"] == "url" for item in items)


def test_sync_public_intelligence_persists_feed_and_source_checkpoints(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    github_item = _item("github-1")
    osv_item = _item("osv-1")

    with mock.patch(
        "pounce_sentinel.feed_sync.github_malware_items_since",
        return_value=([github_item], {"name": "github_advisory", "status": "ok", "last_modified": "2026-06-04T00:00:00Z", "item_count": 1}),
    ), mock.patch(
        "pounce_sentinel.feed_sync.osv_malware_items_since",
        return_value=([osv_item], {"name": "osv", "status": "ok", "last_modified": "2026-06-04T00:00:00Z", "item_count": 1}),
    ):
        feed = sync_public_intelligence()

    state = storage.read_feed_state()
    assert feed["items"]
    assert state is not None
    assert state["syncState"]["sources"]["github_advisory"]["last_modified"] == "2026-06-04T00:00:00Z"
    assert state["lastSync"]["status"] == "ok"


def _item(item_id: str) -> dict[str, object]:
    return {
        "id": item_id,
        "kind": "malicious_package",
        "match": {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.2.3"},
        "action": "block",
        "confidence": 1.0,
        "reason": "Known bad package.",
        "source": "test",
        "source_refs": [{"kind": "test", "id": item_id}],
        "published_at": "2026-06-01T00:00:00Z",
        "modified_at": "2026-06-04T00:00:00Z",
        "first_seen": "2026-06-04T00:00:00Z",
        "last_seen": "2026-06-04T00:00:00Z",
    }

