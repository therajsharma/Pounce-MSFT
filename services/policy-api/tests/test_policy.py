from __future__ import annotations

from unittest import mock

from pounce_sentinel.feeds import IntelUnavailable, persist_feed_cache
from pounce_sentinel.policy import vet_package


def test_blocks_seeded_malicious_dependency() -> None:
    result = vet_package(
        {
            "ecosystem": "npm",
            "packageName": "event-stream",
            "version": "3.3.7",
            "source": "github",
            "repository": "org/agent-service",
            "actor": "github-actions",
        }
    )

    assert result["verdict"] == "block"
    assert result["riskScore"] == 92
    assert "Known malicious package" in result["reasons"]


def test_blocks_installable_demo_dependency() -> None:
    result = vet_package(
        {
            "ecosystem": "npm",
            "packageName": "left-pad",
            "version": "1.3.0",
            "source": "github",
            "repository": "org/agent-service",
            "actor": "github-actions",
        }
    )

    assert result["verdict"] == "block"
    assert result["policyId"] == "supply-chain-demo-block"


def test_warns_on_floating_version() -> None:
    result = vet_package(
        {
            "ecosystem": "npm",
            "packageName": "lodash",
            "version": "^4.17.0",
        }
    )

    assert result["verdict"] == "warn"
    assert result["policyId"] == "exact-version-required"
    assert result["recommendedVersion"] == "4.17.21"


def test_allows_safe_exact_dependency() -> None:
    result = vet_package(
        {
            "ecosystem": "npm",
            "packageName": "lodash",
            "version": "4.17.21",
        }
    )

    assert result["verdict"] == "allow"
    assert result["riskScore"] == 12


def test_blocks_normalized_feed_match(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    persist_feed_cache(
        {
            "schema_version": "1.0",
            "generated_at": "2026-06-04T00:00:00Z",
            "sources": [{"name": "osv", "status": "ok", "item_count": 1}],
            "items": [
                {
                    "id": "MAL-2026-1:npm:demo:package_exact:1.2.3",
                    "kind": "malicious_package",
                    "match": {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.2.3"},
                    "action": "block",
                    "confidence": 1.0,
                    "reason": "Known malicious package.",
                    "source": "osv",
                    "source_refs": [{"kind": "osv", "id": "MAL-2026-1", "url": "https://osv.dev/vulnerability/MAL-2026-1"}],
                    "published_at": "2026-06-01T00:00:00Z",
                    "modified_at": "2026-06-04T00:00:00Z",
                    "first_seen": "2026-06-04T00:00:00Z",
                    "last_seen": "2026-06-04T00:00:00Z",
                }
            ],
        },
        fetched_at="2026-06-04T00:00:00Z",
        fetched_from="local_sync",
    )

    result = vet_package({"ecosystem": "npm", "packageName": "demo", "version": "1.2.3"})

    assert result["verdict"] == "block"
    assert result["policyId"] == "threat-intel-feed-block"
    assert result["evidence"][0]["source"] == "osv"


def test_warns_on_normalized_policy_feed_match(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    persist_feed_cache(
        {
            "schema_version": "1.0",
            "generated_at": "2026-06-04T00:00:00Z",
            "sources": [{"name": "sbom-policy", "status": "ok", "item_count": 1}],
            "items": [
                {
                    "id": "sbom-policy:npm:demo:1.2.3",
                    "kind": "sbom_policy",
                    "match": {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.2.3"},
                    "action": "warn",
                    "confidence": 0.8,
                    "reason": "Package is disallowed by organization SBOM policy.",
                    "source": "sbom_policy",
                    "source_refs": [{"kind": "policy", "id": "restricted-components"}],
                    "published_at": "2026-06-01T00:00:00Z",
                    "modified_at": "2026-06-04T00:00:00Z",
                    "first_seen": "2026-06-04T00:00:00Z",
                    "last_seen": "2026-06-04T00:00:00Z",
                }
            ],
        },
        fetched_at="2026-06-04T00:00:00Z",
        fetched_from="local_sync",
    )

    result = vet_package({"ecosystem": "npm", "packageName": "demo", "version": "1.2.3"})

    assert result["verdict"] == "warn"
    assert result["policyId"] == "threat-intel-feed-warning"


def test_on_demand_osv_malware_blocks_when_live_lookup_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    monkeypatch.setenv("POUNCE_ENABLE_LIVE_LOOKUPS", "true")
    malicious_item = {
        "id": "MAL-2026-1:npm:demo:package_exact:1.2.3",
        "kind": "malicious_package",
        "match": {"type": "package_exact", "ecosystem": "npm", "name": "demo", "version": "1.2.3"},
        "action": "block",
        "confidence": 1.0,
        "reason": "Known malicious package.",
        "source": "osv",
        "source_refs": [{"kind": "osv", "id": "MAL-2026-1", "url": "https://osv.dev/vulnerability/MAL-2026-1"}],
        "published_at": "2026-06-01T00:00:00Z",
        "modified_at": "2026-06-04T00:00:00Z",
        "first_seen": "2026-06-04T00:00:00Z",
        "last_seen": "2026-06-04T00:00:00Z",
    }

    with mock.patch("pounce_sentinel.policy.on_demand_osv_items", return_value=[malicious_item]):
        result = vet_package({"ecosystem": "npm", "packageName": "demo", "version": "1.2.3"})

    assert result["verdict"] == "block"
    assert result["policyId"] == "threat-intel-feed-block"


def test_registry_provenance_warning_when_enabled(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    monkeypatch.setenv("POUNCE_ENABLE_REGISTRY_PROVENANCE", "true")
    with mock.patch(
        "pounce_sentinel.policy.registry_findings",
        return_value=[
            {
                "signal_name": "npm_missing_provenance",
                "category": "provenance",
                "verdict_impact": "warn",
                "evidence": "npm release provenance metadata was missing for demo@1.2.3.",
                "source": "registry",
                "artifact": "demo@1.2.3",
            }
        ],
    ):
        result = vet_package({"ecosystem": "npm", "packageName": "demo", "version": "1.2.3"})

    assert result["verdict"] == "warn"
    assert result["policyId"] == "registry-provenance-warning"


def test_feed_refresh_failure_warns_when_hosted_feed_is_configured(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    monkeypatch.setenv("POUNCE_IOC_FEED_URL", "https://feed.example/intel.json")

    with mock.patch("pounce_sentinel.feeds.load_remote_feed", side_effect=IntelUnavailable("timeout")):
        result = vet_package({"ecosystem": "npm", "packageName": "lodash", "version": "4.17.21"})

    assert result["verdict"] == "warn"
    assert result["policyId"] == "feed-verification-degraded"


def test_feed_failure_mode_can_fail_closed(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_FEED_STATE_PATH", str(tmp_path / "feed-state.json"))
    monkeypatch.setenv("POUNCE_IOC_FEED_URL", "https://feed.example/intel.json")
    monkeypatch.setenv("POUNCE_FEED_FAILURE_MODE", "block")

    with mock.patch("pounce_sentinel.feeds.load_remote_feed", side_effect=IntelUnavailable("timeout")):
        result = vet_package({"ecosystem": "npm", "packageName": "lodash", "version": "4.17.21"})

    assert result["verdict"] == "block"
    assert result["policyId"] == "feed-verification-degraded"
