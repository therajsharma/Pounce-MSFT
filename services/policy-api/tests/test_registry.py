from __future__ import annotations

from unittest import mock

from pounce_sentinel.registry import registry_findings


def test_npm_missing_attestations_warns() -> None:
    package_index = {
        "versions": {"1.1.0": {"dist": {}}},
        "time": {"1.1.0": "2026-06-04T00:00:00Z"},
    }

    with mock.patch("pounce_sentinel.registry.load_npm_package_index", return_value=package_index):
        findings = registry_findings("npm", "demo", "1.1.0")

    assert {finding["signal_name"] for finding in findings} == {"npm_missing_provenance"}


def test_npm_provenance_regression_warns_when_baseline_had_attestations() -> None:
    package_index = {
        "versions": {
            "1.0.0": {"dist": {"attestations": {"url": "https://example.test/attest"}}},
            "1.1.0": {"dist": {}},
        },
        "time": {
            "1.0.0": "2026-06-01T00:00:00Z",
            "1.1.0": "2026-06-04T00:00:00Z",
        },
    }

    with mock.patch("pounce_sentinel.registry.load_npm_package_index", return_value=package_index):
        findings = registry_findings("npm", "demo", "1.1.0")

    signal_names = {finding["signal_name"] for finding in findings}
    assert "npm_missing_provenance" in signal_names
    assert "npm_provenance_regression" in signal_names


def test_npm_with_attestations_has_no_provenance_warning() -> None:
    package_index = {
        "versions": {"1.1.0": {"dist": {"attestations": {"url": "https://example.test/attest"}}}},
        "time": {"1.1.0": "2026-06-04T00:00:00Z"},
    }

    with mock.patch("pounce_sentinel.registry.load_npm_package_index", return_value=package_index):
        findings = registry_findings("npm", "demo", "1.1.0")

    assert findings == []


def test_registry_lookup_is_npm_only() -> None:
    assert registry_findings("pypi", "requests", "2.32.5") == []

