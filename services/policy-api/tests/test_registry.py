from __future__ import annotations

from unittest import mock

from pounce_sentinel.provenance import ProvenanceResult
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


def test_npm_attestation_present_is_verified() -> None:
    package_index = {
        "versions": {"1.1.0": {"dist": {"attestations": {"url": "https://example.test/attest"}, "integrity": "sha512-AAAA"}}},
        "time": {"1.1.0": "2026-06-04T00:00:00Z"},
    }

    with mock.patch("pounce_sentinel.registry.load_npm_package_index", return_value=package_index), mock.patch(
        "pounce_sentinel.registry.load_npm_attestations", return_value={"attestations": [{}]}
    ), mock.patch(
        "pounce_sentinel.registry.verify_npm_attestation",
        return_value=ProvenanceResult("verified", "ok", "https://github.com/demo/repo"),
    ):
        findings = registry_findings("npm", "demo", "1.1.0")

    assert {finding["signal_name"] for finding in findings} == {"npm_provenance_verified"}
    assert all(finding["verdict_impact"] == "none" for finding in findings)


def test_npm_attestation_invalid_warns() -> None:
    package_index = {
        "versions": {"1.1.0": {"dist": {"attestations": {"url": "x"}, "integrity": "sha512-AAAA"}}},
        "time": {"1.1.0": "2026-06-04T00:00:00Z"},
    }

    with mock.patch("pounce_sentinel.registry.load_npm_package_index", return_value=package_index), mock.patch(
        "pounce_sentinel.registry.load_npm_attestations", return_value={"attestations": [{}]}
    ), mock.patch(
        "pounce_sentinel.registry.verify_npm_attestation",
        return_value=ProvenanceResult("invalid", "bad signature"),
    ):
        findings = registry_findings("npm", "demo", "1.1.0")

    assert {finding["signal_name"] for finding in findings} == {"npm_attestation_invalid"}


def test_pypi_provenance_invalid_warns() -> None:
    files = [{"filename": "requests-2.32.5.tar.gz", "sha256": "ab", "packagetype": "sdist"}]
    with mock.patch("pounce_sentinel.registry.load_pypi_release_files", return_value=files), mock.patch(
        "pounce_sentinel.registry.load_pypi_provenance", return_value={"attestation_bundles": [{}]}
    ), mock.patch("pounce_sentinel.registry.verify_pypi_attestation", return_value=ProvenanceResult("invalid", "bad")):
        findings = registry_findings("pypi", "requests", "2.32.5")

    assert {finding["signal_name"] for finding in findings} == {"pypi_attestation_invalid"}


def test_pypi_provenance_missing_warns() -> None:
    files = [{"filename": "requests-2.32.5.tar.gz", "sha256": "ab", "packagetype": "sdist"}]
    with mock.patch("pounce_sentinel.registry.load_pypi_release_files", return_value=files), mock.patch(
        "pounce_sentinel.registry.load_pypi_provenance", return_value={"missing": True}
    ):
        findings = registry_findings("pypi", "requests", "2.32.5")

    assert {finding["signal_name"] for finding in findings} == {"pypi_provenance_no_attestation"}

