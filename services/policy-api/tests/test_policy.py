from __future__ import annotations

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
