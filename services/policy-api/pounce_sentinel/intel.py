from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IntelRecord:
    ecosystem: str
    package_name: str
    version: str
    verdict: str
    risk_score: int
    policy_id: str
    reasons: tuple[str, ...]
    evidence_label: str
    evidence_url: str
    recommended_version: str | None = None


SEEDED_INTEL: tuple[IntelRecord, ...] = (
    IntelRecord(
        ecosystem="npm",
        package_name="event-stream",
        version="3.3.7",
        verdict="block",
        risk_score=92,
        policy_id="supply-chain-high-risk",
        reasons=(
            "Known malicious package",
            "Malicious behavior detected",
            "High impact to agent runtime",
        ),
        evidence_label="Seeded event-stream compromise fixture",
        evidence_url="https://example.invalid/pounce/demo-intel/event-stream",
    ),
    IntelRecord(
        ecosystem="npm",
        package_name="left-pad",
        version="1.3.0",
        verdict="block",
        risk_score=88,
        policy_id="supply-chain-demo-block",
        reasons=(
            "Seeded installable block fixture",
            "Used to verify pull request dependency gates",
        ),
        evidence_label="Seeded installable npm block fixture",
        evidence_url="https://example.invalid/pounce/demo-intel/left-pad",
    ),
    IntelRecord(
        ecosystem="npm",
        package_name="minimist",
        version="1.2.8",
        verdict="warn",
        risk_score=45,
        policy_id="dependency-review-warning",
        reasons=("Known vulnerable history", "Review transitive usage before merge"),
        evidence_label="Seeded advisory history fixture",
        evidence_url="https://example.invalid/pounce/demo-intel/minimist",
        recommended_version="1.2.8",
    ),
    IntelRecord(
        ecosystem="npm",
        package_name="axios",
        version="1.8.2",
        verdict="warn",
        risk_score=40,
        policy_id="dependency-review-warning",
        reasons=("Network-capable package", "Confirm pinned version and provenance"),
        evidence_label="Seeded network package review fixture",
        evidence_url="https://example.invalid/pounce/demo-intel/axios",
        recommended_version="1.8.2",
    ),
    IntelRecord(
        ecosystem="pypi",
        package_name="ctx",
        version="0.1.2",
        verdict="block",
        risk_score=90,
        policy_id="supply-chain-high-risk",
        reasons=("Seeded typosquatting fixture", "Credential access behavior"),
        evidence_label="Seeded PyPI malicious package fixture",
        evidence_url="https://example.invalid/pounce/demo-intel/ctx",
    ),
)


def find_seeded_record(ecosystem: str, package_name: str, version: str) -> IntelRecord | None:
    normalized_name = package_name.lower()
    normalized_ecosystem = ecosystem.lower()
    normalized_version = version.strip()

    for record in SEEDED_INTEL:
        if (
            record.ecosystem == normalized_ecosystem
            and record.package_name == normalized_name
            and record.version == normalized_version
        ):
            return record
    return None
