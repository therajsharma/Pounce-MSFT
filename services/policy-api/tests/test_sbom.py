from __future__ import annotations

import pytest

from pounce_sentinel import sbom


def test_parse_purl_handles_scopes_and_unsupported_types() -> None:
    npm = sbom.parse_purl("pkg:npm/lodash@4.17.21")
    assert (npm.type, npm.namespace, npm.name, npm.version) == ("npm", "", "lodash", "4.17.21")

    scoped = sbom.parse_purl("pkg:npm/%40storybook/core@7.0.0")
    assert sbom.purl_to_ecosystem_component(scoped) == {
        "ecosystem": "npm",
        "name": "@storybook/core",
        "version": "7.0.0",
    }

    pypi = sbom.parse_purl("pkg:pypi/requests@2.32.5")
    assert sbom.purl_to_ecosystem_component(pypi) == {"ecosystem": "pypi", "name": "requests", "version": "2.32.5"}

    assert sbom.purl_to_ecosystem_component(sbom.parse_purl("pkg:maven/org.apache/foo@1.0")) is None
    assert sbom.parse_purl("not-a-purl") is None


def test_parse_cyclonedx_extracts_supported_and_skips_others() -> None:
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {"type": "library", "purl": "pkg:npm/event-stream@3.3.7"},
            {"type": "library", "purl": "pkg:pypi/requests@2.32.5", "components": [
                {"type": "library", "purl": "pkg:npm/lodash@4.17.21"},  # nested
            ]},
            {"type": "library", "purl": "pkg:maven/org.apache/foo@1.0"},  # unsupported
            {"type": "library", "name": "no-purl-here", "version": "1.0.0"},  # no purl
        ],
    }

    result = sbom.parse_cyclonedx(payload)

    names = {(c["ecosystem"], c["name"], c["version"]) for c in result["components"]}
    assert names == {
        ("npm", "event-stream", "3.3.7"),
        ("pypi", "requests", "2.32.5"),
        ("npm", "lodash", "4.17.21"),
    }
    assert len(result["skipped"]) == 2  # maven + no-purl


def test_parse_spdx_reads_purl_external_refs() -> None:
    payload = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "event-stream",
                "versionInfo": "3.3.7",
                "externalRefs": [
                    {"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/event-stream@3.3.7"}
                ],
            },
            {
                "name": "hyphen-cat",
                "versionInfo": "1.0.0",
                "externalRefs": [
                    {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/ctx@0.1.2"}
                ],
            },
            {"name": "no-purl", "versionInfo": "1.0.0", "externalRefs": []},
        ],
    }

    result = sbom.parse_spdx(payload)

    assert {(c["ecosystem"], c["name"], c["version"]) for c in result["components"]} == {
        ("npm", "event-stream", "3.3.7"),
        ("pypi", "ctx", "0.1.2"),
    }
    assert len(result["skipped"]) == 1


def test_parse_sbom_dispatches_and_rejects_unknown() -> None:
    assert sbom.parse_sbom({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []})["format"] == "cyclonedx"
    assert sbom.parse_sbom({"spdxVersion": "SPDX-2.3", "packages": []})["format"] == "spdx"
    with pytest.raises(ValueError):
        sbom.parse_sbom({"unrelated": True})
    with pytest.raises(ValueError):
        sbom.parse_sbom({"spdxVersion": "SPDX-3.0", "packages": []})
