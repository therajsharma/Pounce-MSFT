"""SBOM ingestion for CycloneDX and SPDX (JSON only).

Parses an SBOM document into a flat list of ``{ecosystem, name, version}``
components keyed off Package URLs (PURLs). Only npm and pypi PURLs are mapped to
verifiable components; other types are reported as ``skipped`` rather than
silently dropped. No XML, no SPDX tag-value, no SPDX 3.x (rejected explicitly).
SBOM signatures are NOT validated — this is a structural parse only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from pounce_sentinel.feeds import normalize_ecosystem


@dataclass(frozen=True)
class Purl:
    type: str
    namespace: str
    name: str
    version: str


def parse_purl(purl: str) -> Purl | None:
    text = str(purl or "").strip()
    if not text.lower().startswith("pkg:"):
        return None
    body = text[4:].split("#", 1)[0].split("?", 1)[0]
    type_part, sep, rest = body.partition("/")
    if not sep or not rest:
        return None
    ptype = unquote(type_part).strip().lower()
    name_part, at, version = rest.rpartition("@")
    if not at:
        name_part, version = rest, ""
    segments = [unquote(segment) for segment in name_part.split("/") if segment]
    if not segments:
        return None
    namespace = "/".join(segments[:-1])
    return Purl(type=ptype, namespace=namespace, name=segments[-1], version=unquote(version).strip())


def purl_to_ecosystem_component(purl: Purl | None) -> dict[str, str] | None:
    if purl is None:
        return None
    ecosystem = normalize_ecosystem(purl.type)
    if ecosystem not in {"npm", "pypi"} or not purl.name or not purl.version:
        return None
    name = f"{purl.namespace}/{purl.name}" if ecosystem == "npm" and purl.namespace else purl.name
    return {"ecosystem": ecosystem, "name": name, "version": purl.version}


def parse_cyclonedx(payload: dict[str, Any]) -> dict[str, Any]:
    if str(payload.get("bomFormat", "")).strip() != "CycloneDX":
        raise ValueError("Document is not a CycloneDX SBOM (missing bomFormat).")
    components: list[dict[str, str]] = []
    skipped: list[dict[str, Any]] = []

    def walk(component_list: Any) -> None:
        if not isinstance(component_list, list):
            return
        for component in component_list:
            if not isinstance(component, dict):
                continue
            purl_value = component.get("purl")
            mapped = purl_to_ecosystem_component(parse_purl(str(purl_value))) if purl_value else None
            if mapped:
                components.append({**mapped, "purl": str(purl_value)})
            else:
                skipped.append(
                    {
                        "purl": str(purl_value) if purl_value else None,
                        "name": component.get("name"),
                        "reason": "unsupported ecosystem" if purl_value else "no purl",
                    }
                )
            walk(component.get("components"))

    walk(payload.get("components"))
    return {
        "format": "cyclonedx",
        "spec_version": str(payload.get("specVersion", "")).strip(),
        "components": components,
        "skipped": skipped,
    }


def parse_spdx(payload: dict[str, Any]) -> dict[str, Any]:
    spdx_version = str(payload.get("spdxVersion", "")).strip()
    if spdx_version.startswith("SPDX-3"):
        raise ValueError("SPDX 3.x is not supported (only SPDX-2 JSON).")
    if not spdx_version.startswith("SPDX-2"):
        raise ValueError("Document is not an SPDX-2 SBOM (missing spdxVersion).")
    components: list[dict[str, str]] = []
    skipped: list[dict[str, Any]] = []
    for package in payload.get("packages") or []:
        if not isinstance(package, dict):
            continue
        purl_value = _spdx_purl(package.get("externalRefs"))
        mapped = purl_to_ecosystem_component(parse_purl(purl_value)) if purl_value else None
        if mapped:
            components.append({**mapped, "purl": purl_value})
        else:
            skipped.append(
                {
                    "purl": purl_value,
                    "name": package.get("name"),
                    "reason": "unsupported ecosystem" if purl_value else "no purl",
                }
            )
    return {"format": "spdx", "spec_version": spdx_version, "components": components, "skipped": skipped}


def parse_sbom(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("SBOM must be a JSON object.")
    if "bomFormat" in payload:
        return parse_cyclonedx(payload)
    if "spdxVersion" in payload:
        return parse_spdx(payload)
    raise ValueError("Unsupported SBOM format; expected CycloneDX or SPDX JSON.")


def _spdx_purl(external_refs: Any) -> str | None:
    if not isinstance(external_refs, list):
        return None
    for ref in external_refs:
        if not isinstance(ref, dict):
            continue
        category = str(ref.get("referenceCategory", "")).strip().upper().replace("-", "_")
        if str(ref.get("referenceType", "")).strip().lower() == "purl" and category == "PACKAGE_MANAGER":
            locator = str(ref.get("referenceLocator", "")).strip()
            if locator:
                return locator
    return None
