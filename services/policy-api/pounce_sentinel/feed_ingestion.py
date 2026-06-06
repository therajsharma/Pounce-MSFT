from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import Request, build_opener
from urllib.error import HTTPError, URLError

from pounce_sentinel.feeds import (
    HTTP_USER_AGENT,
    IntelUnavailable,
    iso_now,
    normalize_ecosystem,
    normalize_feed_artifact,
    normalize_package_name,
)

GITHUB_API_ROOT = "https://api.github.com"
OSV_API_ROOT = "https://api.osv.dev"
OSV_EXPORT_ROOT = "https://storage.googleapis.com/osv-vulnerabilities"
URL_RE = re.compile(r"https?://[^\s<>'\"`]+", re.IGNORECASE)
IP_RE = re.compile(r"(?<!\d)((?:\d{1,3}\.){3}\d{1,3})(?!\d)")


def request_text(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: Any = None,
    method: str | None = None,
    timeout: int = 20,
) -> tuple[str, dict[str, str]]:
    data = None
    request_headers = {"Accept": "application/json", "User-Agent": HTTP_USER_AGENT, **(headers or {})}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    request = Request(url, data=data, method=method, headers=request_headers)
    try:
        with build_opener().open(request, timeout=timeout) as response:
            text = response.read().decode("utf-8")
            response_headers = {key: value for key, value in response.headers.items()}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp is not None else ""
        raise IntelUnavailable(f"{url} returned HTTP {exc.code}: {detail or exc.reason}") from exc
    except URLError as exc:
        raise IntelUnavailable(f"{url} could not be reached: {exc.reason}") from exc
    except UnicodeDecodeError as exc:
        raise IntelUnavailable(f"{url} returned a non-UTF-8 response.") from exc
    return text, response_headers


def request_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: Any = None,
    method: str | None = None,
) -> tuple[Any, dict[str, str]]:
    text, response_headers = request_text(url, headers=headers, payload=payload, method=method)
    try:
        return json.loads(text), response_headers
    except json.JSONDecodeError as exc:
        raise IntelUnavailable(f"{url} returned invalid JSON.") from exc


def github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("POUNCE_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def github_malware_items_since(last_modified: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    params = {
        "type": "malware",
        "per_page": "100",
        "sort": "updated",
        "direction": "asc",
    }
    if last_modified:
        params["modified"] = f">={last_modified}"
    url = f"{GITHUB_API_ROOT}/advisories?{urlencode(params)}"
    observed_at = iso_now()
    advisories: list[dict[str, Any]] = []
    newest_modified = last_modified

    while url:
        payload, headers = request_json(url, headers=github_headers())
        if not isinstance(payload, list):
            raise IntelUnavailable("GitHub advisories response was not a list.")
        advisories.extend(item for item in payload if isinstance(item, dict))
        for advisory in payload:
            if not isinstance(advisory, dict):
                continue
            candidate = str(advisory.get("updated_at") or advisory.get("published_at") or "").strip()
            if candidate and (newest_modified is None or candidate > newest_modified):
                newest_modified = candidate
        url = parse_link_header(headers.get("Link")).get("next")

    items: list[dict[str, Any]] = []
    for advisory in advisories:
        items.extend(normalize_github_advisory(advisory, observed_at=observed_at))
    return items, {
        "name": "github_advisory",
        "synced_at": observed_at,
        "status": "ok",
        "last_modified": newest_modified,
        "advisory_count": len(advisories),
        "item_count": len(items),
    }


def osv_recent_malware_ids(last_modified: str | None) -> tuple[list[str], str | None]:
    text, _headers = request_text(f"{OSV_EXPORT_ROOT}/modified_id.csv", headers={"Accept": "text/plain"})
    ids: list[str] = []
    newest_seen = last_modified
    for index, line in enumerate(text.splitlines()):
        if not line.strip() or "," not in line:
            continue
        modified, location = [part.strip() for part in line.split(",", 1)]
        if index == 0 and modified and (newest_seen is None or modified > newest_seen):
            newest_seen = modified
        if last_modified and modified <= last_modified:
            break
        advisory_id = location.rsplit("/", 1)[-1]
        if advisory_id.startswith("MAL-"):
            ids.append(advisory_id)
    return ids, newest_seen


def osv_vuln(advisory_id: str) -> dict[str, Any]:
    payload, _headers = request_json(f"{OSV_API_ROOT}/v1/vulns/{quote(advisory_id, safe='')}")
    if not isinstance(payload, dict):
        raise IntelUnavailable(f"OSV response for {advisory_id} was not an object.")
    return payload


def osv_malware_items_since(last_modified: str | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    advisory_ids, newest_modified = osv_recent_malware_ids(last_modified)
    observed_at = iso_now()
    advisories = [osv_vuln(advisory_id) for advisory_id in advisory_ids]
    items: list[dict[str, Any]] = []
    for advisory in advisories:
        items.extend(normalize_osv_advisory(advisory, observed_at=observed_at, action="block"))
    return items, {
        "name": "osv",
        "synced_at": observed_at,
        "status": "ok",
        "last_modified": newest_modified,
        "advisory_count": len(advisories),
        "item_count": len(items),
    }


def on_demand_osv_items(ecosystem: str, package_name: str, version: str) -> list[dict[str, Any]]:
    normalized_ecosystem = osv_ecosystem_name(ecosystem)
    query = {
        "package": {"ecosystem": normalized_ecosystem, "name": package_name},
        "version": version,
    }
    payload, _headers = request_json(f"{OSV_API_ROOT}/v1/querybatch", payload={"queries": [query]}, method="POST")
    results = payload.get("results", []) if isinstance(payload, dict) else []
    advisories: list[dict[str, Any]] = []
    if isinstance(results, list) and results:
        result = results[0] if isinstance(results[0], dict) else {}
        for vuln in result.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            advisory_id = str(vuln.get("id", "")).strip()
            if advisory_id:
                advisories.append(osv_vuln(advisory_id))

    observed_at = iso_now()
    items: list[dict[str, Any]] = []
    for advisory in advisories:
        advisory_id = str(advisory.get("id", "")).strip()
        items.extend(
            normalize_osv_advisory(
                advisory,
                observed_at=observed_at,
                action="block" if advisory_id.startswith("MAL-") else vulnerability_action(),
            )
        )
    return items


def normalize_github_advisory(advisory: dict[str, Any], *, observed_at: str) -> list[dict[str, Any]]:
    advisory_id = str(advisory.get("ghsa_id") or advisory.get("id") or "").strip()
    if not advisory_id:
        return []
    summary = str(advisory.get("summary") or advisory.get("description") or "").strip()
    published_at = str(advisory.get("published_at") or observed_at).strip()
    modified_at = str(advisory.get("updated_at") or published_at).strip()
    withdrawn_at = str(advisory.get("withdrawn_at") or "").strip()
    references = advisory.get("references") if isinstance(advisory.get("references"), list) else []
    refs = [{"kind": "ghsa", "id": advisory_id}, *[{"kind": "url", "url": str(ref)} for ref in references if str(ref).startswith("https://")]]
    vulnerabilities = advisory.get("vulnerabilities") if isinstance(advisory.get("vulnerabilities"), list) else []
    items: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        package = vulnerability.get("package") if isinstance(vulnerability.get("package"), dict) else {}
        ecosystem = normalize_ecosystem(package.get("ecosystem"))
        name = normalize_package_name(ecosystem, str(package.get("name", "")))
        version_range = str(vulnerability.get("vulnerable_version_range") or "").strip()
        match = _match_from_range(ecosystem, name, version_range)
        if match is None:
            continue
        item_id = f"{advisory_id}:{ecosystem}:{name}:{match['type']}:{match.get('version') or match.get('version_spec')}"
        item = _item(
            item_id=item_id,
            kind="malicious_package",
            match=match,
            action="block",
            reason=summary or f"GitHub advisory {advisory_id}.",
            source="github_advisory",
            source_refs=refs,
            published_at=published_at,
            modified_at=modified_at,
            observed_at=observed_at,
        )
        if withdrawn_at:
            item["revoked_at"] = withdrawn_at
            item["revocation_reason"] = "GitHub advisory withdrawn."
        items.append(item)
    items.extend(_indicator_items(advisory_id, summary, str(advisory.get("description") or ""), "github_advisory", refs, published_at, modified_at, observed_at))
    return normalize_feed_artifact({"items": items}, observed_at=observed_at, default_source="github_advisory")["items"]


def normalize_osv_advisory(advisory: dict[str, Any], *, observed_at: str, action: str) -> list[dict[str, Any]]:
    advisory_id = str(advisory.get("id") or "").strip()
    if not advisory_id:
        return []
    summary = str(advisory.get("summary") or advisory.get("details") or "").strip()
    published_at = str(advisory.get("published") or observed_at).strip()
    modified_at = str(advisory.get("modified") or published_at).strip()
    withdrawn_at = str(advisory.get("withdrawn") or "").strip()
    references = advisory.get("references") if isinstance(advisory.get("references"), list) else []
    refs = [{"kind": "osv", "id": advisory_id}, {"kind": "url", "url": f"https://osv.dev/vulnerability/{advisory_id}"}]
    refs.extend({"kind": "url", "url": str(ref.get("url"))} for ref in references if isinstance(ref, dict) and str(ref.get("url", "")).startswith("https://"))
    affected = advisory.get("affected") if isinstance(advisory.get("affected"), list) else []
    items: list[dict[str, Any]] = []
    for affected_item in affected:
        if not isinstance(affected_item, dict):
            continue
        package = affected_item.get("package") if isinstance(affected_item.get("package"), dict) else {}
        ecosystem = normalize_ecosystem(package.get("ecosystem"))
        name = normalize_package_name(ecosystem, str(package.get("name", "")))
        if not ecosystem or not name:
            continue
        for version in affected_item.get("versions") or []:
            version_text = str(version).strip()
            if not version_text:
                continue
            match = {"type": "package_exact", "ecosystem": ecosystem, "name": name, "version": version_text}
            item_id = f"{advisory_id}:{ecosystem}:{name}:package_exact:{version_text}"
            item = _item(
                item_id=item_id,
                kind="malicious_package" if action == "block" else "vulnerability",
                match=match,
                action=action,
                reason=summary or f"OSV advisory {advisory_id}.",
                source="osv",
                source_refs=refs,
                published_at=published_at,
                modified_at=modified_at,
                observed_at=observed_at,
            )
            if withdrawn_at:
                item["revoked_at"] = withdrawn_at
                item["revocation_reason"] = "OSV advisory withdrawn."
            items.append(item)
        for range_index, range_obj in enumerate(affected_item.get("ranges") or []):
            if not isinstance(range_obj, dict):
                continue
            for spec_index, version_spec in enumerate(_osv_range_specs(range_obj)):
                match = {"type": "package_range", "ecosystem": ecosystem, "name": name, "version_spec": version_spec}
                item_id = f"{advisory_id}:{ecosystem}:{name}:package_range:{range_index}.{spec_index}:{version_spec}"
                item = _item(
                    item_id=item_id,
                    kind="malicious_package" if action == "block" else "vulnerability",
                    match=match,
                    action=action,
                    reason=summary or f"OSV advisory {advisory_id}.",
                    source="osv",
                    source_refs=refs,
                    published_at=published_at,
                    modified_at=modified_at,
                    observed_at=observed_at,
                )
                if withdrawn_at:
                    item["revoked_at"] = withdrawn_at
                    item["revocation_reason"] = "OSV advisory withdrawn."
                items.append(item)
    items.extend(_indicator_items(advisory_id, summary, str(advisory.get("details") or ""), "osv", refs, published_at, modified_at, observed_at))
    return normalize_feed_artifact({"items": items}, observed_at=observed_at, default_source="osv")["items"]


def parse_link_header(value: str | None) -> dict[str, str]:
    links: dict[str, str] = {}
    if not value:
        return links
    for part in value.split(","):
        part = part.strip()
        if ";" not in part:
            continue
        url_part, *params = [section.strip() for section in part.split(";")]
        if not url_part.startswith("<") or not url_part.endswith(">"):
            continue
        rel = None
        for param in params:
            if param.startswith("rel="):
                rel = param.split("=", 1)[1].strip('"')
        if rel:
            links[rel] = url_part[1:-1]
    return links


def osv_ecosystem_name(ecosystem: str) -> str:
    normalized = normalize_ecosystem(ecosystem)
    if normalized == "pypi":
        return "PyPI"
    if normalized == "npm":
        return "npm"
    return ecosystem


def vulnerability_action() -> str:
    action = str(os.getenv("POUNCE_VULNERABILITY_ACTION", "warn")).strip().lower()
    return action if action in {"warn", "block"} else "warn"


def _match_from_range(ecosystem: str, name: str, version_range: str) -> dict[str, Any] | None:
    if not ecosystem or not name or not version_range:
        return None
    normalized_range = version_range.strip()
    exact = normalized_range.lstrip("= ").strip() if normalized_range.startswith("=") else ""
    if exact and not any(character in exact for character in "<> *|,"):
        return {"type": "package_exact", "ecosystem": ecosystem, "name": name, "version": exact}
    return {"type": "package_range", "ecosystem": ecosystem, "name": name, "version_spec": normalized_range}


def _osv_range_specs(range_obj: dict[str, Any]) -> list[str]:
    """Translate an OSV affected-range (introduced/fixed/last_affected events) into
    one version_spec string per affected interval. GIT ranges are skipped."""
    if str(range_obj.get("type", "")).strip().upper() == "GIT":
        return []
    events = range_obj.get("events") if isinstance(range_obj.get("events"), list) else []
    specs: list[str] = []
    introduced: str | None = None
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            value = str(event.get("introduced") or "").strip()
            introduced = None if value in {"", "0"} else value
        elif "fixed" in event:
            fixed = str(event.get("fixed") or "").strip()
            bounds = ([f">={introduced}"] if introduced else []) + ([f"<{fixed}"] if fixed else [])
            if bounds:
                specs.append(", ".join(bounds))
            introduced = None
        elif "last_affected" in event:
            last = str(event.get("last_affected") or "").strip()
            bounds = ([f">={introduced}"] if introduced else []) + ([f"<={last}"] if last else [])
            if bounds:
                specs.append(", ".join(bounds))
            introduced = None
    if introduced:
        specs.append(f">={introduced}")
    return specs


def _indicator_items(
    advisory_id: str,
    summary: str,
    detail: str,
    source: str,
    refs: list[dict[str, Any]],
    published_at: str,
    modified_at: str,
    observed_at: str,
) -> list[dict[str, Any]]:
    text = f"{summary}\n{detail}"
    items: list[dict[str, Any]] = []
    for index, url in enumerate(sorted(set(URL_RE.findall(text))), start=1):
        items.append(_item(f"{advisory_id}:indicator:url:{index}", "ioc_url", {"type": "url", "value": url.rstrip(".,)")}, "warn", summary or "Advisory URL indicator.", source, refs, published_at, modified_at, observed_at))
    for index, ip_address in enumerate(sorted(set(IP_RE.findall(text))), start=1):
        items.append(_item(f"{advisory_id}:indicator:ip:{index}", "ioc_ip", {"type": "ip", "value": ip_address}, "warn", summary or "Advisory IP indicator.", source, refs, published_at, modified_at, observed_at))
    return items


def _item(
    item_id: str,
    kind: str,
    match: dict[str, Any],
    action: str,
    reason: str,
    source: str,
    source_refs: list[dict[str, Any]],
    published_at: str,
    modified_at: str,
    observed_at: str,
) -> dict[str, Any]:
    return {
        "id": item_id,
        "kind": kind,
        "match": match,
        "action": action,
        "confidence": 1.0 if action == "block" else 0.8,
        "reason": reason,
        "source": source,
        "source_refs": source_refs,
        "published_at": published_at,
        "modified_at": modified_at,
        "first_seen": observed_at,
        "last_seen": observed_at,
    }

