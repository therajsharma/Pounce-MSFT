from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pounce_sentinel.intel import SEEDED_INTEL
from pounce_sentinel import signatures
from pounce_sentinel import storage
from pounce_sentinel import version_ranges

FEED_SCHEMA_VERSION = "1.0"
DEFAULT_FEED_STALE_AFTER_HOURS = 6
MAX_HTTP_RESPONSE_BYTES = 5 * 1024 * 1024
HTTP_USER_AGENT = "pounce-sentinel-policy-api"
TRANSPORT_POLICY = "https-only hosted feeds, redirects disabled, 5 MiB response cap"


class IntelUnavailable(Exception):
    """Raised when a threat intelligence feed cannot be loaded."""


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Request | None:
        raise HTTPError(req.full_url, code, "Redirects are not allowed.", headers, fp)


def now_utc() -> datetime:
    return datetime.now(tz=UTC)


def iso_now() -> str:
    return now_utc().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_timestamp(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def normalize_ecosystem(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"node", "javascript", "js"}:
        return "npm"
    if normalized in {"python", "pip"}:
        return "pypi"
    return normalized


def normalize_python_package_key(name: str) -> str:
    base = name.split("[", 1)[0].strip().lower()
    return re.sub(r"[-_.]+", "-", base)


def normalize_package_name(ecosystem: str, name: str) -> str:
    if normalize_ecosystem(ecosystem) == "pypi":
        return normalize_python_package_key(name)
    return str(name or "").strip().lower()


def stale_after_hours() -> int:
    raw = str(os.getenv("POUNCE_FEED_STALE_AFTER_HOURS", DEFAULT_FEED_STALE_AFTER_HOURS)).strip()
    try:
        parsed = int(raw)
    except ValueError:
        return DEFAULT_FEED_STALE_AFTER_HOURS
    return max(1, parsed)


def normalize_match_payload(match: Any) -> dict[str, Any] | None:
    if not isinstance(match, dict):
        return None
    match_type = str(match.get("type", "")).strip().lower()
    if match_type == "package":
        ecosystem = normalize_ecosystem(match.get("ecosystem"))
        name = normalize_package_name(ecosystem, str(match.get("name", "")))
        version = str(match.get("version", "")).strip()
        if ecosystem and name and version:
            return {"type": "package_exact", "ecosystem": ecosystem, "name": name, "version": version}
        return None
    if match_type in {"package_exact", "package_range"}:
        ecosystem = normalize_ecosystem(match.get("ecosystem"))
        name = normalize_package_name(ecosystem, str(match.get("name", "")))
        if not ecosystem or not name:
            return None
        normalized: dict[str, Any] = {"type": match_type, "ecosystem": ecosystem, "name": name}
        if match_type == "package_exact":
            version = str(match.get("version", "")).strip()
            if not version:
                return None
            normalized["version"] = version
        else:
            version_spec = str(match.get("version_spec") or match.get("versionRange") or "").strip()
            if not version_spec:
                return None
            normalized["version_spec"] = version_spec
        return normalized
    if match_type in {"string", "domain", "ip", "url"}:
        value = str(match.get("value", "")).strip()
        if value:
            return {"type": match_type, "value": value}
    return None


def normalize_feed_artifact(
    payload: Any,
    *,
    observed_at: str | None = None,
    default_source: str = "feed",
) -> dict[str, Any]:
    observed = observed_at or iso_now()
    signature: Any = None
    if isinstance(payload, list):
        raw_items = payload
        sources: list[dict[str, Any]] = []
        generated_at = observed
        schema_version = FEED_SCHEMA_VERSION
    elif isinstance(payload, dict):
        raw_items = payload.get("items", [])
        sources = _normalize_sources(payload.get("sources"))
        generated_at = str(payload.get("generated_at", "")).strip() or observed
        schema_version = str(payload.get("schema_version", FEED_SCHEMA_VERSION)).strip() or FEED_SCHEMA_VERSION
        signature = payload.get("signature")
    else:
        raise ValueError("Feed payload must be a JSON object or array.")

    if not isinstance(raw_items, list):
        raise ValueError("Feed items must be a list.")

    items = [
        normalized
        for raw_item in raw_items
        if isinstance(raw_item, dict)
        for normalized in [_normalize_feed_item(raw_item, observed_at=observed, default_source=default_source)]
        if normalized is not None
    ]

    artifact: dict[str, Any] = {
        "schema_version": schema_version,
        "generated_at": generated_at,
        "sources": sources,
        "items": sorted(items, key=lambda item: str(item.get("id", ""))),
    }
    if signature not in {None, ""}:
        artifact["signature"] = signature
    return artifact


def seeded_feed(*, observed_at: str | None = None) -> dict[str, Any]:
    observed = observed_at or iso_now()
    items: list[dict[str, Any]] = []
    for record in SEEDED_INTEL:
        items.append(
            {
                "id": f"seeded:{record.ecosystem}:{record.package_name}:{record.version}",
                "kind": "malicious_package" if record.verdict == "block" else "vulnerability",
                "match": {
                    "type": "package_exact",
                    "ecosystem": record.ecosystem,
                    "name": record.package_name,
                    "version": record.version,
                },
                "action": record.verdict if record.verdict in {"warn", "block"} else "warn",
                "confidence": 1.0 if record.verdict == "block" else 0.75,
                "reason": "; ".join(record.reasons),
                "source": "seeded-intel",
                "source_refs": [{"kind": "seeded-intel", "id": record.policy_id, "url": record.evidence_url}],
                "published_at": observed,
                "modified_at": observed,
                "first_seen": observed,
                "last_seen": observed,
                "metadata": {"policy_id": record.policy_id, "evidence_label": record.evidence_label},
            }
        )
    return normalize_feed_artifact(
        {
            "schema_version": FEED_SCHEMA_VERSION,
            "generated_at": observed,
            "sources": [{"name": "seeded-intel", "status": "fallback", "item_count": len(items), "synced_at": observed}],
            "items": items,
        },
        observed_at=observed,
        default_source="seeded-intel",
    )


def active_feed_items(items: list[dict[str, Any]], *, at: datetime | None = None) -> list[dict[str, Any]]:
    checked_at = at or now_utc()
    active: list[dict[str, Any]] = []
    for item in items:
        if parse_timestamp(item.get("revoked_at")) is not None:
            continue
        expires_at = parse_timestamp(item.get("expires_at"))
        if expires_at is not None and expires_at <= checked_at:
            continue
        active.append(item)
    return active


def match_package_items(
    items: list[dict[str, Any]],
    ecosystem: str,
    package_name: str,
    version: str,
) -> list[dict[str, Any]]:
    normalized_ecosystem = normalize_ecosystem(ecosystem)
    normalized_name = normalize_package_name(normalized_ecosystem, package_name)
    normalized_version = str(version or "").strip()
    matches: list[dict[str, Any]] = []
    for item in active_feed_items(items):
        match = item.get("match")
        if not isinstance(match, dict):
            continue
        if normalize_ecosystem(match.get("ecosystem")) != normalized_ecosystem:
            continue
        if normalize_package_name(normalized_ecosystem, str(match.get("name", ""))) != normalized_name:
            continue
        match_type = str(match.get("type", "")).strip()
        if match_type == "package_exact" and str(match.get("version", "")).strip() == normalized_version:
            matches.append(item)
        elif match_type == "package_range" and _range_matches(
            str(match.get("version_spec", "")), normalized_version, normalized_ecosystem
        ):
            matches.append(item)
    return matches


def runtime_feed(feed_url: str | None = None) -> dict[str, Any]:
    observed = iso_now()
    seed = seeded_feed(observed_at=observed)
    local_envelope = _cached_envelope("localSync")
    local_feed = _normalize_cached_feed(local_envelope, observed_at=observed, default_source="local_sync_cache")
    remote_envelope = _cached_envelope("remoteCache")
    remote_feed = _normalize_cached_feed(remote_envelope, observed_at=observed, default_source="remote_cache")

    selected_feed = local_feed if local_feed.get("items") else seed
    selected_envelope = local_envelope if local_feed.get("items") else {}
    selected_from = "local_sync_cache" if local_feed.get("items") else "seed"
    warnings: list[dict[str, Any]] = []
    remote_verified = False

    configured_url = str(feed_url or os.getenv("POUNCE_IOC_FEED_URL", "")).strip()
    if configured_url:
        try:
            live_feed = load_remote_feed(configured_url)
            fetched_at = iso_now()
            selected_feed = normalize_feed_artifact(live_feed, observed_at=observed, default_source="live_feed")
            selected_envelope = feed_cache_envelope(selected_feed, fetched_at=fetched_at, fetched_from=configured_url)
            persist_feed_cache(
                selected_feed,
                fetched_at=fetched_at,
                fetched_from=configured_url,
                cache_kind="remoteCache",
            )
            selected_from = "remote"
            remote_verified = feed_signature_verification_enabled()
        except IntelUnavailable as exc:
            if remote_feed.get("items") and str(remote_envelope.get("fetched_from", "")).strip() == configured_url:
                selected_feed = remote_feed
                selected_envelope = remote_envelope
                selected_from = "remote_cache"
                warnings.append(_feed_warning("feed_refresh_failed", f"Live feed refresh failed, continuing with the last good hosted feed cache: {exc}", selected_from))
            elif local_feed.get("items"):
                selected_feed = local_feed
                selected_envelope = local_envelope
                selected_from = "local_sync_cache"
                warnings.append(_feed_warning("feed_refresh_failed", f"Live feed refresh failed, continuing with the local synced feed: {exc}", selected_from))
            else:
                selected_feed = seed
                selected_envelope = {}
                selected_from = "seed"
                warnings.append(_feed_warning("feed_refresh_failed", f"Live feed refresh failed and no cached feed was available: {exc}", selected_from))

    stale_warning = _stale_warning(selected_feed, selected_envelope, selected_from)
    if stale_warning is not None:
        warnings.append(stale_warning)

    merged = merge_feed_artifacts(seed, selected_feed)
    return {
        "feed": merged,
        "selected_from": selected_from,
        "trust_state": trust_state(selected_from, verified=remote_verified),
        "transport_policy": TRANSPORT_POLICY,
        "cache_timestamp": str(selected_envelope.get("fetched_at", "")).strip() or None,
        "warnings": warnings,
    }


def trust_state(selected_from: str, *, verified: bool = False) -> str:
    if selected_from == "remote":
        return "hosted_feed_verified" if verified else "hosted_feed_unverified"
    return {
        "remote_cache": "hosted_feed_cache_unverified",
        "local_sync_cache": "local_sync_cache",
        "seed": "bundled_seed",
    }.get(selected_from, "unknown")


def feed_status_rows(context: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    feed_context = context or runtime_feed()
    feed = feed_context.get("feed") if isinstance(feed_context, dict) else {}
    if not isinstance(feed, dict):
        feed = {}
    sources = feed.get("sources")
    if not isinstance(sources, list) or not sources:
        sources = [{"name": "policy-feed", "status": "unknown"}]

    selected_from = str(feed_context.get("selected_from", "seed")).strip() or "seed"
    context_trust = str(feed_context.get("trust_state", "")).strip()
    cache_timestamp = str(feed_context.get("cache_timestamp") or feed.get("generated_at") or "").strip()
    active_count = len(active_feed_items(feed.get("items", []) if isinstance(feed.get("items"), list) else []))
    warnings = feed_context.get("warnings") if isinstance(feed_context.get("warnings"), list) else []

    rows: list[dict[str, Any]] = []
    for source in sources:
        if not isinstance(source, dict):
            continue
        timestamp = str(source.get("synced_at") or source.get("last_modified") or cache_timestamp).strip()
        rows.append(
            {
                "name": str(source.get("name", "policy-feed")).strip() or "policy-feed",
                "status": str(source.get("status", "unknown")).strip() or "unknown",
                "updatedAgo": human_age(timestamp),
                "selectedFrom": selected_from,
                "trustState": context_trust or trust_state(selected_from),
                "activeItemCount": active_count,
                "cacheTimestamp": cache_timestamp or None,
                "transportPolicy": TRANSPORT_POLICY,
                "warnings": warnings,
            }
        )
    return rows


def load_remote_feed(url: str) -> dict[str, Any]:
    validate_https_url(url, purpose="Hosted feed URL")
    request = Request(url, headers={"Accept": "application/json", "User-Agent": HTTP_USER_AGENT})
    try:
        with build_opener(NoRedirectHandler).open(request, timeout=20) as response:
            text = _response_text(response, url=url, max_response_bytes=MAX_HTTP_RESPONSE_BYTES)
            response_headers = {key: value for key, value in response.headers.items()}
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise IntelUnavailable("Hosted feed URL redirects are not allowed.") from exc
        detail = exc.read().decode("utf-8", errors="replace") if exc.fp is not None else ""
        raise IntelUnavailable(f"{url} returned HTTP {exc.code}: {detail or exc.reason}") from exc
    except URLError as exc:
        raise IntelUnavailable(f"{url} could not be reached: {exc.reason}") from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntelUnavailable(f"{url} returned invalid JSON.") from exc
    _verify_feed_signature(url, payload, text, response_headers)
    return normalize_feed_artifact(payload, default_source="live_feed")


def feed_signature_verification_enabled() -> bool:
    return bool(signatures.load_trusted_public_keys())


def _verify_feed_signature(url: str, payload: Any, raw_text: str, headers: dict[str, str]) -> None:
    """Verify a hosted feed against operator-configured trusted keys.

    When keys are configured, a valid signature is required: a missing or invalid
    signature raises ``IntelUnavailable`` so ``runtime_feed`` falls back to the last
    good cache/seed and surfaces a ``feed_refresh_failed`` warning. When no keys are
    configured, verification is skipped (legacy ``hosted_feed_unverified`` behaviour).
    """
    trusted = signatures.load_trusted_public_keys()
    if not trusted:
        return
    mode = str(os.getenv("POUNCE_FEED_SIGNATURE_MODE", "envelope")).strip().lower()
    if mode == "header":
        token = headers.get("X-Pounce-Feed-Signature") or headers.get("x-pounce-feed-signature")
        payload_bytes = raw_text.encode("utf-8")
    else:
        token = payload.get("signature") if isinstance(payload, dict) else None
        payload_bytes = signatures.canonicalize_envelope(payload) if isinstance(payload, dict) else b""
    if not token:
        raise IntelUnavailable(f"Hosted feed at {url} is missing a required signature.")
    try:
        signatures.verify_jws_compact(str(token), payload_bytes, trusted=trusted)
    except signatures.FeedSignatureInvalid as exc:
        raise IntelUnavailable(f"Hosted feed signature invalid: {exc}") from exc


def validate_https_url(url: str, *, purpose: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise IntelUnavailable(f"{purpose} must use an https URL.")
    if not parsed.netloc:
        raise IntelUnavailable(f"{purpose} must include a valid host.")
    if parsed.username or parsed.password:
        raise IntelUnavailable(f"{purpose} must not include credentials.")
    if parsed.fragment:
        raise IntelUnavailable(f"{purpose} must not include a fragment.")


def persist_feed_cache(
    feed: dict[str, Any],
    *,
    fetched_at: str | None = None,
    fetched_from: str | None = None,
    cache_kind: str = "localSync",
) -> None:
    state = storage.read_feed_state() or {}
    state[cache_kind] = feed_cache_envelope(
        normalize_feed_artifact(feed, observed_at=fetched_at, default_source=str(fetched_from or cache_kind)),
        fetched_at=fetched_at or iso_now(),
        fetched_from=fetched_from,
    )
    state["updatedAt"] = iso_now()
    storage.write_feed_state(state)


def feed_cache_envelope(feed: dict[str, Any], *, fetched_at: str, fetched_from: str | None) -> dict[str, Any]:
    return {"feed": feed, "fetched_at": fetched_at, "fetched_from": fetched_from}


def merge_feed_artifacts(seed: dict[str, Any], selected: dict[str, Any]) -> dict[str, Any]:
    items_by_id: dict[str, dict[str, Any]] = {}
    for feed in (seed, selected):
        items = feed.get("items") if isinstance(feed, dict) else []
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and item.get("id"):
                items_by_id[str(item["id"])] = item

    sources_by_name: dict[str, dict[str, Any]] = {}
    for feed in (seed, selected):
        sources = feed.get("sources") if isinstance(feed, dict) else []
        if not isinstance(sources, list):
            continue
        for source in sources:
            if isinstance(source, dict):
                name = str(source.get("name", "unknown")).strip() or "unknown"
                sources_by_name[name] = source

    return {
        "schema_version": FEED_SCHEMA_VERSION,
        "generated_at": str(selected.get("generated_at") or seed.get("generated_at") or iso_now()),
        "sources": sorted(sources_by_name.values(), key=lambda item: str(item.get("name", ""))),
        "items": sorted(items_by_id.values(), key=lambda item: str(item.get("id", ""))),
    }


def human_age(timestamp: str | None) -> str:
    parsed = parse_timestamp(timestamp)
    if parsed is None:
        return "unknown"
    seconds = max(0, int((now_utc() - parsed).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h"
    return f"{hours // 24}d"


def _normalize_sources(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    sources: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        source = {key: current for key, current in item.items() if current not in {None, ""}}
        if source:
            sources.append(source)
    return sources


def _normalize_feed_item(item: dict[str, Any], *, observed_at: str, default_source: str) -> dict[str, Any] | None:
    match = normalize_match_payload(item.get("match"))
    if match is None:
        return None

    item_id = str(item.get("id", "")).strip()
    if not item_id:
        item_id = f"{default_source}:{match.get('type')}:{json.dumps(match, sort_keys=True)}"

    action = str(item.get("action", "")).strip().lower()
    if not action:
        severity = str(item.get("severity", "")).strip().lower()
        action = "block" if severity in {"critical", "high"} else "warn"
    if action not in {"warn", "block"}:
        action = "warn"

    source = str(item.get("source", "")).strip() or default_source
    source_refs = item.get("source_refs")
    if not isinstance(source_refs, list) or not source_refs:
        source_refs = [{"kind": source, "id": item_id}]

    normalized = {
        "id": item_id,
        "kind": str(item.get("kind", "")).strip() or ("malicious_package" if action == "block" else "vulnerability"),
        "match": match,
        "action": action,
        "confidence": _clamp_float(item.get("confidence"), 1.0 if action == "block" else 0.75),
        "reason": str(item.get("reason", "")).strip() or "Threat intelligence finding.",
        "source": source,
        "source_refs": [ref for ref in source_refs if isinstance(ref, dict)],
        "published_at": str(item.get("published_at", "")).strip() or observed_at,
        "modified_at": str(item.get("modified_at", "")).strip() or observed_at,
        "first_seen": str(item.get("first_seen", "")).strip() or observed_at,
        "last_seen": str(item.get("last_seen", "")).strip() or observed_at,
    }
    for optional in ("expires_at", "revoked_at", "revocation_reason", "signature"):
        if item.get(optional) not in {None, ""}:
            normalized[optional] = item[optional]
    if isinstance(item.get("metadata"), dict):
        normalized["metadata"] = item["metadata"]
    return normalized


def _cached_envelope(cache_kind: str) -> dict[str, Any]:
    state = storage.read_feed_state() or {}
    envelope = state.get(cache_kind)
    return envelope if isinstance(envelope, dict) else {}


def _normalize_cached_feed(envelope: dict[str, Any], *, observed_at: str, default_source: str) -> dict[str, Any]:
    feed = envelope.get("feed")
    if isinstance(feed, dict):
        return normalize_feed_artifact(feed, observed_at=observed_at, default_source=default_source)
    return normalize_feed_artifact({"items": []}, observed_at=observed_at, default_source=default_source)


def _stale_warning(feed: dict[str, Any], envelope: dict[str, Any], selected_from: str) -> dict[str, Any] | None:
    if selected_from not in {"remote", "remote_cache", "local_sync_cache"}:
        return None
    references = [parse_timestamp(feed.get("generated_at")), parse_timestamp(envelope.get("fetched_at"))]
    timestamps = [item for item in references if item is not None]
    if not timestamps:
        return None
    age_seconds = (now_utc() - min(timestamps)).total_seconds()
    stale_seconds = stale_after_hours() * 3600
    if age_seconds < stale_seconds:
        return None
    hours = round(age_seconds / 3600, 1)
    return _feed_warning("feed_stale", f"Threat intelligence feed is stale ({hours} hours old based on feed freshness).", selected_from)


def _feed_warning(code: str, detail: str, selected_from: str) -> dict[str, Any]:
    return {"code": code, "detail": detail, "selected_from": selected_from}


def _range_matches(version_spec: str, version: str, ecosystem: str) -> bool:
    spec = version_spec.strip()
    if not spec:
        return False
    return version_ranges.satisfies(version, spec, ecosystem=ecosystem)


def _response_text(response: Any, *, url: str, max_response_bytes: int) -> str:
    content_length = response.headers.get("Content-Length")
    if content_length:
        try:
            parsed_length = int(content_length)
        except ValueError:
            parsed_length = 0
        if parsed_length > max_response_bytes:
            raise IntelUnavailable(f"{url} exceeded the {max_response_bytes} byte response limit.")

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > max_response_bytes:
            raise IntelUnavailable(f"{url} exceeded the {max_response_bytes} byte response limit.")
        chunks.append(chunk)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IntelUnavailable(f"{url} returned a non-UTF-8 response.") from exc


def _clamp_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))

