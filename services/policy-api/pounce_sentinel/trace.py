from __future__ import annotations

from collections.abc import Mapping
from typing import Any

TRACE_FIELDS = (
    "traceId",
    "foundryTraceId",
    "traceparent",
    "spanId",
    "toolInvocationId",
)

TRACE_HEADER_MAP = {
    "traceparent": "traceparent",
    "x-foundry-trace-id": "foundryTraceId",
    "x-ms-client-request-id": "traceId",
    "x-ms-request-id": "traceId",
}


def trace_metadata(payload: Mapping[str, Any]) -> dict[str, str]:
    metadata: dict[str, str] = {}
    for field in TRACE_FIELDS:
        value = str(payload.get(field, "")).strip()
        if value:
            metadata[field] = value

    if "traceId" not in metadata and "foundryTraceId" in metadata:
        metadata["traceId"] = metadata["foundryTraceId"]
    if (
        "foundryTraceId" not in metadata
        and str(payload.get("source", "")).lower() == "foundry"
        and "traceId" in metadata
    ):
        metadata["foundryTraceId"] = metadata["traceId"]

    return metadata


def trace_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    lowered = {str(key).lower(): str(value).strip() for key, value in headers.items()}
    metadata: dict[str, str] = {}
    for header, field in TRACE_HEADER_MAP.items():
        value = lowered.get(header, "")
        if value:
            metadata.setdefault(field, value)

    if "traceId" not in metadata and "foundryTraceId" in metadata:
        metadata["traceId"] = metadata["foundryTraceId"]
    return metadata


def merge_trace_context(payload: dict[str, Any], headers: Mapping[str, Any]) -> dict[str, Any]:
    metadata = trace_headers(headers)
    if not metadata:
        return payload

    enriched = dict(payload)
    for field, value in metadata.items():
        enriched.setdefault(field, value)
    return enriched
