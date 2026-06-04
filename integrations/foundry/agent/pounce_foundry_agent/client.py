from __future__ import annotations

import json
import os
from typing import Any
from urllib.error import HTTPError
from urllib.parse import quote, urljoin
from urllib.request import Request, urlopen

JsonObject = dict[str, Any]


class PouncePolicyClient:
    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        timeout_seconds: float = 20.0,
    ) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_env(cls) -> "PouncePolicyClient":
        return cls(
            base_url=os.getenv(
                "POUNCE_SENTINEL_API_BASE_URL",
                "https://pouncesentineldev-api.azurewebsites.net/api",
            ),
            api_key=os.getenv("POUNCE_SENTINEL_API_KEY"),
            timeout_seconds=float(os.getenv("POUNCE_SENTINEL_API_TIMEOUT_SECONDS", "20")),
        )

    def vet_dependency(self, payload: JsonObject) -> JsonObject:
        return self._request_json("POST", "v1/vet-dependency", payload)

    def scan_manifest(self, payload: JsonObject) -> JsonObject:
        return self._request_json("POST", "v1/scan-manifest", payload)

    def explain_verdict(self, audit_id: str) -> JsonObject:
        encoded = quote(audit_id, safe="")
        return self._request_json("GET", f"v1/verdicts/{encoded}/explain")

    def request_exception(self, payload: JsonObject) -> JsonObject:
        return self._request_json("POST", "v1/exceptions", payload)

    def _request_json(
        self,
        method: str,
        path: str,
        payload: JsonObject | None = None,
    ) -> JsonObject:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "User-Agent": "pounce-sentinel-foundry-agent/0.2.0",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["x-functions-key"] = self.api_key

        request = Request(
            urljoin(self.base_url, path),
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return _decode_json(response.read())
        except HTTPError as exc:
            error = _decode_json(exc.read())
            error.setdefault("statusCode", exc.code)
            return error


def _decode_json(raw: bytes) -> JsonObject:
    if not raw:
        return {}
    payload = json.loads(raw.decode("utf-8"))
    return payload if isinstance(payload, dict) else {"value": payload}
