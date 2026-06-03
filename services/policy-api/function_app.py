from __future__ import annotations

import json
from typing import Any, Callable

from pounce_sentinel.api import (
    create_exception,
    list_verdicts,
    scan_manifest,
    service_status,
    vet_dependency,
)

try:
    import azure.functions as func
except ImportError:  # pragma: no cover - Azure Functions imports this in cloud.
    func = None  # type: ignore[assignment]


def _read_json(req: Any) -> dict[str, Any]:
    try:
        payload = req.get_json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _response(payload: dict[str, Any], status_code: int = 200) -> Any:
    if func is None:
        return payload
    return func.HttpResponse(
        json.dumps(payload, indent=2),
        status_code=status_code,
        mimetype="application/json",
    )


def _route(handler: Callable[[dict[str, Any]], dict[str, Any]]) -> Callable[[Any], Any]:
    def wrapped(req: Any) -> Any:
        result = handler(_read_json(req))
        return _response(result, int(result.get("statusCode", 200)))

    return wrapped


if func is not None:
    app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

    @app.route(route="v1/status", methods=["GET"])
    def status(req: func.HttpRequest) -> func.HttpResponse:
        return _response(service_status())

    @app.route(route="v1/vet-dependency", methods=["POST"])
    def vet(req: func.HttpRequest) -> func.HttpResponse:
        return _route(vet_dependency)(req)

    @app.route(route="v1/scan-manifest", methods=["POST"])
    def scan(req: func.HttpRequest) -> func.HttpResponse:
        return _route(scan_manifest)(req)

    @app.route(route="v1/verdicts", methods=["GET"])
    def verdicts(req: func.HttpRequest) -> func.HttpResponse:
        return _response(list_verdicts())

    @app.route(route="v1/exceptions", methods=["POST"])
    def exceptions(req: func.HttpRequest) -> func.HttpResponse:
        return _route(create_exception)(req)
else:
    app = None

