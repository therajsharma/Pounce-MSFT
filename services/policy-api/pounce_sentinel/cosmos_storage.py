from __future__ import annotations

import os
from typing import Any

DATABASE_NAME = "pounce"
VERDICTS_CONTAINER = "verdicts"
EXCEPTIONS_CONTAINER = "exceptions"


def is_configured() -> bool:
    return bool(os.getenv("AZURE_COSMOS_CONNECTION_STRING"))


def append_verdict(verdict: dict[str, Any]) -> None:
    item = _cosmos_item(verdict)
    _container(_verdicts_container_name()).upsert_item(item)


def list_recent_verdicts(limit: int = 50) -> list[dict[str, Any]]:
    query = "SELECT * FROM c ORDER BY c.createdAt DESC"
    items = _container(_verdicts_container_name()).query_items(
        query=query,
        enable_cross_partition_query=True,
        max_item_count=limit,
    )
    return [_strip_cosmos_metadata(item) for item in list(items)[:limit]]


def append_exception(exception: dict[str, Any]) -> None:
    item = _cosmos_item(exception)
    _container(_exceptions_container_name()).upsert_item(item)


def _cosmos_item(payload: dict[str, Any]) -> dict[str, Any]:
    audit_id = str(payload.get("auditId", "unknown-audit"))
    created_at = str(payload.get("createdAt") or payload.get("requestedAt") or "")
    identifier = str(payload.get("id") or payload.get("exceptionId") or f"{audit_id}-{created_at}")
    item = dict(payload)
    item["id"] = identifier.replace("/", "_")
    item.setdefault("repository", "unknown/repo")
    return item


def _container(container_name: str) -> Any:
    return _database().get_container_client(container_name)


def _database() -> Any:
    return _client().get_database_client(_database_name())


def _client() -> Any:
    from azure.cosmos import CosmosClient

    connection_string = os.getenv("AZURE_COSMOS_CONNECTION_STRING")
    if not connection_string:
        raise RuntimeError("AZURE_COSMOS_CONNECTION_STRING is not configured")
    return CosmosClient.from_connection_string(connection_string)


def _database_name() -> str:
    return os.getenv("AZURE_COSMOS_DATABASE_NAME", DATABASE_NAME)


def _verdicts_container_name() -> str:
    return os.getenv("AZURE_COSMOS_VERDICTS_CONTAINER", VERDICTS_CONTAINER)


def _exceptions_container_name() -> str:
    return os.getenv("AZURE_COSMOS_EXCEPTIONS_CONTAINER", EXCEPTIONS_CONTAINER)


def _strip_cosmos_metadata(item: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if not key.startswith("_") and key != "id"}
