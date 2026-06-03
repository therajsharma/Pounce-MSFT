from __future__ import annotations

import json
import re
from typing import Any


REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.!+\-]+)\s*$")


def scan_dependencies(ecosystem: str, content: str) -> list[dict[str, str]]:
    if ecosystem == "npm":
        return _scan_package_json(content)
    if ecosystem == "pypi":
        return _scan_requirements(content)
    return []


def _scan_package_json(content: str) -> list[dict[str, str]]:
    try:
        parsed: dict[str, Any] = json.loads(content)
    except json.JSONDecodeError:
        return []

    dependencies: list[dict[str, str]] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        section_value = parsed.get(section, {})
        if not isinstance(section_value, dict):
            continue
        for package_name, version in section_value.items():
            dependencies.append(
                {
                    "packageName": str(package_name),
                    "version": str(version),
                    "section": section,
                }
            )
    return dependencies


def _scan_requirements(content: str) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    for line in content.splitlines():
        match = REQUIREMENT_RE.match(line)
        if not match:
            continue
        dependencies.append({"packageName": match.group(1), "version": match.group(2)})
    return dependencies

