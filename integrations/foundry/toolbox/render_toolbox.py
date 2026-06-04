from __future__ import annotations

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
OPENAPI_PATH = ROOT / "integrations" / "foundry" / "openapi.yaml"
TOOLBOX_PATH = ROOT / "integrations" / "foundry" / "toolbox" / "pounce-sentinel-toolbox.json"


def main() -> None:
    spec = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
    toolbox = {
        "description": "Pounce Sentinel policy tools for agentic dependency governance.",
        "tools": [
            {
                "type": "openapi",
                "name": "pounce-sentinel-policy",
                "description": "Vet dependencies, scan manifests, explain verdicts, and request governed exceptions.",
                "openapi": {
                    "name": "pounce-sentinel-policy",
                    "spec": spec,
                    "auth": {
                        "type": "connection_auth",
                        "connection_id": "pounce-sentinel-api-key",
                    },
                },
            }
        ],
    }
    TOOLBOX_PATH.write_text(json.dumps(toolbox, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
