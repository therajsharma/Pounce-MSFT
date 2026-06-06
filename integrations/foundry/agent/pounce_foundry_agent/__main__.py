from __future__ import annotations

import argparse
import asyncio
import json

from pounce_foundry_agent.agent import run_once, serve
from pounce_foundry_agent.tools import TOOL_NAMES


def main() -> None:
    parser = argparse.ArgumentParser(description="Pounce Sentinel Foundry agent runtime")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("serve", help="Start the Foundry Responses hosted-agent server")
    tools_parser = subparsers.add_parser("tools-json", help="Print the exported policy tool names")
    tools_parser.set_defaults(command="tools-json")
    run_parser = subparsers.add_parser("run", help="Run one prompt against the Foundry agent")
    run_parser.add_argument("prompt")
    args = parser.parse_args()

    if args.command == "tools-json":
        print(json.dumps({"tools": TOOL_NAMES}, indent=2))
        return

    if args.command == "run":
        print(asyncio.run(run_once(args.prompt)))
        return

    serve()


if __name__ == "__main__":
    main()
