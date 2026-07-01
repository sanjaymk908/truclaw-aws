#!/usr/bin/env python3
"""
TruClaw AWS admin CLI — port of truclaw_adk/admin_cli.py.

Usage:
  python -m admin.cli clear-ledger --agent-id <id>
  python -m admin.cli clear-memory --agent-id <id>
  python -m admin.cli clear-all --agent-id <id>
  python -m admin.cli view-ledger --agent-id <id> [--limit N]

Requires AWS credentials (same as any boto3 CLI usage) and
TRUCLAW_ADMIN_KEY / TRUCLAW_ADMIN_KEY_HASH exactly as truclaw_adk did --
that check is unchanged since it has nothing to do with GCP vs AWS.
"""
import argparse
import hashlib
import json
import os
import sys

from truclaw_aws import ledger


def _require_admin_key() -> None:
    provided = os.getenv("TRUCLAW_ADMIN_KEY", "").strip()
    expected_hash = os.getenv("TRUCLAW_ADMIN_KEY_HASH", "").strip()

    if not provided:
        print("ERROR: TRUCLAW_ADMIN_KEY not set.")
        sys.exit(1)
    if not expected_hash:
        print("ERROR: TRUCLAW_ADMIN_KEY_HASH not configured.")
        sys.exit(1)
    if hashlib.sha256(provided.encode()).hexdigest() != expected_hash:
        print("ERROR: Invalid admin key.")
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(prog="truclaw-admin")
    sub = parser.add_subparsers(dest="command")

    for name in ("clear-ledger", "clear-memory", "clear-all", "view-ledger"):
        p = sub.add_parser(name)
        p.add_argument("--agent-id", required=True)
        if name == "view-ledger":
            p.add_argument("--limit", type=int, default=20)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    _require_admin_key()

    if args.command == "clear-ledger":
        n = ledger.clear_ledger(args.agent_id)
        print(f"Ledger cleared for agentId={args.agent_id} ({n} objects deleted).")
    elif args.command == "clear-memory":
        ledger.clear_memory(args.agent_id)
        print(f"Memory cleared for agentId={args.agent_id}.")
    elif args.command == "clear-all":
        n = ledger.clear_ledger(args.agent_id)
        ledger.clear_memory(args.agent_id)
        print(f"Ledger ({n} objects) and memory cleared for agentId={args.agent_id}.")
    elif args.command == "view-ledger":
        events = ledger.read_events(args.agent_id, limit=args.limit)
        if not events:
            print("No events in ledger.")
            return
        for e in events:
            print(json.dumps(e, indent=2, default=str))


if __name__ == "__main__":
    main()
