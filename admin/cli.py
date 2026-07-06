#!/usr/bin/env python3
"""
TruClaw AWS admin CLI — port of truclaw_adk/admin_cli.py.

Usage:
  python -m admin.cli clear-ledger --agent-id <id>
  python -m admin.cli clear-memory --agent-id <id>
  python -m admin.cli clear-all --agent-id <id>
  python -m admin.cli view-ledger --agent-id <id> [--limit N]
  python -m admin.cli view-memory --agent-id <id>
  python -m admin.cli pair-device --user-id <id> [--timeout N]
  python -m admin.cli list-devices --user-id <id>

Requires AWS credentials (same as any boto3 CLI usage) and
TRUCLAW_ADMIN_KEY / TRUCLAW_ADMIN_KEY_HASH exactly as truclaw_adk did --
that check is unchanged since it has nothing to do with GCP vs AWS.

pair-device / list-devices are new in this port -- nothing in truclaw-aws
previously called truclaw_aws/pairing.py's start_pairing()/poll_for_pairing()
at all. The relay + OpenClaw companion app (TRUKYC_RELAY_URL,
TRUCLAW_PAIRING_DEEPLINK_BASE) are unchanged, external, already-deployed
infrastructure from the original ADK project -- this CLI command is just
the missing piece that actually drives the handshake and persists the
result via pairing.save_pairing().
"""
import argparse
import asyncio
import hashlib
import json
import os
import sys

from truclaw_aws import ledger, pairing


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


async def _pair_device(user_id: str, timeout_seconds: int) -> None:
    """Drives the full pairing handshake synchronously from the CLI: starts
    a session against the relay, prints the link/QR for the human to open
    on their OpenClaw companion app, blocks polling the relay until the app
    completes the handshake (or the timeout passes), and persists the result
    via pairing.save_pairing(). Uses start_background_poll=False and awaits
    poll_for_pairing() directly here instead, since a CLI process has no
    "background" to run a fire-and-forget task in past its own exit."""
    result = await pairing.start_pairing(user_id, start_background_poll=False)
    if result.get("status") != "pairing_started":
        print(f"ERROR: {result.get('reason', 'could not start pairing')}")
        sys.exit(1)

    print("Open this link (or scan the QR) with your TruClaw/OpenClaw companion app:")
    print(f"  Link: {result['pairingLink']}")
    print(f"  QR:   {result['qrImageUrl']}")
    print(f"\nWaiting up to {timeout_seconds}s for the device to complete pairing...")

    data = await pairing.poll_for_pairing(result["sessionId"], timeout_seconds=timeout_seconds)
    if not data:
        print(
            "\nTimed out waiting for pairing -- no device was paired. "
            "Nothing was persisted; re-run this command to try again."
        )
        sys.exit(1)

    composite = pairing.save_pairing(result["sessionId"], data, user_id=user_id)
    print(f"\nPaired successfully: {composite}")
    print(f"  platform: {data.get('platform')}")


def _list_devices(user_id: str) -> None:
    devices = pairing.find_paired_devices_for_user(user_id)
    if not devices:
        print(f"No paired devices for userId={user_id}.")
        return
    for d in devices:
        print(json.dumps({k: v for k, v in d.items() if k != "publicKey"}, indent=2, default=str))
        print(f"  publicKey (sha256 prefix): {pairing._public_key_hash(d['publicKey'])}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="truclaw-admin")
    sub = parser.add_subparsers(dest="command")

    for name in ("clear-ledger", "clear-memory", "clear-all", "view-ledger", "view-memory"):
        p = sub.add_parser(name)
        p.add_argument("--agent-id", required=True)
        if name == "view-ledger":
            p.add_argument("--limit", type=int, default=20)

    pair_p = sub.add_parser("pair-device")
    pair_p.add_argument("--user-id", default="default")
    pair_p.add_argument("--timeout", type=int, default=300)

    list_p = sub.add_parser("list-devices")
    list_p.add_argument("--user-id", default="default")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    _require_admin_key()

    if args.command == "pair-device":
        asyncio.run(_pair_device(args.user_id, args.timeout))
        return
    if args.command == "list-devices":
        _list_devices(args.user_id)
        return

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
    elif args.command == "view-memory":
        memory = ledger.read_memory(args.agent_id)
        if not memory:
            print(
                f"No memory found for agentId={args.agent_id}. "
                "It's generated by the hourly aggregator Lambda -- either it "
                "hasn't run yet for this agent, or there's no ledger activity "
                "for it yet. See aggregator/handler.py; can be invoked "
                "directly to force generation instead of waiting."
            )
            return
        print(memory)


if __name__ == "__main__":
    main()
