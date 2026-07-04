"""
Track A/B test client using the official MCP Python SDK, instead of raw
curl -- a bare curl POST straight to "tools/call" gets rejected by any
spec-compliant MCP server, because the protocol requires an `initialize`
handshake first (negotiating protocol version + capabilities) before any
operation other than `ping` is accepted. That's confirmed the root cause
of the first test call's "internal error": the interceptor's CloudWatch
log group never even got created, meaning the Gateway rejected the
request before ever routing to a target or interceptor.

This script does the handshake properly via the SDK's session object,
then calls both the safe-path ("read") and dangerous-path ("send_email")
tools registered on the gateway.

Usage:
  pip install mcp httpx
  python3 test_client.py <bearer-token> <safe|dangerous|both>

Note: this is the first real use of the MCP Python SDK against a live
AgentCore Gateway in this project -- the exact call shapes below are
best-effort against the SDK's documented API, not verified against this
specific Gateway yet. If something doesn't match, the SDK's own error
messages should be far more specific than the raw curl attempt was.
"""
import asyncio
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

GATEWAY_URL = "https://truclawgw-truclaw-gateway-yrcmlcuphn.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"


async def call_tool(token: str, tool_name: str, message: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    print(f"\n=== Calling tool: {tool_name} ===")
    async with streamablehttp_client(GATEWAY_URL, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            # This is the handshake the raw curl attempt skipped.
            init_result = await session.initialize()
            print(f"initialized, server: {init_result.serverInfo}")

            tools = await session.list_tools()
            print(f"tools visible on gateway: {[t.name for t in tools.tools]}")

            print(f"calling {tool_name}({{'message': {message!r}}}) ...")
            result = await session.call_tool(tool_name, {"message": message})
            print(f"result: {result}")


async def main() -> None:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <bearer-token> <safe|dangerous|both>")
        sys.exit(1)

    token = sys.argv[1]
    which = sys.argv[2]

    # AgentCore Gateway namespaces every tool as <targetName>___<toolName>
    # (confirmed via a real tools/list response, see test_client_iam.py) --
    # the bare tool names ("read"/"send_email") only exist inside each
    # target's own schema, not as invokable names on the Gateway itself.
    if which in ("safe", "both"):
        await call_tool(token, "echo-safe___read", "track A test")
    if which in ("dangerous", "both"):
        print("\n(dangerous call will hang until you approve on your paired device, or it times out)")
        await call_tool(token, "echo-dangerous___send_email", "track B test")


if __name__ == "__main__":
    asyncio.run(main())
