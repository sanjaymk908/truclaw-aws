"""
Track A/B test client using AWS_IAM (SigV4) inbound auth instead of CUSTOM_JWT.

Why this exists alongside test_client.py: the Gateway's CUSTOM_JWT authorizer
kept rejecting every access token with `insufficient_scope`, even after a
token was minted with a Cognito Resource Server custom scope
(`truclaw/invoke`) that exactly matched the Gateway's own configured
`allowedScopes` -- confirmed via the WWW-Authenticate challenge header
itself demanding `scope="truclaw/invoke"` while presenting a token that
carried exactly that scope. Every documented lever (Resource Server,
client_credentials grant, allowedScopes, allowedAudience) was configured
correctly per AWS's docs; the rejection persisted regardless. That's either
a genuine AgentCore platform bug or a very obscure Cognito/AgentCore
interaction -- filed as an open follow-up (see docs/ARCHITECTURE.md), not
solved here.

To unblock Track A/B testing of TruClaw's actual logic (interceptor,
danger classification, escalation state machine -- none of which cares
which inbound auth type the Gateway uses), this script switches the
Gateway to AWS_IAM auth instead and signs requests with the caller's own
AWS credentials via SigV4, using AWS's own `mcp-proxy-for-aws` package
(https://github.com/aws/mcp-proxy-for-aws) rather than hand-rolling
signing logic.

Prerequisites (see README.md / ARCHITECTURE.md for the full commands):
  1. Gateway's authorizerType switched to AWS_IAM via
     `aws bedrock-agentcore-control update-gateway`.
  2. The AWS credentials active in this shell (`aws sts get-caller-identity`)
     need `bedrock-agentcore:InvokeGateway` on this Gateway's ARN -- already
     covered if you're using the AdministratorAccess IAM user set up earlier
     in this project.

Usage:
  pip install mcp mcp-proxy-for-aws
  python3 test_client_iam.py <safe|dangerous|both> [agent-id]

No bearer token needed -- auth comes from whatever AWS credentials are
active in the environment (profile, env vars, or instance/role credentials).

agent-id (optional, defaults to "test-agent-a") is the calling agent's own
declared identity -- passed as MCP's standard per-request `_meta.agentId`
field on every tools/call (see interceptor/handler.py's `_parse_gateway_event`
for why this replaced deriving agentId from the caller's IAM principal: IAM
identity answers "who is authenticating", not "which agent is this", and a
fleet of agents sharing one execution role would otherwise all collapse
into a single agentId). Run this script twice with two different agent-ids
to see two distinct agentId values in the logs/ledger, e.g.:
  python3 test_client_iam.py safe agentA
  python3 test_client_iam.py safe agentB
"""
import asyncio
import sys

from mcp import ClientSession
from mcp_proxy_for_aws.client import aws_iam_streamablehttp_client

GATEWAY_URL = "https://truclawgw-iam-test-x8ubuihr18.gateway.bedrock-agentcore.us-east-1.amazonaws.com/mcp"
# Testing-only AWS_IAM Gateway, created as a workaround for the CUSTOM_JWT
# insufficient_scope issue documented in docs/ARCHITECTURE.md. Same
# interceptor Lambda and same underlying echo-tool targets as the original
# CUSTOM_JWT Gateway (truclawgw-truclaw-gateway-yrcmlcuphn) -- only the
# inbound auth type differs.
AWS_REGION = "us-east-1"


async def call_tool(tool_name: str, message: str, agent_id: str) -> None:
    print(f"\n=== Calling tool: {tool_name} (agentId={agent_id}) ===")
    async with aws_iam_streamablehttp_client(
        endpoint=GATEWAY_URL,
        aws_service="bedrock-agentcore",
        aws_region=AWS_REGION,
        # Default read timeout (30s) is shorter than the interceptor's own
        # escalation poll deadline (CHALLENGE_TIMEOUT_SECONDS=120s + a 10s
        # margin, see interceptor/handler.py:_escalate) -- the dangerous-path
        # call legitimately takes up to ~130s while it waits on Step
        # Functions for a real device approval/denial. Without this, the
        # client's own HTTP connection times out and raises httpx.ReadTimeout
        # well before the interceptor is done, even though the interceptor
        # itself is working correctly. 150s gives headroom over that ~130s.
        timeout=150,
    ) as (read, write, _):
        async with ClientSession(read, write) as session:
            init_result = await session.initialize()
            print(f"initialized, server: {init_result.serverInfo}")

            tools = await session.list_tools()
            print(f"tools visible on gateway: {[t.name for t in tools.tools]}")

            print(f"calling {tool_name}({{'message': {message!r}}}) with agentId={agent_id!r} ...")
            # meta -> serialized as the JSON-RPC request's params._meta (MCP's
            # standard out-of-band metadata field, confirmed via mcp SDK's
            # ClientSession.call_tool / RequestParams.Meta, which allows
            # arbitrary extra keys) -- kept fully separate from `arguments`
            # so it never touches the tool's own parameter schema.
            result = await session.call_tool(
                tool_name, {"message": message}, meta={"agentId": agent_id}
            )
            print(f"result: {result}")


async def main() -> None:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <safe|dangerous|both> [agent-id]")
        sys.exit(1)

    which = sys.argv[1]
    agent_id = sys.argv[2] if len(sys.argv) > 2 else "test-agent-a"

    # AgentCore Gateway namespaces every tool as <targetName>___<toolName>
    # (confirmed via a real tools/list response: ['echo-dangerous___send_email',
    # 'echo-safe___read']) -- the bare tool names ("read"/"send_email") only
    # exist inside each target's own schema, not as invokable names on the
    # Gateway itself. Calling the bare name gets an "Unknown tool" error from
    # the Gateway's own routing, *after* the interceptor has already allowed
    # the call -- this tripped up the first real test run.
    if which in ("safe", "both"):
        await call_tool("echo-safe___read", "track A test", agent_id)
    if which in ("dangerous", "both"):
        print("\n(dangerous call will hang until you approve on your paired device, or it times out)")
        await call_tool("echo-dangerous___send_email", "track B test", agent_id)


if __name__ == "__main__":
    asyncio.run(main())
