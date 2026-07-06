"""
AgentCore Gateway REQUEST interceptor — the native "before-tool-call hook".

The request/tool-call event shape (`_parse_gateway_event`) is confirmed
against real invocations, not guessed -- see docs/ARCHITECTURE.md.

*** agent_id is no longer derived from IAM/network identity ***
An earlier version derived agent_id from `context.identity.awsPrincipalArn`
(the calling IAM principal). That was wrong the same way the earlier Step
Functions detour was wrong: a plausible-sounding platform-idiomatic guess
that was never checked against what the original ADK implementation
actually did. It read the developer-declared `LlmAgent(name=...)` off the
in-process agent object (truclaw_adk/guardrail.py:_root_agent_id) -- an
application-level identity the agent chooses for itself, completely
unrelated to auth. A fleet of AWS agents sharing one execution role/IAM
identity (normal on AWS) would have collapsed into one shared agentId,
silently merging their policies and ledgers. Fixed: agent_id is now read
from the agent's own declared value in MCP's standard per-request `_meta`
field (`params._meta.agentId`), with the old IAM-derived value kept only as
a fallback. See `_parse_gateway_event` for the exact code.

The response shape below was previously WRONG -- an invented
`{"action": "ALLOW"|"DENY"}` payload that isn't AWS's actual contract at
all. Confirmed live: the Gateway rejected it with "Received invalid
response from interceptor". The real contract (confirmed against
https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html,
official docs, not inferred) has no allow/deny verb. A REQUEST interceptor
must return one of:
  - `mcp.transformedGatewayRequest.body` -- the (optionally modified)
    JSON-RPC request body. Returning this lets the Gateway proceed to call
    the target. ALLOW = return the original body unchanged.
  - `mcp.transformedGatewayResponse` (`statusCode` + JSON-RPC `body`) --
    short-circuits the call; the Gateway responds with this immediately and
    never invokes the target ("If the interceptor output contains a
    transformedGatewayResponse, the gateway will respond with that content
    immediately, even if transformedGatewayRequest is also provided.").
    DENY = synthesize a JSON-RPC error response ourselves, since there's no
    native reject verb. The JSON-RPC error `code` used below (-32001) is a
    best-effort choice within the implementation-defined server-error range
    (-32000 to -32099 per the JSON-RPC 2.0 spec) -- AWS's docs don't show a
    worked DENY/error example, so the exact code isn't independently
    confirmed, only the envelope shape is.
Both cases are wrapped in `{"interceptorOutputVersion": "1.0", "mcp": {...}}`.

This replaces truclaw_adk's approach of monkey-patching ADK's
`before_tool_callback` on the live agent tree (see the old protect.py /
autopatch.py). That approach only ever covered agents you personally wrote
in ADK. This interceptor fires for every tool call the Gateway routes,
regardless of which framework built the calling agent — which is the
difference between "our agent has guardrails" and "TruClaw governs the
fleet."

Design (see docs/ARCHITECTURE.md for the full writeup):
  1. Parse identity + tool call out of the Gateway event.
  2. Run the same four-path decision the original implementation always ran
     (danger.check_danger).
  3. ALLOW / DENY resolve immediately — this is the common case and stays
     synchronous and cheap.
  4. ESCALATE calls truclaw_aws/challenge.py's send_challenge() directly and
     awaits it, in this same Lambda invocation, bounded by
     TRUCLAW_CHALLENGE_TIMEOUT_SECONDS (default 120s).

     *** Rearchitected away from Step Functions (was over-engineered) ***
     An earlier version of this routed ESCALATE through a Step Functions
     STANDARD state machine + task-token callback pattern, on the
     assumption that the push-notification relay would call back into an
     AWS webhook when the device responded. That assumption was never
     checked against the relay and turned out to be wrong: the relay is
     poll-based (push a challenge, then poll for the result -- see
     truclaw_aws/challenge.py's docstring and docs/ARCHITECTURE.md for the
     full story, found via two rounds of live relay 400s and finally
     reading truclaw_adk/challenge.py in full). Once `send_challenge()`
     does the entire push-then-poll cycle itself, there's no unpredictable
     external caller left to wait for durably -- the whole reason Step
     Functions was there in the first place. Collapsed back to a direct
     await, same shape as the original ADK's `before_tool_callback`: one
     process, one push, one poll loop, one answer. No state machine, no
     task token, no separate Lambda for this.
"""
import asyncio
import json
from typing import Any, Dict

from truclaw_aws import config
from truclaw_aws.challenge import send_challenge
from truclaw_aws.danger import check_danger
from truclaw_aws.ledger import append_event
from truclaw_aws.logging import log


def _parse_gateway_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Real shape, confirmed via a live diagnostic capture against a
    deployed Gateway (not guessed -- see docs/ARCHITECTURE.md for the raw
    event this was reverse-engineered from):

        event = {
          "interceptorInputVersion": "1.0",
          "mcp": {
            "gatewayRequest": {
              "path": "/mcp", "httpMethod": "POST",
              "headers": {...},  # empty today, passRequestHeaders=false
              "body": {"id": ..., "method": "...", "params": {...}, "jsonrpc": "2.0"},
              "context": ...  # null on the one real event seen so far (an
                               # `initialize` call) -- identity extraction
                               # below is still best-effort until a real
                               # authenticated tools/call is captured.
            },
            "gatewayResponse": ...,  # presumably populated for RESPONSE-type interceptions
            "rawGatewayRequest": {"body": "<raw JSON string>"}
          }
        }

    Critical thing this shape revealed that the earlier guess completely
    missed: the interceptor fires on EVERY MCP protocol message flowing
    through the Gateway, not just tool invocations -- `initialize`,
    `tools/list`, `notifications/initialized`, `ping`, etc. all hit this
    same interceptor. Only `body.method == "tools/call"` has a tool
    name/arguments to evaluate (per the MCP spec, `params` for that method
    is `{"name": ..., "arguments": {...}}`). Every other method must be
    passed through without ever reaching check_danger() -- that's the
    actual bug that crashed the first real invocation (tool_name was None
    for an `initialize` call, and check_danger() isn't meant to be called
    for non-tool-call messages at all, not just handed a None safely).
    """
    gateway_request = (event.get("mcp") or {}).get("gatewayRequest") or {}
    body = gateway_request.get("body") or {}
    method = body.get("method")

    # `body` is carried through unconditionally -- both the passthrough
    # (non-tool-call) and ALLOW paths need the original JSON-RPC body to
    # echo back via transformedGatewayRequest, and the DENY path needs
    # body.get("id") to build a well-formed JSON-RPC error response.
    if method != "tools/call":
        return {"isToolCall": False, "method": method, "tool": None, "args": {}, "agentId": "unknown", "userId": "default", "body": body}

    params = body.get("params") or {}
    tool = params.get("name")
    args = params.get("arguments") or {}

    # agent_id: MUST be something the agent itself declares, not something
    # inferred from the network/auth layer. Confirmed against the original
    # ADK implementation (truclaw_adk/guardrail.py:_root_agent_id) -- it
    # read the developer-supplied `LlmAgent(name="...")` off the in-process
    # agent object. There is no AWS/network equivalent of that: the IAM
    # principal (or JWT subject) calling the Gateway identifies WHO IS
    # AUTHENTICATING, not WHICH AGENT this is -- a fleet of agents sharing
    # one execution role/credential (a completely normal AWS pattern) would
    # otherwise all collapse into the same agentId, silently sharing one
    # policy file and one audit ledger. That was a real bug in the earlier
    # awsPrincipalArn-derived version, not just a testing artifact.
    #
    # Fix: the agent declares its own id per call, via MCP's standard `_meta`
    # field on tools/call (params._meta -- see the MCP spec / mcp Python
    # SDK's `RequestParams.Meta`, which explicitly allows arbitrary extra
    # keys for exactly this kind of out-of-band, protocol-native metadata).
    # This keeps the agent's identity completely separate from the tool's
    # own argument schema -- callers pass it as
    # `session.call_tool(name, arguments, meta={"agentId": "agentA"})`.
    # Falls back to the IAM-principal-derived value (useful only when every
    # agent genuinely has its own dedicated IAM identity) and then
    # "unknown" if neither is present.
    meta = params.get("_meta") or {}
    declared_agent_id = meta.get("agentId") if isinstance(meta, dict) else None

    ctx = gateway_request.get("context") or {}
    identity = ctx.get("identity", {}) if isinstance(ctx, dict) else {}
    aws_principal_arn = identity.get("awsPrincipalArn")
    agent_id = (
        declared_agent_id
        or identity.get("agentId")
        or identity.get("principalId")
        or (aws_principal_arn.rsplit("/", 1)[-1] if aws_principal_arn else None)
        or "unknown"
    )
    user_id = identity.get("userId") or identity.get("sessionUserId") or "default"

    return {"isToolCall": True, "method": method, "tool": tool, "args": args, "agentId": agent_id, "userId": user_id, "body": body}


def _allow_response(request_body: Dict[str, Any]) -> Dict[str, Any]:
    """Let the call proceed to the target, unmodified. Per AWS docs, ALLOW
    is expressed by returning the original request body via
    transformedGatewayRequest -- there's no separate allow verb."""
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {"transformedGatewayRequest": {"body": request_body}},
    }


def _deny_response(request_body: Dict[str, Any], reason: str, **extra) -> Dict[str, Any]:
    """Short-circuit the call with a synthesized JSON-RPC error, returned via
    transformedGatewayResponse -- per AWS docs, this makes the Gateway
    respond immediately without ever invoking the target. See module
    docstring for the caveat on the exact JSON-RPC error `code` used here."""
    req_id = request_body.get("id")
    error_body = {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {
            "code": -32001,
            "message": reason or "Denied by TruClaw policy",
            "data": {k: v for k, v in extra.items() if v is not None},
        },
    }
    return {
        "interceptorOutputVersion": "1.0",
        "mcp": {"transformedGatewayResponse": {"statusCode": 200, "body": error_body}},
    }


async def _decide(tool_name: str, tool_args: Any, agent_id: str, user_id: str) -> Dict[str, Any]:
    """All the async work for one tool call, in one place so `handle()` only
    needs a single `asyncio.run()` call: run the danger check, and if it
    escalates, await send_challenge() directly (see module docstring for
    why this replaced a Step Functions state machine)."""
    decision = await check_danger(tool_name, tool_args, agent_id=agent_id, user_id=user_id)

    base_event = {
        "agentId": agent_id,
        "userId": user_id,
        "toolName": tool_name,
        "toolArgs": tool_args,
        "dangerous": decision.get("dangerous"),
        "reason": decision.get("reason"),
        "safeBypass": decision.get("safeBypass", False),
        "thresholdViolation": decision.get("thresholdViolation", False),
    }

    if not decision.get("dangerous"):
        append_event({**base_event, "allowed": True, "approvalRequired": False})
        return {"allow": True}

    if not config.ENFORCE:
        append_event({**base_event, "allowed": True, "approvalRequired": True, "enforce": False})
        log(f"[interceptor] dangerous but TRUCLAW_ENFORCE=0, allowing tool={tool_name}")
        return {"allow": True}

    approval = await send_challenge(
        action_title=decision.get("actionTitle"),
        action_body=decision.get("actionBody"),
        reason=decision.get("reason"),
        tool_name=tool_name,
        tool_args=tool_args,
        user_id=user_id,
        timeout_seconds=config.CHALLENGE_TIMEOUT_SECONDS,
    )

    if approval.get("approved"):
        append_event({**base_event, "allowed": True, "approvalRequired": True, "approval": approval})
        return {"allow": True}

    append_event({**base_event, "allowed": False, "approvalRequired": True, "approval": approval})
    return {
        "allow": False,
        "reason": approval.get("reason") or decision.get("reason"),
        "actionTitle": decision.get("actionTitle"),
        "actionBody": decision.get("actionBody"),
    }


def handle(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entrypoint. Synchronous by design from the Gateway's point of
    view -- see module docstring for why this now stays a single Lambda
    invocation end to end, including the escalation wait, instead of
    handing off to a separate state machine."""
    # TEMPORARY DIAGNOSTIC — remove once _parse_gateway_event is verified
    # against a real invocation. Logs the complete raw event so the actual
    # Gateway interceptor payload shape can be read from CloudWatch Logs
    # instead of guessed at. Safe to leave in short-term only because
    # passRequestHeaders is currently false on this Gateway (see
    # docs/ARCHITECTURE.md) -- if that's ever flipped to true, this line
    # would start logging raw Authorization headers/tokens and must come
    # out first.
    log(f"[interceptor] RAW EVENT (diagnostic): {json.dumps(event, default=str)}")

    parsed = _parse_gateway_event(event)
    request_body = parsed["body"]

    if not parsed["isToolCall"]:
        # Protocol-level MCP message (initialize, tools/list,
        # notifications/initialized, ping, etc.) -- TruClaw has no opinion
        # on these, they never reach check_danger(). Not logged to the
        # ledger either; this isn't a tool-call decision, there's nothing
        # to audit.
        log(f"[interceptor] non-tool-call MCP method={parsed['method']}, passing through")
        return _allow_response(request_body)

    tool_name, tool_args = parsed["tool"], parsed["args"]
    agent_id, user_id = parsed["agentId"], parsed["userId"]

    log(f"[interceptor] tool={tool_name} agentId={agent_id} userId={user_id}")

    result = asyncio.run(_decide(tool_name, tool_args, agent_id, user_id))

    if result["allow"]:
        return _allow_response(request_body)

    return _deny_response(
        request_body,
        reason=result.get("reason"),
        actionTitle=result.get("actionTitle"),
        actionBody=result.get("actionBody"),
    )
