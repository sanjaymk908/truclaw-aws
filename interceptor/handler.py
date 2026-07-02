"""
AgentCore Gateway REQUEST interceptor — the native "before-tool-call hook".

*** REMAINING VERIFICATION NEEDED ***
The request/tool-call event shape (`_parse_gateway_event`) is now confirmed
against a real invocation, not guessed -- see docs/ARCHITECTURE.md. Two
things are still unverified: (1) identity extraction (`context.identity`)
has only been observed as null, on a non-authenticated `initialize` call --
not yet confirmed against a real authenticated `tools/call`; (2)
`_gateway_response`'s ALLOW/DENY shape hasn't been independently confirmed
as correct by AWS docs, only inferred from the fact that real calls made it
this far without the Gateway itself rejecting the response shape.

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
  4. ESCALATE hands off to a Step Functions STANDARD state machine (see
     statemachine/escalation.asl.json) that sends the human challenge and
     waits on a task token, bounded by TRUCLAW_CHALLENGE_TIMEOUT_SECONDS.
     Standard, not Express: Express workflows don't support
     .waitForTaskToken at all, which was discovered via a failed deploy —
     see _escalate()'s docstring below for the resulting poll-based design.
     Either way, the wait state lives in Step Functions (durable, externally
     resumable by resume_handler.py) instead of an in-process dict + polling
     thread, without requiring the Gateway itself to support
     pausing/resuming a call — from the Gateway's point of view this
     interceptor just took a bit longer and returned a normal decision.

     NOTE: this bounded-wait approach is the right fit as long as challenge
     timeouts stay short (today's default: 120s). If the on-call/escalation
     chain routing discussed as a follow-up ever needs a longer SLA than
     that, this needs to move to a fully async "return pending, caller
     retries" model instead — see docs/ARCHITECTURE.md, not solved here.
"""
import asyncio
import json
import time
from typing import Any, Dict

from truclaw_aws import config
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

    if method != "tools/call":
        return {"isToolCall": False, "method": method, "tool": None, "args": {}, "agentId": "unknown", "userId": "default"}

    params = body.get("params") or {}
    tool = params.get("name")
    args = params.get("arguments") or {}

    # Identity: unverified against a real authenticated call yet (the one
    # real event captured so far had context=null, since `initialize`
    # doesn't carry caller identity). Defensive fallbacks kept so this
    # degrades to "unknown"/"default" rather than crashing if the real
    # shape for an authenticated tools/call turns out to differ.
    ctx = gateway_request.get("context") or {}
    identity = ctx.get("identity", {}) if isinstance(ctx, dict) else {}
    agent_id = identity.get("agentId") or identity.get("principalId") or "unknown"
    user_id = identity.get("userId") or identity.get("sessionUserId") or "default"

    return {"isToolCall": True, "method": method, "tool": tool, "args": args, "agentId": agent_id, "userId": user_id}


def _gateway_response(action: str, **extra) -> Dict[str, Any]:
    """*** VERIFY AGAINST CURRENT DOCS *** — shape of what an interceptor
    returns to allow, deny, or (via the escalation path) resolve a call.
    `action` is one of "ALLOW" | "DENY".
    """
    return {"action": action, **extra}


def handle(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entrypoint. Synchronous by design — see module docstring for
    why individual Lambda invocations stay synchronous even though the
    overall escalation flow is async at the architecture level."""
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

    if not parsed["isToolCall"]:
        # Protocol-level MCP message (initialize, tools/list,
        # notifications/initialized, ping, etc.) -- TruClaw has no opinion
        # on these, they never reach check_danger(). Not logged to the
        # ledger either; this isn't a tool-call decision, there's nothing
        # to audit.
        log(f"[interceptor] non-tool-call MCP method={parsed['method']}, passing through")
        return _gateway_response("ALLOW")

    tool_name, tool_args = parsed["tool"], parsed["args"]
    agent_id, user_id = parsed["agentId"], parsed["userId"]

    log(f"[interceptor] tool={tool_name} agentId={agent_id} userId={user_id}")

    decision = asyncio.run(
        check_danger(tool_name, tool_args, agent_id=agent_id, user_id=user_id)
    )

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
        return _gateway_response("ALLOW")

    if not config.ENFORCE:
        append_event({**base_event, "allowed": True, "approvalRequired": True, "enforce": False})
        log(f"[interceptor] dangerous but TRUCLAW_ENFORCE=0, allowing tool={tool_name}")
        return _gateway_response("ALLOW")

    # ESCALATE — bounded wait via a Step Functions STANDARD execution, polled.
    approval = _escalate(decision, tool_name, tool_args, agent_id, user_id)

    if approval.get("approved"):
        append_event({**base_event, "allowed": True, "approvalRequired": True, "approval": approval})
        return _gateway_response("ALLOW")

    append_event({**base_event, "allowed": False, "approvalRequired": True, "approval": approval})
    return _gateway_response(
        "DENY",
        reason=approval.get("reason") or decision.get("reason"),
        actionTitle=decision.get("actionTitle"),
        actionBody=decision.get("actionBody"),
    )


def _escalate(
    decision: Dict[str, Any], tool_name: str, tool_args: Any, agent_id: str, user_id: str
) -> Dict[str, Any]:
    """Starts the escalation state machine and waits (bounded by
    CHALLENGE_TIMEOUT_SECONDS + a small margin) for it to resolve.

    This is a STANDARD state machine, not Express -- Express workflows
    (including Express Sync) don't support the .waitForTaskToken pattern the
    escalation flow depends on, which is a hard AWS platform limitation
    discovered via an actual failed deploy, not a design choice. Standard
    has no StartSyncExecution API, so instead of blocking on one synchronous
    call, this starts the execution and polls DescribeExecution in a short
    loop until it resolves or the deadline passes. Still synchronous from
    the caller's (Gateway's) point of view -- this function doesn't return
    until it has an answer or gives up -- just implemented as a poll against
    Step Functions' own durable execution state instead of a single blocking
    API call. See infra/cdk/truclaw_stack.py for the IAM side of this.
    """
    import boto3

    if not config.ESCALATION_STATE_MACHINE_ARN:
        log("[interceptor] no state machine configured; fail closed")
        return {"approved": False, "reason": "escalation not configured"}

    client = boto3.client("stepfunctions", region_name=config.AWS_REGION)
    payload = {
        "toolName": tool_name,
        "toolArgs": tool_args,
        "agentId": agent_id,
        "userId": user_id,
        "reason": decision.get("reason"),
        "actionTitle": decision.get("actionTitle"),
        "actionBody": decision.get("actionBody"),
        "timeoutSeconds": config.CHALLENGE_TIMEOUT_SECONDS,
    }

    try:
        resp = client.start_execution(
            stateMachineArn=config.ESCALATION_STATE_MACHINE_ARN,
            name=f"escalation-{int(time.time() * 1000)}",
            input=json.dumps(payload),
        )
    except Exception as e:
        log(f"[interceptor] failed to start escalation workflow: {e}")
        return {"approved": False, "reason": f"escalation start failed: {e}"}

    execution_arn = resp["executionArn"]
    poll_interval_seconds = 2
    deadline = time.time() + config.CHALLENGE_TIMEOUT_SECONDS + 10  # small margin over the state machine's own task timeout

    while time.time() < deadline:
        try:
            desc = client.describe_execution(executionArn=execution_arn)
        except Exception as e:
            log(f"[interceptor] describe_execution error: {e}")
            time.sleep(poll_interval_seconds)
            continue

        status = desc.get("status")
        if status == "SUCCEEDED":
            try:
                return json.loads(desc["output"])
            except Exception as e:
                log(f"[interceptor] could not parse escalation output: {e}")
                return {"approved": False, "reason": "unparseable escalation result"}
        if status in ("FAILED", "TIMED_OUT", "ABORTED"):
            log(f"[interceptor] escalation workflow ended status={status}")
            return {"approved": False, "reason": f"escalation workflow {status.lower()}"}
        # RUNNING -- keep polling
        time.sleep(poll_interval_seconds)

    log(f"[interceptor] escalation poll deadline reached, stopping execution {execution_arn}")
    try:
        client.stop_execution(executionArn=execution_arn, cause="TruClaw interceptor poll timeout")
    except Exception as e:
        log(f"[interceptor] stop_execution error (non-fatal): {e}")
    return {"approved": False, "reason": "escalation timed out"}
