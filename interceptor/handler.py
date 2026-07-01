"""
AgentCore Gateway REQUEST interceptor — the native "before-tool-call hook".

*** VERIFY BEFORE PRODUCTION ***
AgentCore Gateway interceptors are a new (2026) capability and the exact
event/response JSON shape is not fully stabilized in public docs at the time
this port was written. `_parse_gateway_event` and the return shape at the
bottom of `handle` are written against the documented *concept* (interceptor
receives tool name/args/identity context, returns allow/deny/transform), not
a verified field-for-field schema. Confirm exact field names against the
current "Using interceptors with Gateway" doc and adjust the two marked
functions before pointing a real Gateway at this — the decision logic in
between (which is the actual hook design) does not need to change.

This replaces truclaw_adk's approach of monkey-patching ADK's
`before_tool_callback` on the live agent tree (see the old protect.py /
autopatch.py). That approach only ever covered agents you personally wrote
in ADK. This interceptor fires for every tool call the Gateway routes,
regardless of which framework built the calling agent — which is the
difference between "our agent has guardrails" and "TruClaw governs the
fleet."

Design (see README.md for the full writeup):
  1. Parse identity + tool call out of the Gateway event.
  2. Run the same four-path decision truclaw_adk always ran (danger.check_danger).
  3. ALLOW / DENY resolve immediately — this is the common case and stays
     synchronous and cheap.
  4. ESCALATE hands off to a short Step Functions Express *synchronous*
     execution (see statemachine/escalation.asl.json) that sends the human
     challenge and waits on a task token, bounded by
     TRUCLAW_CHALLENGE_TIMEOUT_SECONDS. That keeps the wait state in Step
     Functions (durable, externally resumable by resume_handler.py) instead
     of an in-process dict + polling thread, without requiring the Gateway
     itself to support pausing/resuming a call — from the Gateway's point of
     view this interceptor just took a bit longer and returned a normal
     decision.

     NOTE: this bounded-synchronous-wait approach is the right fit as long
     as challenge timeouts stay short (today's default: 120s, well under
     Express Sync's ~5 minute execution cap). If the V1 on-call/escalation
     chain routing we discussed ever needs a longer SLA than that, this
     needs to move to a fully async "return pending, caller retries" model
     instead — flagged in README.md as a known follow-up, not solved here.
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
    """*** VERIFY FIELD NAMES AGAINST CURRENT AGENTCORE GATEWAY DOCS ***

    Expected shape (conceptual, per AWS's "Using interceptors with Gateway"
    docs as of this writing): the interceptor receives the tool/target name,
    the arguments the agent supplied, and identity context propagated by
    AgentCore Identity (the calling agent principal + end-user session).
    """
    tool = event.get("toolName") or event.get("targetName") or event.get("tool", {}).get("name")
    args = event.get("arguments") or event.get("toolArgs") or event.get("input") or {}
    identity = event.get("identity") or event.get("requestContext", {}).get("identity", {})
    agent_id = identity.get("agentId") or identity.get("principalId") or event.get("agentId", "unknown")
    user_id = identity.get("userId") or identity.get("sessionUserId") or event.get("userId", "default")

    return {"tool": tool, "args": args, "agentId": agent_id, "userId": user_id}


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
    parsed = _parse_gateway_event(event)
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

    # ESCALATE — bounded synchronous wait via Step Functions Express Sync.
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
    """Starts the escalation state machine synchronously and waits (bounded
    by CHALLENGE_TIMEOUT_SECONDS + a small margin) for it to resolve."""
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
        resp = client.start_sync_execution(
            stateMachineArn=config.ESCALATION_STATE_MACHINE_ARN,
            name=f"escalation-{int(time.time() * 1000)}",
            input=json.dumps(payload),
        )
    except Exception as e:
        log(f"[interceptor] failed to start escalation workflow: {e}")
        return {"approved": False, "reason": f"escalation start failed: {e}"}

    if resp.get("status") != "SUCCEEDED":
        log(f"[interceptor] escalation workflow did not succeed: {resp.get('status')} {resp.get('error')}")
        return {"approved": False, "reason": resp.get("error") or "escalation workflow failed"}

    try:
        return json.loads(resp["output"])
    except Exception as e:
        log(f"[interceptor] could not parse escalation output: {e}")
        return {"approved": False, "reason": "unparseable escalation result"}
