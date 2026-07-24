"""
Ported from truclaw_adk/danger.py. The three-question rubric and the four
decision paths (safe-tool bypass -> threshold check -> always-dangerous ->
classifier) are unchanged — this logic doesn't care what cloud it runs on.

Classifier call: V1 keeps calling Gemini directly (config.CLASSIFIER_PROVIDER
defaults to "gemini"), exactly as truclaw_adk did. A Bedrock-hosted model is
left as a stub (_bedrock_generate) rather than fully wired — swapping model
providers is a V2 decision independent of the AgentCore hook/S3 port, and
wiring it now without being able to test it against a real Bedrock endpoint
isn't worth the risk of shipping unverified code.
"""
import json
import re
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from . import config
from .logging import log


def normalize_tool_name(tool_name: str) -> str:
    """Strip whatever namespacing wraps the bare tool name before matching
    it against a policy's safeTools/alwaysDangerousTools lists.

    Bug found live (2026-07-08, via the truclaw-aws-samples demo's
    calculator target): this used to be `tool_name.split(".")[-1]` only,
    left over from the original ADK port where a tool's fully-qualified
    name was dot-separated. AgentCore Gateway does NOT use dots -- it
    namespaces every tool as `<targetName>___<toolName>` (triple
    underscore, confirmed against a real `tools/list` response elsewhere
    in this project). So `calculator___calculator` never matched
    `"calculator"` in safeTools, and `payments___process_payment` would
    never have matched `"process_payment"` in alwaysDangerousTools either
    -- every single tool call, safe or dangerous, was silently falling
    through Path 1/Path 3 straight to Path 4 (the live classifier call).
    For alwaysDangerousTools specifically this was worse than just wasted
    latency/cost: it meant "always" wasn't actually guaranteed -- a
    dangerous tool's escalation depended on the classifier agreeing, not
    on a deterministic policy match.

    Splits on both separators (Gateway's `___` first, then the legacy
    `.`) so both naming conventions keep working."""
    name = tool_name.split("___")[-1]
    name = name.split(".")[-1]
    return name


def command_from_args(tool_args: Any) -> str:
    if isinstance(tool_args, dict):
        return str(
            tool_args.get("command") or tool_args.get("cmd") or json.dumps(tool_args, default=str)
        )
    return str(tool_args)


SCRIPT_PATH_PATTERN = re.compile(
    r"^(?:python3?|bash|sh|node|ruby|perl|php|pwsh|powershell)\s+"
    r"([\w./~-]+\.(?:py|sh|js|ts|rb|pl|php|ps1))"
)


def resolve_script_content(command: str) -> Dict[str, Any]:
    m = SCRIPT_PATH_PATTERN.match(command)
    if not m:
        return {"scriptContent": None}
    p = Path(m.group(1)).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
        truncated = len(content) > 6000
        excerpt = content[:6000] + ("\n...[truncated]" if truncated else "")
        return {
            "scriptPath": str(p),
            "scriptSha256": hashlib.sha256(content.encode()).hexdigest(),
            "scriptContent": excerpt,
            "scriptTruncated": truncated,
        }
    except Exception as e:
        return {"scriptPath": str(p), "scriptReadError": str(e), "scriptContent": None}


def extract_json_object(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        raise ValueError("empty classifier response")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
        raise ValueError("classifier JSON was not an object")
    except Exception:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S | re.I)
    if fenced:
        obj = json.loads(fenced.group(1))
        if isinstance(obj, dict):
            return obj
        raise ValueError("classifier fenced JSON was not an object")
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        obj = json.loads(text[start : end + 1])
        if isinstance(obj, dict):
            return obj
        raise ValueError("classifier embedded JSON was not an object")
    raise ValueError(f"No JSON object found in classifier response: {text[:300]}")


def normalize_classifier_decision(decision: Dict[str, Any], tool_name: str) -> Dict[str, Any]:
    dangerous = bool(decision.get("dangerous"))
    reason = str(decision.get("reason") or decision.get("rationale") or "classified")
    action_title = str(
        decision.get("actionTitle")
        or decision.get("action")
        or decision.get("actionDescription")
        or f"Approve: {tool_name}"
    )[:64]
    action_body = str(decision.get("actionBody") or "")[:178]
    return {
        "dangerous": dangerous,
        "reason": reason,
        "actionTitle": action_title,
        "actionBody": action_body,
        "classifierRaw": decision,
    }


async def _gemini_generate(system: str, user: str, max_tokens: int = 300) -> str:
    from google import genai
    from google.genai import types as genai_types

    client = genai.Client(api_key=config.GOOGLE_API_KEY, vertexai=False)
    response = await client.aio.models.generate_content(
        model=config.GEMINI_CLASSIFIER_MODEL,
        contents=user,
        config=genai_types.GenerateContentConfig(
            system_instruction=system,
            max_output_tokens=max_tokens,
            thinking_config=genai_types.ThinkingConfig(thinking_budget=0),
        ),
    )
    return response.text.strip()


def _bedrock_generate(system: str, user: str, max_tokens: int = 300) -> str:
    """V2 stub, not wired into check_danger() below. Shape only — verify the
    Converse API request/response contract against current Bedrock docs
    before using this in production; not exercised against a live endpoint
    in this port."""
    import boto3

    client = boto3.client("bedrock-runtime", region_name=config.AWS_REGION)
    resp = client.converse(
        modelId=config.BEDROCK_CLASSIFIER_MODEL_ID,
        system=[{"text": system}],
        messages=[{"role": "user", "content": [{"text": user}]}],
        inferenceConfig={"maxTokens": max_tokens},
    )
    return resp["output"]["message"]["content"][0]["text"].strip()


async def get_action_description(
    tool_name: str, tool_args: Any, script_content: Optional[str]
) -> Dict[str, str]:
    if not config.GOOGLE_API_KEY:
        return {"title": f"Approve: {tool_name}", "body": ""}

    prompt = (
        f"Script content:\n```\n{script_content}\n```"
        if script_content
        else f"Tool: {tool_name}\nArgs: {json.dumps(tool_args, default=str)}"
    )
    prompt += (
        "\n\nRespond with JSON only, no prose:\n"
        '{"title": "<verb phrase ≤64 chars, e.g. Create P0 ticket>", '
        '"body": "<one sentence ≤178 chars naming the key args, e.g. title, priority, assignee>"}'
    )

    try:
        raw = await _gemini_generate("You are a security analyst.", prompt, max_tokens=80)
        parsed = extract_json_object(raw)
        title = str(parsed.get("title", f"Approve: {tool_name}"))[:64]
        body = str(parsed.get("body", ""))[:178]
        return {"title": title, "body": body}
    except Exception:
        return {"title": f"Approve: {tool_name}", "body": ""}


DANGER_SYSTEM_PROMPT_TMPL = """
You are a security guardrail for an AI agent. Your job is to decide if a tool call
should be blocked and require human biometric approval before execution.

Reply with JSON only. No markdown. No prose.

Schema:
{{
  "dangerous": boolean,
  "reason": "one line",
  "actionTitle": "verb phrase ≤64 chars, e.g. Create P0 ticket",
  "actionBody": "≤178 chars naming key args such as ticket title, priority, assignee"
}}
{business_rules_section}
Core principle:
A tool call is dangerous if it causes an irreversible or harmful side effect in the
real world, or if it is part of a cumulative pattern that would cause such harm.

Ask yourself three questions:

1. DIRECT HARM: Does this single tool call, by itself, cause an irreversible or
   harmful change in the world? Examples: sending money, deleting data, sending a
   message, executing a trade, modifying permissions, installing code, exfiltrating
   data. If yes -> dangerous.

2. CUMULATIVE HARM: Does this tool call, considered alongside prior actions in this
   session, form part of a suspicious pattern that a human would want to review?
   Examples: repeated transactions below detection limits, escalating amounts,
   bulk reads followed by external sends, probing behavior with modified args,
   reading credentials then making network calls. If yes -> dangerous.

3. STRUCTURAL ACTION: Is this tool call purely structural -- routing, delegation,
   reading data for display, searching, listing, querying -- with no real-world side
   effect of its own, and no suspicious cumulative pattern? If yes -> safe.

Key distinctions:
- Reading data is safe. Sending data externally is dangerous.
- Agent transfers are structural and always safe.
- A single read of sensitive data is safe. A read immediately followed by an
  external send is dangerous (cumulative).
- Legitimate multi-step agentic workflows (transfer -> read -> act) are normal.
  The act step should be flagged, not the transfer or read steps.
- One small transaction may be fine. Ten identical small transactions in one
  session is suspicious regardless of individual size.

When in doubt, prefer dangerous. It is better to require a human to approve a
legitimate action than to allow a harmful action without oversight.
""".strip()


async def check_danger(
    tool_name: str,
    tool_args: Any,
    agent_id: str = "unknown",
    user_id: str = "default",
) -> Dict[str, Any]:
    log(f"[guardrail] danger check tool={tool_name} agentId={agent_id} userId={user_id}")

    from .policy import load_policy, load_usage_summary, check_threshold, SAFE_BYPASS
    from .ledger import prior_summary, dangerous_prior_flag

    policy = load_policy(agent_id)
    load_usage_summary(agent_id)

    normalized = normalize_tool_name(tool_name)

    # Path 1: safeTools bypass
    safe_set = set(policy.get("safeTools", []))
    if normalized in safe_set or tool_name in safe_set:
        log(f"[guardrail] safe-tool bypass tool={tool_name}")
        return {
            "dangerous": False,
            "reason": "safe tool bypass",
            "actionTitle": f"Run {tool_name}",
            "actionBody": "",
            "safeBypass": True,
        }

    # Path 2: toolThresholds
    threshold_result = check_threshold(agent_id, user_id, tool_name, tool_args)
    if threshold_result == SAFE_BYPASS:
        log(f"[guardrail] threshold safe-bypass tool={tool_name}")
        return {
            "dangerous": False,
            "reason": "below threshold — safe bypass",
            "actionTitle": f"Run {tool_name}",
            "actionBody": "",
            "safeBypass": True,
        }
    if threshold_result:
        log(f"[guardrail] threshold violation: {threshold_result}")
        action = await get_action_description(tool_name, tool_args, None)
        return {
            "dangerous": True,
            "reason": f"threshold exceeded: {threshold_result}",
            "actionTitle": action["title"],
            "actionBody": action["body"],
            "thresholdViolation": True,
        }

    command = command_from_args(tool_args)
    script = resolve_script_content(command)

    # Path 3: alwaysDangerousTools
    dangerous_set = set(policy.get("alwaysDangerousTools", []))
    if normalized in dangerous_set or tool_name in dangerous_set:
        # Pass the NORMALIZED name, not the raw Gateway-namespaced one --
        # found live via the OWASP Agentic Top 10 test suite (ASI09: Human-
        # Agent Trust Exploitation), confirmed against a real push
        # notification earlier during Task #22: the human's paired-device
        # prompt showed the raw string "payments___process_payment" instead
        # of a readable name, because get_action_description()'s fallback
        # (`f"Approve: {tool_name}"`, used whenever GOOGLE_API_KEY is unset
        # or the classifier call fails) and its Gemini prompt both echo
        # back whatever tool_name they're given verbatim. An unreadable
        # approval prompt is itself a vulnerability -- a human can't
        # meaningfully consent to something they can't parse.
        action = await get_action_description(normalized, tool_args, script.get("scriptContent"))
        return {
            "dangerous": True,
            "reason": "always-dangerous tool",
            "actionTitle": action["title"],
            "actionBody": action["body"],
            **script,
        }

    # Path 4: classifier
    if not config.GOOGLE_API_KEY:
        log("[guardrail] GOOGLE_API_KEY missing; fail closed")
        return {
            "dangerous": True,
            "reason": "GOOGLE_API_KEY not configured",
            "actionTitle": f"Approve: {tool_name}",
            "actionBody": "",
            **script,
        }

    business_rules = policy.get("businessRules", "")
    business_rules_section = (
        f"\nBusiness rules for this agent:\n{business_rules}\n" if business_rules else ""
    )
    system = DANGER_SYSTEM_PROMPT_TMPL.format(business_rules_section=business_rules_section)

    user = (
        f"Tool: {tool_name}\n"
        f"Args: {json.dumps(tool_args, default=str)}\n"
        f"Prior actions:\n{prior_summary(agent_id=agent_id)}\n"
        f"{dangerous_prior_flag(agent_id=agent_id)}\n"
    )
    if script.get("scriptContent"):
        user += f"Script content:\n```\n{script['scriptContent']}\n```\n"

    try:
        text = await _gemini_generate(system, user, max_tokens=300)
        log(f"[guardrail] classifier raw={text[:300]}")
        decision = extract_json_object(text)
        normalized_decision = normalize_classifier_decision(decision, tool_name)
        log(
            f"[guardrail] classifier dangerous={normalized_decision.get('dangerous')} "
            f"reason={normalized_decision.get('reason')}"
        )
        return {**normalized_decision, **script}
    except Exception as e:
        log(f"[guardrail] classifier error; fail closed error={e}")
        return {
            "dangerous": True,
            "reason": f"classifier error: {e}",
            "actionTitle": f"Approve: {tool_name}",
            "actionBody": "",
            **script,
        }
