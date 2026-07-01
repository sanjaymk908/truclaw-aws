"""
S3-backed port of truclaw_adk/policy.py.

Policy and usage-summary objects keep the original single-object-per-agent
shape (truclaw_adk/policy.py's read-modify-write concern doesn't really
apply here in practice: policy edits are human-gated and infrequent, and
usage_summary.json / memory.md have exactly one writer — the aggregator
Lambda — so there's nothing to race). Only the ledger and pairing needed the
one-object-per-item redesign; see ledger.py and pairing.py for why.

In-process caching is kept (module-level dict) because a warm Lambda
execution environment reuses the same Python process across invocations —
same benefit the original got from a long-running ADK server process, same
caveat that a cold start (or a different concurrent execution environment)
starts with an empty cache.
"""
import json
import time
from typing import Any, Dict, List, Optional, Set

from .s3_storage import s3_get_bytes, s3_put_bytes
from .logging import log

_DEFAULT_SAFE_TOOLS: List[str] = [
    "read", "session_status", "list", "ls", "web_search", "web_fetch",
    "browser_snapshot", "status", "truclaw_pair", "truclaw_status",
    "transfer_to_agent", "transfer_to_agent_tool", "agent_transfer",
    "load_artifacts", "list_artifacts", "save_artifacts",
]

_DEFAULT_ALWAYS_DANGEROUS_TOOLS: List[str] = [
    "place_trade", "execute_trade", "send_email", "send_email_via_porteden",
    "delete_email", "forward_email", "reply_email",
]

_DEFAULT_BUSINESS_RULES = (
    "No specific business rules configured. "
    "All unclassified tool calls will be evaluated by the security classifier. "
    "Update this field with domain-specific policy before deploying to production."
)

_policy_cache: Dict[str, Dict[str, Any]] = {}
_usage_cache: Dict[str, Dict[str, Any]] = {}

SAFE_BYPASS = "SAFE_BYPASS"


def _policy_key(agent_id: str) -> str:
    return f"truclaw/policies/{agent_id}/TruClaw-Policies.json"


def _usage_key(agent_id: str) -> str:
    return f"truclaw/policies/{agent_id}/usage_summary.json"


def _bootstrap_policy(agent_id: str, known_tools: Optional[Set[str]] = None) -> Dict[str, Any]:
    safe_set = set(_DEFAULT_SAFE_TOOLS)
    dangerous_set = set(_DEFAULT_ALWAYS_DANGEROUS_TOOLS)

    if known_tools is not None:
        unclassified = sorted(known_tools - safe_set - dangerous_set)
        agent_safe = sorted(safe_set & known_tools)
        agent_dangerous = sorted(dangerous_set & known_tools)
    else:
        unclassified = []
        agent_safe = sorted(safe_set)
        agent_dangerous = sorted(dangerous_set)

    policy = {
        "agentId": agent_id,
        "version": "1.0.0",
        "bootstrappedFromCode": True,
        "bootstrappedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "safeTools": agent_safe,
        "alwaysDangerousTools": agent_dangerous,
        "unclassified": unclassified,
        "toolThresholds": {},
        "businessRules": _DEFAULT_BUSINESS_RULES,
    }
    log(
        f"[policy] bootstrapped agentId={agent_id} safe={len(agent_safe)} "
        f"dangerous={len(agent_dangerous)} unclassified={len(unclassified)}"
    )
    return policy


def _save_policy(agent_id: str, policy: Dict[str, Any]) -> None:
    s3_put_bytes(
        json.dumps(policy, indent=2).encode("utf-8"), _policy_key(agent_id)
    )
    log(f"[policy] saved agentId={agent_id} version={policy.get('version')}")


def load_policy(agent_id: str, known_tools: Optional[Set[str]] = None) -> Dict[str, Any]:
    if agent_id in _policy_cache:
        return _policy_cache[agent_id]

    raw = s3_get_bytes(_policy_key(agent_id))
    if raw:
        try:
            policy = json.loads(raw)
            _policy_cache[agent_id] = policy
            log(
                f"[policy] loaded agentId={agent_id} version={policy.get('version')} "
                f"safe={len(policy.get('safeTools', []))} "
                f"dangerous={len(policy.get('alwaysDangerousTools', []))}"
            )
            return policy
        except Exception as e:
            log(f"[policy] corrupt policy object agentId={agent_id}: {e} — bootstrapping")

    log(f"[policy] no policy found for agentId={agent_id} — bootstrapping from code defaults")
    policy = _bootstrap_policy(agent_id, known_tools)
    _save_policy(agent_id, policy)
    log(
        f"[policy] NOTICE: bootstrapped policy saved for agentId={agent_id}. "
        f"Review s3://<bucket>/{_policy_key(agent_id)} before this agent handles production traffic."
    )
    _policy_cache[agent_id] = policy
    return policy


def reload_policy(agent_id: str) -> Dict[str, Any]:
    _policy_cache.pop(agent_id, None)
    return load_policy(agent_id)


def load_usage_summary(agent_id: str) -> Dict[str, Any]:
    if agent_id in _usage_cache:
        return _usage_cache[agent_id]
    raw = s3_get_bytes(_usage_key(agent_id))
    if raw:
        try:
            summary = json.loads(raw)
            _usage_cache[agent_id] = summary
            return summary
        except Exception as e:
            log(f"[policy] usage summary load error agentId={agent_id}: {e}")
    return {}


def reload_usage_summary(agent_id: str) -> Dict[str, Any]:
    _usage_cache.pop(agent_id, None)
    return load_usage_summary(agent_id)


def _week_key(ts: Optional[float] = None) -> str:
    import datetime as dt
    d = dt.datetime.utcfromtimestamp(ts or time.time())
    iso_year, iso_week, _ = d.isocalendar()
    return f"week:{iso_year}-W{iso_week:02d}"


def _day_key(ts: Optional[float] = None) -> str:
    import datetime as dt
    d = dt.datetime.utcfromtimestamp(ts or time.time())
    return d.strftime("%Y-%m-%d")


def check_threshold(
    agent_id: str, user_id: str, tool_name: str, tool_args: Dict[str, Any]
) -> Optional[str]:
    """Same three-check order as truclaw_adk: safeBelow -> dailyLimit -> weeklyLimit."""
    policy = _policy_cache.get(agent_id, {})
    thresholds = policy.get("toolThresholds", {})
    if not thresholds or tool_name not in thresholds:
        return None

    rule = thresholds[tool_name]

    field = rule.get("field")
    safe_below = rule.get("safeBelow")
    if field and safe_below is not None:
        val = tool_args.get(field) if isinstance(tool_args, dict) else None
        if val is not None:
            try:
                if float(val) <= float(safe_below):
                    return SAFE_BYPASS
                return (
                    f"tool={tool_name} field={field} value={val} "
                    f"exceeds safeBelow={safe_below}"
                )
            except (TypeError, ValueError):
                pass

    daily_limit = rule.get("dailyLimit")
    weekly_limit = rule.get("weeklyLimit")
    if daily_limit is None and weekly_limit is None:
        return None

    summary = _usage_cache.get(agent_id, {})
    user_counts = summary.get("counts", {}).get(user_id, {}).get(tool_name, {})

    if daily_limit is not None:
        day_count = user_counts.get(_day_key(), 0)
        if day_count >= int(daily_limit):
            return (
                f"tool={tool_name} userId={user_id} "
                f"dailyCount={day_count} exceeds dailyLimit={daily_limit}"
            )

    if weekly_limit is not None:
        week_count = user_counts.get(_week_key(), 0)
        if week_count >= int(weekly_limit):
            return (
                f"tool={tool_name} userId={user_id} "
                f"weeklyCount={week_count} exceeds weeklyLimit={weekly_limit}"
            )

    return None
