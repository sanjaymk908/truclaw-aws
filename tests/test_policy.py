"""
Unit tests for the threshold-check logic in truclaw_aws/policy.py. No AWS
calls: exercises the in-process caches directly rather than going through
load_policy()/load_usage_summary() (which would hit S3).
"""
from truclaw_aws import policy


def _set_policy(agent_id: str, thresholds: dict) -> None:
    policy._policy_cache[agent_id] = {
        "agentId": agent_id,
        "safeTools": [],
        "alwaysDangerousTools": [],
        "toolThresholds": thresholds,
    }


def _set_usage(agent_id: str, counts: dict) -> None:
    policy._usage_cache[agent_id] = {"agentId": agent_id, "counts": counts}


def test_safe_below_bypasses():
    _set_policy("agent-a", {"wire_transfer": {"field": "amount", "safeBelow": 100}})
    _set_usage("agent-a", {})
    result = policy.check_threshold("agent-a", "user-1", "wire_transfer", {"amount": 50})
    assert result == policy.SAFE_BYPASS


def test_safe_below_violation():
    _set_policy("agent-b", {"wire_transfer": {"field": "amount", "safeBelow": 100}})
    _set_usage("agent-b", {})
    result = policy.check_threshold("agent-b", "user-1", "wire_transfer", {"amount": 500})
    assert result is not None and "exceeds safeBelow" in result


def test_daily_limit_violation():
    _set_policy("agent-c", {"ach_transfer": {"dailyLimit": 3}})
    today = policy._day_key()
    _set_usage("agent-c", {"user-1": {"ach_transfer": {today: 3}}})
    result = policy.check_threshold("agent-c", "user-1", "ach_transfer", {})
    assert result is not None and "dailyLimit" in result


def test_no_threshold_rule_returns_none():
    _set_policy("agent-d", {})
    result = policy.check_threshold("agent-d", "user-1", "anything", {})
    assert result is None
