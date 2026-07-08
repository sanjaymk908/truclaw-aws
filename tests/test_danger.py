"""
Unit tests for truclaw_aws/danger.py's JSON-extraction and script-detection
helpers -- the parts of the module that don't require a live classifier
call or S3 access.
"""
import pytest
from unittest.mock import AsyncMock, patch

from truclaw_aws import danger


def test_extract_json_object_plain():
    assert danger.extract_json_object('{"dangerous": true}') == {"dangerous": True}


def test_extract_json_object_fenced():
    text = '```json\n{"dangerous": false, "reason": "ok"}\n```'
    assert danger.extract_json_object(text) == {"dangerous": False, "reason": "ok"}


def test_extract_json_object_embedded():
    text = 'Here is my answer: {"dangerous": true, "reason": "x"} thanks'
    result = danger.extract_json_object(text)
    assert result["dangerous"] is True


def test_extract_json_object_empty_raises():
    with pytest.raises(ValueError):
        danger.extract_json_object("")


def test_normalize_classifier_decision_defaults():
    out = danger.normalize_classifier_decision({}, "send_email")
    assert out["dangerous"] is False
    assert "send_email" in out["actionTitle"]


def test_command_from_args_dict():
    assert danger.command_from_args({"command": "python3 foo.py"}) == "python3 foo.py"


def test_command_from_args_string():
    assert danger.command_from_args("ls -la") == "ls -la"


# ── normalize_tool_name -- regression coverage for the bug found live via
# truclaw-aws-samples's calculator target on 2026-07-08: AgentCore Gateway
# namespaces tools as `<target>___<tool>` (triple underscore), but this
# function used to only split on ".", so a Gateway-routed safe tool never
# matched its own policy's safeTools list and fell through to a live
# classifier call every time. See normalize_tool_name's own docstring.

def test_normalize_tool_name_strips_gateway_namespace():
    assert danger.normalize_tool_name("calculator___calculator") == "calculator"


def test_normalize_tool_name_strips_multiple_underscored_target_name():
    assert danger.normalize_tool_name("payments___process_payment") == "process_payment"


def test_normalize_tool_name_still_supports_legacy_dot_separator():
    assert danger.normalize_tool_name("some_agent.read") == "read"


def test_normalize_tool_name_bare_name_unchanged():
    assert danger.normalize_tool_name("calculator") == "calculator"


# ── check_danger Path 1 / Path 3 -- confirm the fix actually short-circuits
# before ever reaching the classifier (Path 4), for both safe and dangerous
# Gateway-namespaced tool names. Everything check_danger touches besides
# normalize_tool_name is mocked out (S3-backed policy/usage/ledger lookups,
# the Gemini call) so these run with no network/AWS access.

def _mock_policy(safe=None, dangerous=None, business_rules=""):
    return {
        "safeTools": safe or [],
        "alwaysDangerousTools": dangerous or [],
        "toolThresholds": {},
        "businessRules": business_rules,
    }


@pytest.mark.asyncio
async def test_gateway_namespaced_safe_tool_bypasses_without_calling_classifier():
    with patch("truclaw_aws.policy.load_policy", return_value=_mock_policy(safe=["calculator"])), \
         patch("truclaw_aws.policy.load_usage_summary", return_value={}), \
         patch("truclaw_aws.policy.check_threshold", return_value=None), \
         patch("truclaw_aws.danger._gemini_generate", new_callable=AsyncMock) as mock_gemini:
        result = await danger.check_danger(
            "calculator___calculator", {"expression": "1+1"}, agent_id="financialAnalyst"
        )

    assert result["dangerous"] is False
    assert result.get("safeBypass") is True
    mock_gemini.assert_not_called()


@pytest.mark.asyncio
async def test_gateway_namespaced_dangerous_tool_matches_without_calling_classifier():
    with patch("truclaw_aws.policy.load_policy", return_value=_mock_policy(dangerous=["process_payment"])), \
         patch("truclaw_aws.policy.load_usage_summary", return_value={}), \
         patch("truclaw_aws.policy.check_threshold", return_value=None), \
         patch("truclaw_aws.danger.get_action_description", new_callable=AsyncMock) as mock_action, \
         patch("truclaw_aws.danger._gemini_generate", new_callable=AsyncMock) as mock_gemini:
        mock_action.return_value = {"title": "Process payment", "body": ""}
        result = await danger.check_danger(
            "payments___process_payment", {"x402_payload": {}}, agent_id="portfolioExecution"
        )

    assert result["dangerous"] is True
    assert result["reason"] == "always-dangerous tool"
    mock_gemini.assert_not_called()
