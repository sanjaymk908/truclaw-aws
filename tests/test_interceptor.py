"""
Regression tests for the interceptor's request-parsing AND response-shape
logic, both reverse-engineered from real, confirmed sources (see
docs/ARCHITECTURE.md):

1. _parse_gateway_event's event shape -- captured live from a deployed
   Gateway. Losing this fix would silently reintroduce the crash where
   every non-tools/call MCP message (initialize, tools/list, ping, etc.)
   got passed to check_danger() and blew up on tool_name.split().

2. _allow_response / _deny_response's output shape -- confirmed against
   AWS's official docs (gateway-interceptors-types.html), NOT the earlier
   invented `{"action": "ALLOW"|"DENY"}` payload, which a live Gateway
   invocation rejected outright with "Received invalid response from
   interceptor". Losing this fix would silently reintroduce that failure:
   every single tool call, safe or dangerous, would be rejected by the
   Gateway before ever reaching the target.
"""
from interceptor.handler import _parse_gateway_event, _allow_response, _deny_response

REAL_INITIALIZE_EVENT = {
    "interceptorInputVersion": "1.0",
    "mcp": {
        "gatewayRequest": {
            "path": "/mcp",
            "httpMethod": "POST",
            "headers": {},
            "body": {
                "id": 0,
                "method": "initialize",
                "params": {
                    "clientInfo": {"name": "mcp", "version": "0.1.0"},
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                },
                "jsonrpc": "2.0",
            },
            "context": None,
        },
        "gatewayResponse": None,
    },
}

TOOLS_CALL_EVENT = {
    "interceptorInputVersion": "1.0",
    "mcp": {
        "gatewayRequest": {
            "path": "/mcp",
            "httpMethod": "POST",
            "headers": {},
            "body": {
                "id": 1,
                "method": "tools/call",
                "params": {"name": "read", "arguments": {"message": "hello"}},
                "jsonrpc": "2.0",
            },
            "context": None,
        },
        "gatewayResponse": None,
    },
}

# Same tools/call, but the caller declared its own identity via MCP's
# standard _meta field, and the Gateway also reports an IAM principal --
# _meta.agentId must win, since it's the agent's own declared identity, not
# an inference from whichever credential happened to sign the request.
TOOLS_CALL_EVENT_WITH_DECLARED_AGENT_ID = {
    "interceptorInputVersion": "1.0",
    "mcp": {
        "gatewayRequest": {
            "path": "/mcp",
            "httpMethod": "POST",
            "headers": {},
            "body": {
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "send_email",
                    "arguments": {"message": "hi"},
                    "_meta": {"agentId": "agentA"},
                },
                "jsonrpc": "2.0",
            },
            "context": {
                "identity": {"awsPrincipalArn": "arn:aws:iam::111122223333:user/shared-deploy-role"}
            },
        },
        "gatewayResponse": None,
    },
}


def test_non_tool_call_method_is_not_a_tool_call():
    parsed = _parse_gateway_event(REAL_INITIALIZE_EVENT)
    assert parsed["isToolCall"] is False
    assert parsed["method"] == "initialize"
    assert parsed["tool"] is None


def test_tools_call_extracts_name_and_arguments():
    parsed = _parse_gateway_event(TOOLS_CALL_EVENT)
    assert parsed["isToolCall"] is True
    assert parsed["tool"] == "read"
    assert parsed["args"] == {"message": "hello"}


def test_missing_mcp_key_does_not_crash():
    parsed = _parse_gateway_event({})
    assert parsed["isToolCall"] is False
    assert parsed["tool"] is None


def test_declared_agent_id_in_meta_wins_over_iam_principal():
    """Two different agents sharing one IAM execution role (a normal AWS
    pattern) must NOT collapse into the same agentId. The agent's own
    _meta.agentId is the source of truth; the IAM principal is only a
    fallback for when no agent-declared id is present."""
    parsed = _parse_gateway_event(TOOLS_CALL_EVENT_WITH_DECLARED_AGENT_ID)
    assert parsed["agentId"] == "agentA"


def test_agent_id_falls_back_to_iam_principal_when_not_declared():
    event = {
        "interceptorInputVersion": "1.0",
        "mcp": {
            "gatewayRequest": {
                "path": "/mcp",
                "httpMethod": "POST",
                "headers": {},
                "body": {
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "read", "arguments": {}},
                    "jsonrpc": "2.0",
                },
                "context": {
                    "identity": {"awsPrincipalArn": "arn:aws:iam::111122223333:user/truclaw-deploy"}
                },
            },
            "gatewayResponse": None,
        },
    }
    parsed = _parse_gateway_event(event)
    assert parsed["agentId"] == "truclaw-deploy"


def test_allow_response_echoes_original_body_via_transformed_request():
    body = TOOLS_CALL_EVENT["mcp"]["gatewayRequest"]["body"]
    resp = _allow_response(body)
    assert resp["interceptorOutputVersion"] == "1.0"
    assert resp["mcp"]["transformedGatewayRequest"]["body"] == body
    # ALLOW must never carry a transformedGatewayResponse -- per AWS docs,
    # if one is present the Gateway responds immediately and skips the
    # target entirely, which would break every safe tool call.
    assert "transformedGatewayResponse" not in resp["mcp"]


def test_deny_response_synthesizes_jsonrpc_error_with_matching_id():
    body = TOOLS_CALL_EVENT["mcp"]["gatewayRequest"]["body"]
    resp = _deny_response(body, reason="blocked by policy", actionTitle="Send email")
    assert resp["interceptorOutputVersion"] == "1.0"
    transformed = resp["mcp"]["transformedGatewayResponse"]
    assert transformed["statusCode"] == 200
    assert transformed["body"]["jsonrpc"] == "2.0"
    assert transformed["body"]["id"] == body["id"]
    assert transformed["body"]["error"]["message"] == "blocked by policy"
    assert transformed["body"]["error"]["data"]["actionTitle"] == "Send email"
