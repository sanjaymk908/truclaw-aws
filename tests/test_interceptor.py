"""
Regression test for _parse_gateway_event's now-confirmed real event shape.
The two fixtures below are trimmed versions of an actual raw event
captured from a deployed Gateway (see docs/ARCHITECTURE.md) -- not
hypothetical. Losing this fix would silently reintroduce the crash where
every non-tools/call MCP message (initialize, tools/list, ping, etc.)
got passed to check_danger() and blew up on tool_name.split().
"""
from interceptor.handler import _parse_gateway_event

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
