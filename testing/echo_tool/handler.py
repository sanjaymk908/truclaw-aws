"""
Throwaway smoke-test tool for Track A/B testing — NOT part of the product.

Purpose: give the Gateway a real, trivial target to route to, so a live
tool call actually flows Gateway -> interceptor -> this Lambda -> back,
proving the interceptor pipeline works end to end without needing a real
banking API or a deployed agent yet.

Two behaviors based on the tool name AgentCore invokes this under (set at
registration time — register it twice, once as a safe tool, once as a
dangerous one, to exercise both tracks):
  - Anything else: just echoes the input back. Use this registration for
    Track A (should sail through as ALLOW if the tool name is in
    safeTools, e.g. call it "echo_read").
  - Register a second target pointing at the same Lambda under a name
    that's in alwaysDangerousTools (e.g. "echo_wire_transfer") to exercise
    Track B -- the interceptor will escalate before this handler ever
    actually runs.
"""
import json


def handler(event, context):
    message = event.get("message", "")
    return {"echo": message, "received": event}
