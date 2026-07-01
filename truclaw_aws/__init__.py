"""
truclaw_aws — AWS/AgentCore port of TruClaw.

Unlike the original truclaw_adk package, this package does NOT install an
in-process monkey-patch on agent startup. The enforcement point moves to an
AgentCore Gateway REQUEST interceptor (see interceptor/handler.py), which is
framework-agnostic and fires for every tool call routed through the Gateway,
regardless of whether the agent behind it is ADK, LangGraph, Strands, or
anything else.

See README.md for the full architecture writeup and the mapping back to the
original truclaw_adk modules.
"""
