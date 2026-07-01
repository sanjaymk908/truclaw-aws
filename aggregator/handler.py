"""
EventBridge-scheduled Lambda — port of truclaw_adk/cron_aggregator.py
(originally a Google Cloud Run Job triggered by Cloud Scheduler).

Reads the per-event ledger objects (see truclaw_aws/ledger.py) for every
agent that has a policy object, aggregates per-userId per-toolName daily and
weekly counts, and writes usage_summary.json + memory.md back to S3 for each
agent -- same two output artifacts as the original, same reasoning for why
both exist (see truclaw_aws/ledger.py's module docstring).

Deploy as a Lambda on an EventBridge schedule, e.g. rate(1 hour) -- see
infra/cdk/truclaw_stack.py.
"""
import datetime as dt
import json
from collections import defaultdict
from typing import Any, Dict, List

from truclaw_aws import config
from truclaw_aws.s3_storage import s3_list, s3_get_bytes, s3_put_bytes
from truclaw_aws.logging import log

POLICIES_PREFIX = "truclaw/policies/"


def _list_agent_ids() -> List[str]:
    keys = s3_list(POLICIES_PREFIX)
    agent_ids = set()
    for key in keys:
        parts = key[len(POLICIES_PREFIX):].split("/")
        if len(parts) >= 2 and parts[1] == "TruClaw-Policies.json":
            agent_ids.add(parts[0])
    return sorted(agent_ids)


def _day_key(ts: float) -> str:
    return dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d")


def _week_key(ts: float) -> str:
    d = dt.datetime.utcfromtimestamp(ts)
    iso_year, iso_week, _ = d.isocalendar()
    return f"week:{iso_year}-W{iso_week:02d}"


def _read_recent_events(agent_id: str, days_back: int = 8) -> List[Dict[str, Any]]:
    """Lists the last `days_back` days of date-prefixed ledger keys for this
    agent and reads every event object. This is the whole point of the
    date-prefixed key scheme in ledger.py: a bounded listing instead of a
    full-ledger scan, regardless of how long the agent has been running."""
    prefix = f"{POLICIES_PREFIX}{agent_id}/ledger"
    now = dt.datetime.utcnow()
    events: List[Dict[str, Any]] = []
    for i in range(days_back):
        d = now - dt.timedelta(days=i)
        for key in s3_list(f"{prefix}/{d:%Y}/{d:%m}/{d:%d}/"):
            raw = s3_get_bytes(key)
            if not raw:
                continue
            try:
                events.append(json.loads(raw))
            except Exception:
                continue
    return events


def _aggregate(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(int))
    )
    for event in events:
        if not event.get("allowed", True):
            continue
        if event.get("safeBypass"):
            continue
        user_id = event.get("userId") or "unknown"
        tool_name = event.get("toolName")
        ts = event.get("ts")
        if not tool_name or not ts:
            continue
        try:
            ts_float = float(ts)
        except (TypeError, ValueError):
            continue
        counts[user_id][tool_name][_day_key(ts_float)] += 1
        counts[user_id][tool_name][_week_key(ts_float)] += 1

    return {uid: {t: dict(p) for t, p in tools.items()} for uid, tools in counts.items()}


def _generate_memory(agent_id: str, events: List[Dict[str, Any]], counts: Dict[str, Any]) -> str:
    """Deterministic qualitative behavioral summary -- no LLM call, pure
    aggregation, exactly like truclaw_adk's cron_aggregator._generate_memory_summary."""
    now = dt.datetime.utcnow()
    cutoff = now - dt.timedelta(days=7)
    day_keys = [(now - dt.timedelta(days=i)).strftime("%Y-%m-%d") for i in range(7)]

    notable: Dict[str, List[str]] = defaultdict(list)
    for event in events:
        try:
            ts = float(event.get("ts", 0))
        except (TypeError, ValueError):
            continue
        if dt.datetime.utcfromtimestamp(ts) < cutoff:
            continue
        user_id = event.get("userId") or "unknown"
        tool = event.get("toolName") or "unknown"
        allowed = event.get("allowed", True)
        reason = event.get("reason") or ""
        threshold_violation = event.get("thresholdViolation", False)
        dangerous = event.get("dangerous", False)
        safe_bypass = event.get("safeBypass", False)
        ts_str = dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

        if not allowed:
            notable[user_id].append(f"- {ts_str}: {tool} BLOCKED — {reason}")
        elif threshold_violation:
            notable[user_id].append(f"- {ts_str}: {tool} threshold exceeded — {reason}")
        elif dangerous and not safe_bypass:
            notable[user_id].append(f"- {ts_str}: {tool} approved after auth — {reason}")

    lines = [
        f"# TruClaw Behavioral Memory — {agent_id}",
        f"Generated: {now.strftime('%Y-%m-%dT%H:%M:%SZ')} | Window: last 7 days",
        "",
    ]
    if not counts:
        lines.append("No activity recorded in this period.")
        return "\n".join(lines)

    for user_id, tools in sorted(counts.items()):
        lines.append(f"## User: {user_id}")
        tool_lines = []
        total = 0
        for tool_name, periods in sorted(tools.items()):
            week_total = sum(periods.get(d, 0) for d in day_keys)
            if week_total == 0:
                continue
            total += week_total
            tool_lines.append(f"  - {tool_name}: {week_total} calls")
        lines.append(f"**7-day total:** {total} tool calls")
        lines.extend(tool_lines)
        user_notable = notable.get(user_id, [])
        if user_notable:
            lines.append("**Notable events:**")
            lines.extend(user_notable[-10:])
        else:
            lines.append("**Notable events:** None — normal activity pattern")
        lines.append("")

    return "\n".join(lines)


def handle(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    if not config.S3_BUCKET:
        log("TRUCLAW_S3_BUCKET not set — nothing to do")
        return {"agents": 0, "errors": 0}

    agent_ids = _list_agent_ids() or ["unknown"]
    log(f"aggregating agents: {agent_ids}")

    errors = 0
    for agent_id in agent_ids:
        try:
            events = _read_recent_events(agent_id)
            counts = _aggregate(events)
            summary = {
                "agentId": agent_id,
                "generatedAt": dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "counts": counts,
            }
            s3_put_bytes(
                json.dumps(summary, indent=2, sort_keys=True).encode("utf-8"),
                f"{POLICIES_PREFIX}{agent_id}/usage_summary.json",
            )
            memory_md = _generate_memory(agent_id, events, counts)
            s3_put_bytes(
                memory_md.encode("utf-8"), f"{POLICIES_PREFIX}{agent_id}/memory.md", "text/markdown"
            )
        except Exception as e:
            log(f"unexpected error agentId={agent_id}: {e}")
            errors += 1

    log(f"done — agents={len(agent_ids)} errors={errors}")
    return {"agents": len(agent_ids), "errors": errors}
