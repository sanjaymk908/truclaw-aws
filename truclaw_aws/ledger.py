"""
S3-backed port of truclaw_adk/ledger.py.

Design change vs. the original: truclaw_adk kept one growing local ledger
file and re-uploaded the ENTIRE file to one shared GCS blob on every single
event (`blob.upload_from_filename` is a full overwrite, called from
`append_event`). Under concurrent writers that silently drops events —
whichever process uploads last wins, and there's no merge. It also re-sends
the whole accumulated file on every write, which is O(n) per event and
O(n^2) over the ledger's lifetime.

This port writes each event as its own immutable S3 object, keyed with a
zero-padded timestamp prefix so lexicographic key order is chronological:

    truclaw/policies/<agentId>/ledger/<yyyy>/<mm>/<dd>/<epoch_ms>-<uuid8>.json

There is no local buffering and nothing to overwrite, so concurrent writers
from many parallel interceptor Lambda invocations cannot clobber each other
— each just PUTs its own object. The cost is one small S3 PUT per event
(~$0.005 per 1,000 requests) instead of one growing re-upload per event —
cheaper AND correct, not a tradeoff.

memory.md and usage_summary.json remain single objects (see aggregator/) —
those have exactly one writer (the aggregator Lambda), so the original
single-object-overwrite pattern is fine for them and wasn't changed.
"""
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from .s3_storage import s3_put_bytes, s3_get_bytes, s3_list
from .logging import log

LEDGER_PREFIX_TMPL = "truclaw/policies/{agent_id}/ledger"
MEMORY_KEY_TMPL = "truclaw/policies/{agent_id}/memory.md"


def _jsonable(x: Any) -> Any:
    try:
        json.dumps(x)
        return x
    except Exception:
        return repr(x)


def _event_key(agent_id: str, ts: float, event_id: str) -> str:
    d = datetime.fromtimestamp(ts, tz=timezone.utc)
    prefix = LEDGER_PREFIX_TMPL.format(agent_id=agent_id or "unknown")
    epoch_ms = int(ts * 1000)
    return f"{prefix}/{d:%Y}/{d:%m}/{d:%d}/{epoch_ms}-{event_id}.json"


def append_event(event: Dict[str, Any]) -> str:
    """Write one event as its own immutable S3 object. Returns the event id."""
    event = dict(event)
    ts = event.setdefault("ts", time.time())
    event_id = uuid.uuid4().hex[:8]
    event.setdefault("id", event_id)
    agent_id = event.get("agentId") or "unknown"

    event = _jsonable(event)
    body = json.dumps(event, sort_keys=True, default=str).encode("utf-8")
    key = _event_key(agent_id, ts, event_id)
    s3_put_bytes(body, key)

    log(
        f"[ledger] appended id={event['id']} agentId={agent_id} "
        f"tool={event.get('toolName')} allowed={event.get('allowed')} "
        f"dangerous={event.get('dangerous')}"
    )
    return event["id"]


def read_events(agent_id: str, limit: int = 100, days_back: int = 2) -> List[Dict[str, Any]]:
    """Read the most recent `limit` events for an agent.

    Lists only the last `days_back` days of date-prefixed keys rather than
    the whole ledger — this is what the date-prefixed key scheme buys you:
    a bounded, cheap listing instead of scanning every event ever written.
    """
    prefix = LEDGER_PREFIX_TMPL.format(agent_id=agent_id or "unknown")
    now = datetime.now(timezone.utc)
    keys: List[str] = []
    for i in range(days_back):
        d = now - _day_delta(i)
        keys.extend(s3_list(f"{prefix}/{d:%Y}/{d:%m}/{d:%d}/"))

    keys.sort()
    keys = keys[-limit:]

    out = []
    for k in keys:
        raw = s3_get_bytes(k)
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except Exception:
            continue
    return out


def _day_delta(days: int):
    from datetime import timedelta
    return timedelta(days=days)


def prior_summary(agent_id: str, limit: int = 30) -> str:
    """Classifier context: cross-session behavioral memory (from the
    aggregator Lambda) followed by current-session recent events."""
    parts: List[str] = []

    memory = _load_memory(agent_id)
    if memory:
        parts.append("=== Cross-session behavioral memory ===")
        parts.append(memory.strip())
        parts.append("")

    events = read_events(agent_id, limit=limit)
    if events:
        parts.append("=== Recent actions ===")
        for i, e in enumerate(events, 1):
            args = json.dumps(e.get("toolArgs"), default=str)[:1200]
            reason = e.get("reason") or "n/a"
            parts.append(
                f"{i}. {e.get('toolName')}({args}) — {reason} — allowed={e.get('allowed')}"
            )

    return "\n".join(parts) if parts else "No prior actions."


def dangerous_prior_flag(agent_id: str, limit: int = 5) -> str:
    dangerous = [e for e in read_events(agent_id, limit=200) if e.get("dangerous")]
    if not dangerous:
        return ""
    lines = []
    for e in dangerous[-limit:]:
        lines.append(
            f"- {e.get('toolName')}({json.dumps(e.get('toolArgs'), default=str)[:800]}) "
            f"— {e.get('reason')}"
        )
    return "\n\nIMPORTANT — prior dangerous actions:\n" + "\n".join(lines)


def _load_memory(agent_id: str) -> str:
    return read_memory(agent_id)


def read_memory(agent_id: str) -> str:
    """Public accessor for the aggregator-generated memory.md — used by
    prior_summary() internally, and by admin/cli.py's view-memory command."""
    raw = s3_get_bytes(MEMORY_KEY_TMPL.format(agent_id=agent_id))
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Admin operations (see admin/cli.py)
# --------------------------------------------------------------------------- #

def clear_ledger(agent_id: str) -> int:
    from .s3_storage import s3_delete_prefix
    prefix = LEDGER_PREFIX_TMPL.format(agent_id=agent_id)
    n = s3_delete_prefix(f"{prefix}/")
    log(f"[ledger] cleared agentId={agent_id} objects_deleted={n}")
    return n


def clear_memory(agent_id: str) -> None:
    from .s3_storage import s3_delete
    s3_delete(MEMORY_KEY_TMPL.format(agent_id=agent_id))
    log(f"[ledger] memory cleared agentId={agent_id}")
