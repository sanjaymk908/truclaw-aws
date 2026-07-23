"""
Push/poll challenge logic — port of truclaw_adk/challenge.py's send_challenge().

*** Simplified from an earlier, wrong design ***
This used to be split across a Step Functions state machine and two
separate Lambdas (escalation/send_challenge.py, escalation/resume_handler.py),
using AWS's task-token callback pattern. That design assumed the relay
would call back into an AWS webhook when a device responded -- an
assumption that was never actually checked against the relay, and was
wrong (see docs/ARCHITECTURE.md for the full story, found via two rounds
of live 400s and finally reading the original source in full). The relay
is poll-based: push a challenge, then poll for the result, both from the
same caller -- exactly like truclaw_adk did. Once that was understood, the
Step Functions layer was solving a problem that no longer existed: there's
no unpredictable external caller to wait for durably, because this
function does the whole push-then-poll cycle itself, synchronously, within
one Lambda invocation. Collapsed back down to match the original's shape:
one process, one push, one poll loop, one answer.

Lives in truclaw_aws/ (not escalation/, which no longer exists) because
this is genuinely shared business logic ported in spirit from
truclaw_adk/challenge.py, same treatment as jwt_verify.py and pairing.py --
not Lambda/infra-specific glue.
"""
import asyncio
import hashlib
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from . import config
from .jwt_verify import verify_jwt
from .pairing import find_paired_devices_for_user, find_paired_device
from .logging import log


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def _make_challenge_session_id(nonce: str, timestamp: str) -> str:
    """Copied from truclaw_adk/challenge.py verbatim -- this is what the
    relay actually expects as `sessionId` in the /challenge payload (a
    fresh per-challenge id, NOT the device's pairing composite key -- an
    earlier version of this port guessed that instead of reading the
    original source, and was wrong)."""
    return hashlib.sha256(f"{nonce}{timestamp}".encode("utf-8")).hexdigest()[:16]


async def _send_and_poll(
    device: Dict[str, Any],
    action_title: Optional[str],
    action_body: Optional[str],
    timeout_seconds: int,
) -> Dict[str, Any]:
    """Port of truclaw_adk's `_send_and_poll`: push a challenge to the
    relay, then poll the relay for the device's signed response. The
    original ran its poll loop (`_sync_poll`) in a background thread via
    `asyncio.to_thread`, specifically to stay off the ADK app's own event
    loop while the rest of the app kept serving other requests. That
    constraint doesn't apply in a Lambda invocation -- nothing else runs
    concurrently here -- so this is a plain asyncio loop instead. Poll
    interval is 2s rather than the original's 0.3s: Lambda billing is
    duration-based regardless of what the invocation does while waiting,
    so the tight interval bought responsiveness on a long-lived server
    for free; here it would only add relay load for no benefit.
    """
    fcm_token = device.get("fcmToken")
    if not fcm_token:
        return {"approved": False, "reason": "device missing fcmToken"}

    nonce = secrets.token_hex(16)
    timestamp = _now_iso()
    salt = secrets.token_hex(8)
    challenge_session_id = _make_challenge_session_id(nonce, timestamp)
    deadline = time.time() + timeout_seconds
    webhook_url = f"{config.RELAY_URL}/verify/{challenge_session_id}"
    challenge_url = f"{config.RELAY_URL}/challenge"

    payload = {
        "fcmToken": fcm_token,
        "nonce": nonce,
        "timestamp": timestamp,
        "salt": salt,
        "sessionId": challenge_session_id,
        "webhookURL": webhook_url,
        "action": action_title or "Approve action",  # legacy field -- OpenClaw reads this today
        "actionTitle": action_title,                  # new field -- read after OpenClaw migration
        "actionBody": action_body,
    }

    log(f"[challenge] sending challengeSessionId={challenge_session_id}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(challenge_url, json=payload)
        except Exception as e:
            log(f"[challenge] relay exception: {e}")
            return {"approved": False, "reason": f"relay exception: {e}"}

        if resp.status_code >= 400:
            log(f"[challenge] relay error status={resp.status_code} body={resp.text[:300]}")
            return {"approved": False, "reason": f"relay error {resp.status_code}"}

        poll_url = f"{config.RELAY_URL}/poll/{challenge_session_id}"
        while time.time() < deadline:
            try:
                poll_resp = await client.get(poll_url)
                if poll_resp.status_code == 200:
                    data = poll_resp.json()
                    jwt = data.get("jwt")
                    if not jwt:
                        return {"approved": False, "reason": "approval missing JWT"}

                    # session_id=None matches truclaw_adk's own call here --
                    # this is verify_jwt's optional *device* lookup hint
                    # (keyed by pairing composite key), unrelated to
                    # challenge_session_id above.
                    verified = verify_jwt(jwt, nonce, None)
                    if not verified.get("valid"):
                        log(
                            f"[challenge] JWT invalid challengeSessionId={challenge_session_id} "
                            f"error={verified.get('error')}"
                        )
                        return {"approved": False, "reason": verified.get("error")}

                    claims = verified.get("claims", {})

                    # The raw signed JWT (not just its decoded claims) is
                    # carried through in the returned dict below so
                    # interceptor/handler.py's append_event() can persist it
                    # to the S3 ledger alongside the decoded claims. Flagged
                    # live (2026-07-23): decoded claims alone are only as
                    # trustworthy as whatever wrote the ledger entry: they
                    # can't be independently re-verified later against the
                    # paired device's public key (stored in pairing.py's
                    # device registry). Retaining the actual signed artifact
                    # turns "an audit log" into non-repudiable proof of what
                    # the device actually signed -- the whole point of using
                    # a signed challenge/response scheme in the first place.
                    # Only done for signature-verified JWTs (this branch);
                    # a JWT that failed verify_jwt() isn't proof of anything
                    # from the device and isn't retained.

                    # Approval requires BOTH isHuman and isAbove21 to be
                    # explicitly True -- fail-closed, not just "not False".
                    # isAbove21 doubles as this demo's explicit approve/deny
                    # signal, not just an age claim -- confirmed directly by
                    # the paired device's owner (2026-07-22, Task #22 live
                    # testing). Found the hard way: a "denied" approval on
                    # the device still came back with a validly-signed,
                    # isHuman=true JWT and the payment went through anyway,
                    # because this code only ever checked isHuman (and even
                    # that check was permissive -- `is False` rather than
                    # `is True`, so a missing/null claim would have silently
                    # passed too). Added a temporary diagnostic log of the
                    # raw poll response (`{"jwt":..., "sessionId":...,
                    # "receivedAt":...}` -- confirmed no separate decision
                    # field exists in the relay's poll contract itself)
                    # before finding out the decision is encoded in this
                    # specific JWT claim instead. A real (non-demo)
                    # deployment would presumably use a dedicated
                    # `approved`/`decision` claim instead of overloading an
                    # age-verification field, but this repo follows the
                    # demo's actual wire format rather than inventing a
                    # cleaner one that wouldn't match what the paired device
                    # actually sends.
                    if claims.get("isHuman") is not True:
                        return {"approved": False, "reason": "JWT isHuman not true", "jwt": jwt}
                    if claims.get("isAbove21") is not True:
                        return {"approved": False, "reason": "denied (isAbove21 not true)", "jwt": jwt}

                    log(f"[challenge] approved challengeSessionId={challenge_session_id}")
                    return {
                        "approved": True,
                        "claims": claims,
                        "sessionId": verified.get("sessionId"),
                        "jwt": jwt,
                    }
                elif poll_resp.status_code == 404:
                    log(f"[challenge] poll 404 challengeSessionId={challenge_session_id}")
                    break
                # 202 = still pending; anything else, log and keep polling.
            except Exception as e:
                log(f"[challenge] poll error challengeSessionId={challenge_session_id} error={e}")
            await asyncio.sleep(2.0)

    log(f"[challenge] timeout challengeSessionId={challenge_session_id}")
    return {"approved": False, "reason": "approval timeout"}


async def send_challenge(
    action_title: Optional[str],
    action_body: Optional[str],
    reason: str,
    tool_name: str,
    tool_args: Any,
    user_id: str = "default",
    timeout_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    """Public entrypoint -- same name and argument shape as truclaw_adk's
    send_challenge(). Called directly and awaited from
    interceptor/handler.py:_escalate(), inside the same Lambda invocation
    that detected the dangerous call. No separate Lambda, no Step
    Functions, no task token -- one push, one poll loop, one answer, same
    as the original.
    """
    timeout_seconds = timeout_seconds or config.CHALLENGE_TIMEOUT_SECONDS

    devices: List[Dict[str, Any]] = find_paired_devices_for_user(user_id)
    if not devices and user_id == "default":
        found = find_paired_device()
        if found:
            _, device = found
            devices = [device]

    if not devices:
        log(f"[challenge] no paired device for userId={user_id}; block")
        return {
            "approved": False,
            "reason": f"no paired TruClaw device for userId={user_id}",
        }

    log(f"[challenge] fanning out to {len(devices)} device(s) for userId={user_id}")

    tasks = [
        _send_and_poll(device, action_title, action_body, timeout_seconds)
        for device in devices
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, dict) and result.get("approved"):
            return result
    for result in results:
        if isinstance(result, dict):
            return result
    return {"approved": False, "reason": "all devices denied or timed out"}
