"""
Step Functions Task Lambda — the "send" half of truclaw_adk's challenge.py.

Invoked by statemachine/escalation.asl.json with `.waitForTaskToken`, so the
input event includes a `Token` field (Step Functions' `$$.Task.Token`)
alongside the escalation payload. This function's only job is to find the
user's paired device(s) and push the challenge with that token embedded in
the callback URL — it does NOT itself wait for a response. Step Functions
holds the execution open on the token; resume_handler.py resolves it later,
from a completely separate Lambda invocation, possibly on a different
execution environment entirely. That's the actual "no in-process PENDING
dict" fix: the wait state lives in Step Functions, not in this function's
memory.

If no device is paired (or the push fails outright), this function calls
SendTaskFailure itself immediately rather than letting Step Functions wait
out the full timeout for something that was never going to resolve.
"""
import json
from typing import Any, Dict
from urllib.parse import quote

import boto3
import httpx

from truclaw_aws import config
from truclaw_aws.pairing import find_paired_devices_for_user, find_paired_device
from truclaw_aws.logging import log

_sfn = boto3.client("stepfunctions", region_name=config.AWS_REGION)


def handle(event: Dict[str, Any], context: Any) -> None:
    task_token = event["Token"]
    payload = event["payload"]
    user_id = payload.get("userId", "default")

    devices = find_paired_devices_for_user(user_id)
    if not devices and user_id == "default":
        found = find_paired_device()
        if found:
            _, device = found
            devices = [device]

    if not devices:
        log(f"[send_challenge] no paired device for userId={user_id}; failing task token")
        _sfn.send_task_failure(
            taskToken=task_token,
            error="NoPairedDevice",
            cause=f"no paired TruClaw device for userId={user_id}",
        )
        return

    # Fan out to every paired device, exactly like truclaw_adk's send_challenge.
    # Whichever approves (or denies) first resolves the task token via
    # resume_handler.py — this function's job ends once the pushes are sent.
    any_sent = False
    with httpx.Client(timeout=10.0) as client:
        for device in devices:
            fcm_token = device.get("fcmToken")
            if not fcm_token:
                continue
            webhook_url = (
                f"{config.RELAY_URL}/verify-callback"
                f"?taskToken={quote(task_token)}"
            )
            challenge_payload = {
                "fcmToken": fcm_token,
                "webhookURL": webhook_url,
                "action": payload.get("actionTitle") or f"Approve: {payload.get('toolName')}",
                "actionTitle": payload.get("actionTitle"),
                "actionBody": payload.get("actionBody"),
            }
            try:
                resp = client.post(f"{config.RELAY_URL}/challenge", json=challenge_payload)
                if resp.status_code < 400:
                    any_sent = True
                else:
                    log(f"[send_challenge] relay error status={resp.status_code} body={resp.text[:300]}")
            except Exception as e:
                log(f"[send_challenge] relay exception: {e}")

    if not any_sent:
        _sfn.send_task_failure(
            taskToken=task_token,
            error="PushDeliveryFailed",
            cause="could not deliver challenge to any paired device",
        )
