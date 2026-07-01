"""
Resolves a pending escalation when the paired device responds.

Wired behind an API Gateway route or a Lambda Function URL that the relay's
webhook (`/verify-callback` in send_challenge.py above) calls with the
device's signed JWT and the task token that was embedded in that URL. This
Lambda has no dependency on which execution environment sent the original
challenge — any warm or cold resume_handler invocation can resolve any
pending task token, because the token itself (not local memory) is what
Step Functions uses to find the paused execution.
"""
import json
from typing import Any, Dict

import boto3

from truclaw_aws import config
from truclaw_aws.jwt_verify import verify_jwt
from truclaw_aws.logging import log

_sfn = boto3.client("stepfunctions", region_name=config.AWS_REGION)


def handle(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """`event` is an API Gateway / Function URL proxy event."""
    qs = event.get("queryStringParameters") or {}
    task_token = qs.get("taskToken")
    if not task_token:
        return {"statusCode": 400, "body": "missing taskToken"}

    try:
        body = json.loads(event.get("body") or "{}")
    except Exception:
        return {"statusCode": 400, "body": "invalid JSON body"}

    jwt = body.get("jwt")
    nonce = body.get("nonce")
    if not jwt or not nonce:
        _sfn.send_task_failure(
            taskToken=task_token, error="MissingFields", cause="jwt/nonce required"
        )
        return {"statusCode": 400, "body": "missing jwt/nonce"}

    verified = verify_jwt(jwt, nonce, body.get("sessionId"))

    if not verified.get("valid"):
        log(f"[resume] JWT invalid: {verified.get('error')}")
        _sfn.send_task_success(
            taskToken=task_token,
            output=json.dumps({"approved": False, "reason": verified.get("error")}),
        )
        return {"statusCode": 200, "body": "denied"}

    claims = verified.get("claims", {})
    if claims.get("isHuman") is False:
        _sfn.send_task_success(
            taskToken=task_token,
            output=json.dumps({"approved": False, "reason": "JWT isHuman=false"}),
        )
        return {"statusCode": 200, "body": "denied"}

    log(f"[resume] approved sessionId={verified.get('sessionId')}")
    _sfn.send_task_success(
        taskToken=task_token,
        output=json.dumps({"approved": True, "claims": claims}),
    )
    return {"statusCode": 200, "body": "approved"}
