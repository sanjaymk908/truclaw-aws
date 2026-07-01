import os
from pathlib import Path

# --- External relay (unchanged from truclaw_adk — device push/pairing relay
# is not GCP/AWS-specific, so it is not part of this port) ---
RELAY_URL = os.getenv("TRUKYC_RELAY_URL", "").rstrip("/")

# --- Classifier model ---
# V1 keeps calling Gemini directly, exactly as truclaw_adk did — AgentCore
# Runtime/Gateway are model-agnostic, so there is no requirement to move the
# classifier onto a Bedrock-hosted model for the AWS port to work. Swapping
# to Bedrock (see danger.py:_bedrock_generate) is left as a V2 decision so
# this port doesn't grow scope before the hook design itself is proven out.
CLASSIFIER_PROVIDER = os.getenv("TRUCLAW_CLASSIFIER_PROVIDER", "gemini")  # "gemini" | "bedrock"
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
GEMINI_CLASSIFIER_MODEL = os.getenv("TRUCLAW_CLASSIFIER_MODEL", "gemini-3.5-flash")
BEDROCK_CLASSIFIER_MODEL_ID = os.getenv(
    "TRUCLAW_BEDROCK_MODEL_ID", "anthropic.claude-3-5-haiku-20241022-v1:0"
)
AWS_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))

# --- Persistence (S3 replaces GCS) ---
S3_BUCKET = os.getenv("TRUCLAW_S3_BUCKET", "")
# Lambda's only writable path is /tmp, and it is NOT guaranteed to persist
# between invocations (a fresh execution environment gets a fresh /tmp).
# Every read path in this package must be able to run with an empty /tmp.
STATE_DIR = Path(os.getenv("TRUCLAW_STATE_DIR", "/tmp/.truclaw"))

# --- Pairing / challenge ---
PAIRING_DEEPLINK_BASE = os.getenv(
    "TRUCLAW_PAIRING_DEEPLINK_BASE", "https://aasa.trusources.ai/openclaw"
)
PAIR_POLL_TIMEOUT_SECONDS = int(os.getenv("TRUCLAW_PAIR_POLL_TIMEOUT_SECONDS", "300"))
CHALLENGE_TIMEOUT_SECONDS = int(os.getenv("TRUCLAW_CHALLENGE_TIMEOUT_SECONDS", "120"))
ENFORCE = os.getenv("TRUCLAW_ENFORCE", "1") not in {"0", "false", "False", "no"}

# --- Step Functions (async escalation — see statemachine/escalation.asl.json) ---
ESCALATION_STATE_MACHINE_ARN = os.getenv("TRUCLAW_ESCALATION_STATE_MACHINE_ARN", "")

# --- Admin ---
ADMIN_KEY_HASH = os.getenv("TRUCLAW_ADMIN_KEY_HASH", "")
