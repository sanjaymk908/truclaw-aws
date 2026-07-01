"""
S3-backed port of truclaw_adk/pairing.py.

Design change vs. the original: truclaw_adk stored ALL paired devices as one
JSON blob (paired.json) and did read-modify-write on every pairing event —
a race under concurrent writers. This port gives every paired device its own
S3 object keyed by its composite key, so `save_pairing` is a single PUT with
no read-modify-write at all, and there is nothing to race. This is strictly
less code than the original, not an added feature — it's the natural shape
once you stop forcing every device into one shared blob.

The pairing/relay handshake itself (start_pairing / poll_for_pairing against
TRUKYC_RELAY_URL) is unchanged from truclaw_adk — it isn't GCP/AWS-specific.
"""
import asyncio
import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx

from . import config
from .s3_storage import s3_get_bytes, s3_put_bytes, s3_list
from .logging import log

PAIRING_PREFIX = "truclaw/pairing"


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def _public_key_hash(public_key: str) -> str:
    return hashlib.sha256(public_key.encode()).hexdigest()[:16]


def _composite_key(user_id: str, public_key: str) -> str:
    return f"{user_id}:{_public_key_hash(public_key)}"


def _device_key(user_id: str, public_key_hash: str) -> str:
    return f"{PAIRING_PREFIX}/{user_id}/{public_key_hash}.json"


# --------------------------------------------------------------------------- #
# Storage — one S3 object per paired device, no read-modify-write
# --------------------------------------------------------------------------- #

def save_pairing(session_id: str, data: Dict[str, Any], user_id: str = "default") -> str:
    required = ["publicKey", "apnsToken", "fcmToken", "platform"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        raise ValueError(f"Missing pairing fields: {missing}")

    pk_hash = _public_key_hash(data["publicKey"])
    composite = _composite_key(user_id, data["publicKey"])
    record = {
        "publicKey": data["publicKey"],
        "apnsToken": data["apnsToken"],
        "fcmToken": data["fcmToken"],
        "platform": data["platform"],
        "userId": user_id,
        "pairedAt": _now_iso(),
    }
    ok = s3_put_bytes(
        json.dumps(record, indent=2, sort_keys=True).encode("utf-8"),
        _device_key(user_id, pk_hash),
    )
    if not ok:
        raise RuntimeError(f"failed to persist pairing for userId={user_id}")
    log(f"[pair] saved pairing key={composite} sessionId={session_id}")
    return composite


def find_paired_devices_for_user(user_id: str) -> List[Dict[str, Any]]:
    keys = s3_list(f"{PAIRING_PREFIX}/{user_id}/")
    out = []
    for k in keys:
        raw = s3_get_bytes(k)
        if raw:
            try:
                out.append(json.loads(raw))
            except Exception:
                continue
    return out


def find_paired_device() -> Optional[Tuple[str, Dict[str, Any]]]:
    """Legacy fallback — returns first device found under any user prefix
    that has a push token. Mirrors truclaw_adk's find_paired_device(), kept
    for parity with the "default" single-user flows in the original CLI."""
    keys = s3_list(f"{PAIRING_PREFIX}/")
    for k in keys:
        raw = s3_get_bytes(k)
        if not raw:
            continue
        try:
            device = json.loads(raw)
        except Exception:
            continue
        if device.get("fcmToken") or device.get("apnsToken"):
            # key shape: truclaw/pairing/{userId}/{pkHash}.json
            parts = k.split("/")
            user_id = parts[-2] if len(parts) >= 2 else device.get("userId", "default")
            pk_hash = _public_key_hash(device["publicKey"])
            return _composite_key(user_id, device["publicKey"]), device
    return None


def load_paired_devices() -> Dict[str, Dict[str, Any]]:
    """Back-compat shape for jwt_verify.py, which expects a dict keyed by
    composite key. Reconstructs it from the per-device objects."""
    keys = s3_list(f"{PAIRING_PREFIX}/")
    out: Dict[str, Dict[str, Any]] = {}
    for k in keys:
        raw = s3_get_bytes(k)
        if not raw:
            continue
        try:
            device = json.loads(raw)
        except Exception:
            continue
        parts = k.split("/")
        user_id = parts[-2] if len(parts) >= 2 else device.get("userId", "default")
        composite = _composite_key(user_id, device["publicKey"])
        out[composite] = device
    return out


# --------------------------------------------------------------------------- #
# Pairing handshake — unchanged from truclaw_adk (relay-based, not cloud-specific)
# --------------------------------------------------------------------------- #

async def poll_for_pairing(
    session_id: str,
    timeout_seconds: int = 300,
    poll_interval: float = 2.0,
) -> Optional[Dict[str, Any]]:
    if not config.RELAY_URL:
        raise ValueError("TRUKYC_RELAY_URL is not configured")

    url = f"{config.RELAY_URL}/pair-poll/{session_id}"
    deadline = asyncio.get_event_loop().time() + timeout_seconds
    log(f"[pair] polling relay sessionId={session_id} url={url}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        while True:
            if asyncio.get_event_loop().time() > deadline:
                return None
            try:
                resp = await client.get(url)
                if resp.status_code in {204, 404}:
                    await asyncio.sleep(poll_interval)
                    continue
                resp.raise_for_status()
                data = resp.json()
                if data and data.get("publicKey"):
                    log(f"[pair] pairing received sessionId={session_id}")
                    return data
            except Exception as e:
                log(f"[pair] poll error sessionId={session_id} error={e}")
            await asyncio.sleep(poll_interval)


async def start_pairing(
    user_id: str = "default",
    start_background_poll: bool = True,
) -> Dict[str, Any]:
    if not config.RELAY_URL:
        return {"status": "error", "reason": "TRUKYC_RELAY_URL not configured"}

    session_id = secrets.token_hex(16)
    webhook_url = f"{config.RELAY_URL}/pair/{session_id}"
    pairing_link = (
        f"{config.PAIRING_DEEPLINK_BASE}"
        f"?sessionId={session_id}"
        f"&webhookURL={quote(webhook_url)}"
    )
    qr_url = (
        "https://api.qrserver.com/v1/create-qr-code/"
        f"?size=300x300&data={quote(pairing_link)}"
    )

    log(f"[pair] started userId={user_id} sessionId={session_id} webhookURL={webhook_url}")

    if start_background_poll:
        async def bg() -> None:
            data = await poll_for_pairing(session_id)
            if data:
                composite = save_pairing(session_id, data, user_id=user_id)
                log(f"[pair] background poll saved key={composite}")

        asyncio.create_task(bg())

    return {
        "status": "pairing_started",
        "sessionId": session_id,
        "userId": user_id,
        "pairingLink": pairing_link,
        "qrImageUrl": qr_url,
        "webhookURL": webhook_url,
    }
