"""
Ported unchanged from truclaw_adk/jwt_verify.py.

This is pure ECDSA/JWT verification logic with no GCP or AWS dependency, so
it doesn't need to change for the AWS port — only its `pairing` import
target changes (S3-backed pairing.py in this package instead of GCS-backed).
"""
import base64
import json
import time
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from .pairing import load_paired_devices
from .logging import log

SPKI_HEADER = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_jwt(jwt: str, nonce: str, session_id: Optional[str] = None) -> Dict[str, Any]:
    try:
        header_b64, claims_b64, sig_b64 = jwt.split(".")
    except ValueError:
        return {"valid": False, "error": "JWT must have 3 parts"}
    try:
        claims = json.loads(_b64url_decode(claims_b64).decode())
        log(
            f"[verify] claims nonce={claims.get('nonce')} "
            f"sessionId={claims.get('sessionId')} exp={claims.get('exp')}"
        )
    except Exception as e:
        return {"valid": False, "error": f"claims parse failed: {e}"}

    now = time.time()
    if claims.get("exp") is None or now > float(claims["exp"]):
        return {"valid": False, "error": "JWT expired"}
    if claims.get("nonce") != nonce:
        return {
            "valid": False,
            "error": f"nonce mismatch expected={nonce} got={claims.get('nonce')}",
        }

    claim_session_id = claims.get("sessionId")
    if session_id and claim_session_id and claim_session_id != session_id:
        return {"valid": False, "error": "sessionId mismatch"}

    devices = load_paired_devices()
    candidates = []
    if session_id and session_id in devices:
        candidates.append((session_id, devices[session_id]))
    if claim_session_id and claim_session_id in devices and claim_session_id != session_id:
        candidates.append((claim_session_id, devices[claim_session_id]))
    if not candidates:
        candidates = [
            (sid, d) for sid, d in devices.items() if d.get("apnsToken") and not d.get("role")
        ]

    signing_input = f"{header_b64}.{claims_b64}".encode()
    sig = _b64url_decode(sig_b64)

    for sid, device in candidates:
        try:
            raw = base64.b64decode(device["publicKey"])
            pub = serialization.load_der_public_key(SPKI_HEADER + raw)
            pub.verify(sig, signing_input, ec.ECDSA(hashes.SHA256()))
            log(f"[verify] signature valid sessionId={sid}")
            return {"valid": True, "claims": claims, "sessionId": sid}
        except InvalidSignature:
            continue
        except Exception as e:
            log(f"[verify] candidate failed sessionId={sid} error={e}")

    return {"valid": False, "error": "invalid signature"}
