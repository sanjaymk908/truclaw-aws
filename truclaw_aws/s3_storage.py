"""
S3 replacement for truclaw_adk's gcs_storage.py.

Kept as a thin, direct analogue of the original three functions
(download/upload/delete) so callers didn't need to change shape — but ledger.py
and pairing.py in this port do NOT use the "download whole blob, mutate
locally, re-upload whole blob" pattern the original ledger.py/pairing.py used.
That pattern is a read-modify-write race under concurrent writers (see
README.md "Design notes vs. truclaw_adk" for the full explanation) — the
fix costs nothing extra in complexity, so it's applied here rather than
carried over.
"""
from pathlib import Path
from typing import Optional

from . import config
from .logging import log


def _client():
    import boto3
    return boto3.client("s3", region_name=config.AWS_REGION)


def _is_not_found(exc: Exception) -> bool:
    code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
    return code in {"404", "NoSuchKey", "NotFound"}


def s3_download(local_path: Path, key: str) -> bool:
    """Download from S3 to local path. Returns True if a file was downloaded."""
    if not config.S3_BUCKET:
        return False
    if local_path.exists():
        return False
    try:
        client = _client()
        local_path.parent.mkdir(parents=True, exist_ok=True)
        client.download_file(config.S3_BUCKET, key, str(local_path))
        log(f"[s3] downloaded {key} from s3://{config.S3_BUCKET}")
        return True
    except Exception as e:
        if _is_not_found(e):
            log(f"[s3] {key} not found in bucket — starting fresh")
        else:
            log(f"[s3] download error {key}: {e}")
        return False


def s3_upload(local_path: Path, key: str) -> bool:
    """Upload local path to S3. Returns True if successful."""
    if not config.S3_BUCKET:
        return False
    if not local_path.exists():
        return False
    try:
        client = _client()
        client.upload_file(str(local_path), config.S3_BUCKET, key)
        log(f"[s3] uploaded {key} to s3://{config.S3_BUCKET}")
        return True
    except Exception as e:
        log(f"[s3] upload error {key}: {e}")
        return False


def s3_put_bytes(data: bytes, key: str, content_type: str = "application/json") -> bool:
    """Write bytes directly to a key without touching the local filesystem.

    Used for the ledger's per-event objects (see ledger.py) where every
    event is its own immutable object — there is nothing to buffer locally.
    """
    if not config.S3_BUCKET:
        return False
    try:
        client = _client()
        client.put_object(
            Bucket=config.S3_BUCKET, Key=key, Body=data, ContentType=content_type
        )
        return True
    except Exception as e:
        log(f"[s3] put error {key}: {e}")
        return False


def s3_get_bytes(key: str) -> Optional[bytes]:
    if not config.S3_BUCKET:
        return None
    try:
        client = _client()
        resp = client.get_object(Bucket=config.S3_BUCKET, Key=key)
        return resp["Body"].read()
    except Exception as e:
        if not _is_not_found(e):
            log(f"[s3] get error {key}: {e}")
        return None


def s3_list(prefix: str, limit: Optional[int] = None) -> list[str]:
    """List object keys under a prefix, sorted lexicographically (which is
    chronological given the timestamp-first key scheme this port uses)."""
    if not config.S3_BUCKET:
        return []
    keys: list[str] = []
    try:
        client = _client()
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=config.S3_BUCKET, Prefix=prefix):
            for obj in page.get("Contents", []):
                keys.append(obj["Key"])
            if limit and len(keys) >= limit:
                break
    except Exception as e:
        log(f"[s3] list error prefix={prefix}: {e}")
    keys.sort()
    if limit:
        keys = keys[-limit:]
    return keys


def s3_delete(key: str) -> bool:
    if not config.S3_BUCKET:
        return False
    try:
        client = _client()
        client.delete_object(Bucket=config.S3_BUCKET, Key=key)
        log(f"[s3] deleted {key} from s3://{config.S3_BUCKET}")
        return True
    except Exception as e:
        log(f"[s3] delete error {key}: {e}")
        return False


def s3_delete_prefix(prefix: str) -> int:
    """Delete every object under a prefix. Returns count deleted."""
    keys = s3_list(prefix)
    n = 0
    for k in keys:
        if s3_delete(k):
            n += 1
    return n
