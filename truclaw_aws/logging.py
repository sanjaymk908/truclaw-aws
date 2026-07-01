"""
Minimal structured logger.

Lambda ships anything written to stdout to CloudWatch Logs automatically, so
there is no handler/transport setup needed here — this just keeps every log
line a single JSON object so CloudWatch Logs Insights queries can filter on
`msg` without regex-parsing free text.
"""
import json
import time


def log(msg: str) -> None:
    print(json.dumps({"ts": time.time(), "msg": msg}, default=str))
