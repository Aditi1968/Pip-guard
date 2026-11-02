"""stdlib logging with a JSON formatter and a per-scan correlation ID (PRD: observability)."""

from __future__ import annotations

import json
import logging
import uuid
from contextvars import ContextVar

correlation_id: ContextVar[str] = ContextVar("correlation_id", default="-")


def new_correlation_id() -> str:
    cid = uuid.uuid4().hex[:12]
    correlation_id.set(cid)
    return cid


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "cid": correlation_id.get(),
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()  # stderr: stdout is reserved for the JSON report
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger("pipguard")
    root.handlers[:] = [handler]
    root.setLevel(level)
