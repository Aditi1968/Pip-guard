import json
import logging

from pipguard.log import JsonFormatter, new_correlation_id


def test_json_formatter_includes_correlation_id() -> None:
    cid = new_correlation_id()
    rec = logging.LogRecord("pipguard", logging.INFO, __file__, 1, "hi %s", ("x",), None)
    out = json.loads(JsonFormatter().format(rec))
    assert out["msg"] == "hi x" and out["cid"] == cid
