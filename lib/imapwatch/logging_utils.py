import json
import re


SAFE_LOGFMT_VALUE = re.compile(r"^[A-Za-z0-9._@:/+\-]+$")


def _format_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        if value and SAFE_LOGFMT_VALUE.fullmatch(value):
            return value
        return json.dumps(value, ensure_ascii=False)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def format_event(event, **fields):
    parts = [f"event={event}"]
    for name, value in fields.items():
        if value is not None:
            parts.append(f"{name}={_format_value(value)}")
    return " ".join(parts)


def log_event(logger, level, event, *, exc_info=False, **fields):
    method = getattr(logger, level)
    message = format_event(event, **fields)
    if exc_info:
        method(message, exc_info=True)
    else:
        method(message)
