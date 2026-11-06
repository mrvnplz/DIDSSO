from __future__ import annotations

import math
import os
import time
from collections import OrderedDict
from threading import Lock
from typing import Any


_ENABLED_VALUES = {"1", "true", "yes", "on"}
_MAX_SESSIONS = 2_000
_EVENTS: OrderedDict[str, dict[str, dict[str, Any]]] = OrderedDict()
_EVENTS_LOCK = Lock()


def evaluation_enabled() -> bool:
    return os.environ.get("DIDSSO_EVALUATION_ENABLED", "").strip().lower() in _ENABLED_VALUES


def epoch_milliseconds() -> float:
    return time.time_ns() / 1_000_000


def elapsed_seconds(started_ns: int) -> float:
    return (time.perf_counter_ns() - started_ns) / 1_000_000_000


def record_event(
    session_id: str,
    event: str,
    *,
    timestamp_epoch_ms: float | int | None = None,
    duration_seconds: float | int | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    if not evaluation_enabled():
        return

    session_id = str(session_id).strip()
    event = str(event).strip()
    if not session_id or not event:
        return

    timestamp = (
        float(timestamp_epoch_ms)
        if timestamp_epoch_ms is not None
        else epoch_milliseconds()
    )
    if not math.isfinite(timestamp):
        raise ValueError("Evaluation event timestamp must be finite")

    entry: dict[str, Any] = {"timestamp_epoch_ms": timestamp}
    if duration_seconds is not None:
        duration = float(duration_seconds)
        if not math.isfinite(duration) or duration < 0:
            raise ValueError("Evaluation duration must be finite and non-negative")
        entry["duration_seconds"] = duration
    if details:
        entry["details"] = dict(details)

    with _EVENTS_LOCK:
        events = _EVENTS.setdefault(session_id, {})
        events[event] = entry
        _EVENTS.move_to_end(session_id)
        while len(_EVENTS) > _MAX_SESSIONS:
            _EVENTS.popitem(last=False)


def measurements_for(session_id: str) -> dict[str, dict[str, Any]]:
    with _EVENTS_LOCK:
        return {
            event: dict(values)
            for event, values in _EVENTS.get(str(session_id), {}).items()
        }


def clear_measurements(session_id: str = "") -> None:
    with _EVENTS_LOCK:
        if session_id:
            _EVENTS.pop(str(session_id), None)
        else:
            _EVENTS.clear()
