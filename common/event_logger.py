import json
import os
import queue
import threading
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    requests = None


def _event_path(service_name: str) -> str:
    default_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "runtime-logs")
    logs_dir = os.getenv("LOG_DIR", "/logs")
    try:
        os.makedirs(logs_dir, exist_ok=True)
    except (PermissionError, OSError):
        logs_dir = default_dir
        os.makedirs(logs_dir, exist_ok=True)
    return os.path.join(logs_dir, f"{service_name}.jsonl")


# Background HTTP log dispatcher worker (non-blocking for callers)
_EVENT_QUEUE: queue.Queue = queue.Queue(maxsize=10000)
_WORKER_STARTED = False
_WORKER_LOCK = threading.Lock()
COLLECTOR_URL = os.getenv("COLLECTOR_URL", "")


def _log_worker_loop():
    session = requests.Session() if requests else None
    while True:
        try:
            item = _EVENT_QUEUE.get()
            if item is None:
                break
            service_name, event = item
            # Cold storage local file append
            try:
                with open(_event_path(service_name), "a", encoding="utf-8") as f:
                    f.write(json.dumps(event, separators=(",", ":")) + "\n")
            except (IOError, OSError, PermissionError) as err:
                if getattr(err, "errno", None) == 28:
                    import sys
                    print(f"[!] EventLogger CRITICAL: Disk full on {_event_path(service_name)} (ENOSPC)", file=sys.stderr)

            # Optional HTTP POST to Collector if configured
            if COLLECTOR_URL and session:
                try:
                    session.post(COLLECTOR_URL, json=event, timeout=0.8)
                except Exception:
                    pass
        except Exception:
            pass
        finally:
            _EVENT_QUEUE.task_done()


def _ensure_worker_running():
    global _WORKER_STARTED
    if not _WORKER_STARTED:
        with _WORKER_LOCK:
            if not _WORKER_STARTED:
                t = threading.Thread(target=_log_worker_loop, daemon=True, name="EventLoggerWorker")
                t.start()
                _WORKER_STARTED = True


def flush_events(timeout_seconds: float = 2.0) -> None:
    """Flush pending events in the queue before process exits."""
    if _WORKER_STARTED:
        try:
            _EVENT_QUEUE.join()
        except Exception:
            pass


import atexit
atexit.register(flush_events)


def emit_event(service_name: str, event: dict) -> dict:
    """Standard event emitter: non-blocking queue dispatch with cold JSONL persistence."""
    event.setdefault("ts", datetime.now(timezone.utc).isoformat())
    event.setdefault("service", service_name)
    _ensure_worker_running()

    try:
        _EVENT_QUEUE.put_nowait((service_name, event))
    except queue.Full:
        # Direct fallback write to avoid dropping logs under extreme load
        try:
            with open(_event_path(service_name), "a", encoding="utf-8") as f:
                f.write(json.dumps(event, separators=(",", ":")) + "\n")
        except (IOError, OSError, PermissionError) as err:
            if getattr(err, "errno", None) == 28:
                import sys
                print(f"[!] EventLogger CRITICAL: Disk full on fallback {_event_path(service_name)} (ENOSPC)", file=sys.stderr)
    return event



