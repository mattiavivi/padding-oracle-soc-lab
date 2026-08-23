import json
import os
from datetime import datetime, timezone


def _event_path(service_name: str) -> str:
    default_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "runtime-logs")
    logs_dir = os.getenv("LOG_DIR", "/logs")
    try:
        os.makedirs(logs_dir, exist_ok=True)
    except (PermissionError, OSError):
        logs_dir = default_dir
        os.makedirs(logs_dir, exist_ok=True)
    return os.path.join(logs_dir, f"{service_name}.jsonl")



def emit_event(service_name: str, event: dict) -> None:
    event.setdefault("ts", datetime.now(timezone.utc).isoformat())
    event.setdefault("service", service_name)
    try:
        with open(_event_path(service_name), "a", encoding="utf-8") as f:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")
    except (IOError, OSError, PermissionError):
        pass

