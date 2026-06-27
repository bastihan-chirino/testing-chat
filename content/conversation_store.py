import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List


def get_default_conversation_path() -> str:
    """Devuelve una ruta local y visible para guardar las conversaciones."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    data_dir = os.path.join(project_root, "data")
    os.makedirs(data_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(data_dir, f"conversation_{timestamp}.json")


def ensure_message_timestamp(message: Dict[str, Any]) -> Dict[str, Any]:
    """Añade timestamp si no existe."""
    message_copy = dict(message)
    message_copy.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    return message_copy


def ensure_message_id(message: Dict[str, Any], next_id: int) -> Dict[str, Any]:
    """Añade un id incremental si no existe."""
    message_copy = dict(message)
    if "id" not in message_copy:
        message_copy["id"] = next_id
    return message_copy


def load_conversations(path: str | None = None) -> List[Dict[str, Any]]:
    """Carga las conversaciones desde un archivo JSON si existe."""
    file_path = path or get_default_conversation_path()
    if not os.path.exists(file_path):
        return []

    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            if isinstance(data, list):
                normalized: List[Dict[str, Any]] = []
                next_id = 1
                for item in data:
                    if isinstance(item, dict):
                        item_with_timestamp = ensure_message_timestamp(item)
                        if "id" not in item_with_timestamp:
                            item_with_timestamp = ensure_message_id(item_with_timestamp, next_id)
                            next_id += 1
                        else:
                            next_id = max(next_id, int(item_with_timestamp["id"]) + 1)
                        normalized.append(item_with_timestamp)
                return normalized
    except Exception:
        return []

    return []


def save_conversations(messages: List[Dict[str, Any]], path: str | None = None) -> str:
    """Guarda las conversaciones en un archivo JSON por conversación."""
    file_path = path or get_default_conversation_path()
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    normalized_messages: List[Dict[str, Any]] = []
    next_id = 1
    for message in messages:
        if not isinstance(message, dict):
            continue
        message_with_timestamp = ensure_message_timestamp(message)
        if "id" not in message_with_timestamp:
            message_with_timestamp = ensure_message_id(message_with_timestamp, next_id)
            next_id += 1
        else:
            next_id = max(next_id, int(message_with_timestamp["id"]) + 1)
        normalized_messages.append(message_with_timestamp)

    with open(file_path, "w", encoding="utf-8") as handle:
        json.dump(normalized_messages, handle, ensure_ascii=False, indent=2)

    return file_path


def add_conversation_event(messages: List[Dict[str, Any]], event: Dict[str, Any], path: str | None = None) -> str:
    """Añade un evento especial a la conversación, como una falla de PII o un reintento."""
    event_message = {
        "role": "system",
        "content": event.get("content", ""),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event.get("event_type", "info"),
        "details": event.get("details", {}),
    }
    messages.append(event_message)
    return save_conversations(messages, path)
