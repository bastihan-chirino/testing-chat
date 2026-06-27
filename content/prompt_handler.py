from pii_detector import detect_pii


def decide_prompt_action(prompt: str, allow_pii: bool = False) -> dict:
    """Decide whether a prompt should be sent or blocked based on PII detection."""
    pii_check = detect_pii(prompt)
    if pii_check["found"] and not allow_pii:
        return {"action": "warn", "pii_check": pii_check}
    return {"action": "send", "pii_check": pii_check}


def should_process_new_prompt(prompt: str | None, pending_prompt: str | None) -> bool:
    """Return True only when a fresh prompt should be processed.

    This prevents stale chat input from being treated as a new prompt while
    a PII warning is already waiting for confirmation.
    """
    return bool(prompt) and pending_prompt is None
