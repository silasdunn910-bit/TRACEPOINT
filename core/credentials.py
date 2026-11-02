"""Credential entry rules for API Configuration (UI-independent so they can be tested).

Nothing here ever returns or logs a credential value in a message."""
from __future__ import annotations

import re
from typing import Callable

from core import search_engine
from core.configuration import API_INTEGRATIONS
from providers.search_providers import validate_searxng_url

MAX_LEN = 512
MIN_LEN = 6


def validate_credential(key: str, raw: str) -> tuple[str, str]:
    """Return (clean_value, error). error is '' when acceptable."""
    if key not in API_INTEGRATIONS:
        return "", "Unknown integration."
    value = (raw or "").strip()
    if not value:
        return "", "No value entered; nothing was changed."
    if re.search(r"[\x00-\x1f\x7f]", value):
        return "", "The value contains control characters (a bad paste?); nothing was changed."
    if len(value) > MAX_LEN:
        return "", f"The value is longer than {MAX_LEN} characters; nothing was changed."
    if key == "searxng_url":
        url, err = validate_searxng_url(value)
        return (url, "") if not err else ("", err + " Nothing was changed.")
    if re.search(r"\s", value):
        return "", "API keys do not contain spaces; check the pasted value. Nothing was changed."
    if len(value) < MIN_LEN:
        return "", f"The value is too short to be a valid credential (minimum {MIN_LEN} characters). Nothing was changed."
    return value, ""


def save_credential(db, key: str, raw: str) -> tuple[bool, str]:
    value, err = validate_credential(key, raw)
    if err:
        return False, err
    db.set_secret(key, value)
    search_engine.clear_test_results(key)  # an older CONNECTED result no longer applies
    return True, f"Stored (encrypted) for {API_INTEGRATIONS[key][0]}. Status is CONFIGURED until you run a connection test."


def remove_credential(db, key: str, confirm: Callable[[], bool]) -> tuple[bool, str]:
    label = API_INTEGRATIONS.get(key, (key,))[0]
    if key not in db.secret_names():
        return False, f"{label} is not set."
    if not confirm():
        return False, "Cancelled; credential unchanged."
    db.delete_secret(key)
    search_engine.clear_test_results(key)
    return True, f"Removed {label}."
