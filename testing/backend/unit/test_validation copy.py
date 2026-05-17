"""
Tests for centralized validation and sanitization helpers.
"""

from backend.secuscan.validation import (
    validate_target,
    validate_task_inputs,
    sanitize_input,
    sanitize_inputs,
    extract_target_from_inputs,
)


def test_validate_target_valid_domain():
    is_valid, error = validate_target(
        "example.com",
        safe_mode=False
    )

    assert is_valid is True
    assert error == ""


def test_validate_target_invalid_hostname():
    is_valid, error = validate_target(
        "bad host!!!",
        safe_mode=False
    )

    assert is_valid is False
    assert "Invalid hostname format" in error


def test_validate_target_safe_mode_public_ip_blocked():
    is_valid, error = validate_target(
        "8.8.8.8",
        safe_mode=True
    )

    assert is_valid is False
    assert "Public IPs/networks not allowed" in error


def test_sanitize_input_removes_dangerous_chars():
    raw = "example.com; rm -rf /"

    sanitized = sanitize_input(raw)

    assert ";" not in sanitized
    assert sanitized == "example.com rm -rf /"


def test_sanitize_inputs_nested_dict():
    payload = {
        "target": "example.com;",
        "nested": {
            "cmd": "test && whoami"
        }
    }

    sanitized = sanitize_inputs(payload)

    assert ";" not in sanitized["target"]
    assert "&" not in sanitized["nested"]["cmd"]


def test_extract_target_from_inputs():
    payload = {
        "url": "https://example.com"
    }

    target = extract_target_from_inputs(payload)

    assert target == "https://example.com"


def test_validate_task_inputs_success():
    payload = {
        "target": "192.168.1.1"
    }

    is_valid, error, sanitized = validate_task_inputs(
        payload,
        safe_mode=True
    )

    assert is_valid is True
    assert error == ""
    assert sanitized["target"] == "192.168.1.1"


def test_validate_task_inputs_failure():
    payload = {
        "target": "8.8.8.8"
    }

    is_valid, error, sanitized = validate_task_inputs(
        payload,
        safe_mode=True
    )

    assert is_valid is False
    assert "Public IPs/networks not allowed" in error