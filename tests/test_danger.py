"""
Unit tests for truclaw_aws/danger.py's JSON-extraction and script-detection
helpers -- the parts of the module that don't require a live classifier
call or S3 access.
"""
import pytest

from truclaw_aws import danger


def test_extract_json_object_plain():
    assert danger.extract_json_object('{"dangerous": true}') == {"dangerous": True}


def test_extract_json_object_fenced():
    text = '```json\n{"dangerous": false, "reason": "ok"}\n```'
    assert danger.extract_json_object(text) == {"dangerous": False, "reason": "ok"}


def test_extract_json_object_embedded():
    text = 'Here is my answer: {"dangerous": true, "reason": "x"} thanks'
    result = danger.extract_json_object(text)
    assert result["dangerous"] is True


def test_extract_json_object_empty_raises():
    with pytest.raises(ValueError):
        danger.extract_json_object("")


def test_normalize_classifier_decision_defaults():
    out = danger.normalize_classifier_decision({}, "send_email")
    assert out["dangerous"] is False
    assert "send_email" in out["actionTitle"]


def test_command_from_args_dict():
    assert danger.command_from_args({"command": "python3 foo.py"}) == "python3 foo.py"


def test_command_from_args_string():
    assert danger.command_from_args("ls -la") == "ls -la"
