"""Tests for custom framework service — helper functions, evaluation logic."""
import json
import pytest

from api.services.custom_framework_service import (
    _parse_json_list,
    _to_json,
    _generated_check_id,
    determine_assessment_type,
    format_custom_control_response,
    format_framework_response,
)


class TestParseJsonList:
    def test_valid_json_array(self):
        assert _parse_json_list('["a","b"]') == ["a", "b"]

    def test_none(self):
        assert _parse_json_list(None) == []

    def test_empty_string(self):
        assert _parse_json_list("") == []

    def test_invalid_json(self):
        assert _parse_json_list("not json") == []

    def test_json_object(self):
        result = _parse_json_list('{"key": "value"}')
        assert result == {"key": "value"}


class TestToJson:
    def test_list(self):
        assert _to_json(["a", "b"]) == '["a", "b"]'

    def test_none(self):
        assert _to_json(None) is None

    def test_dict(self):
        result = json.loads(_to_json({"k": "v"}))
        assert result == {"k": "v"}


class TestGeneratedCheckId:
    def test_basic(self):
        assert _generated_check_id("MY-CHECK.1") == "custom_my_check_1"

    def test_already_lowercase(self):
        assert _generated_check_id("my_check_1") == "custom_my_check_1"

    def test_dashes_and_dots(self):
        assert _generated_check_id("CIS-AWS-2.1.1") == "custom_cis_aws_2_1_1"


class TestDetermineAssessmentType:
    def test_manual_when_no_ids(self):
        assert determine_assessment_type([]) == "manual"

    def test_automated_with_evaluation_logic(self):
        assert determine_assessment_type([], has_evaluation_logic=True) == "automated"
