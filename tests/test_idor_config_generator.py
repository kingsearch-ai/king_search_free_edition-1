"""Unit tests for IDOR_Config_Generator module."""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.IDOR_Config_Generator import (
    parse_user_id_from_url,
    extract_path_params,
    extract_query_params,
    generate_config_from_urls,
    generate_config_from_creds,
    parse_urls_file,
)


class TestParseUserIdFromUrl:
    """Tests for parse_user_id_from_url."""

    def test_user_path(self):
        assert parse_user_id_from_url("https://api.example.com/users/12345") == "12345"

    def test_user_singular(self):
        assert parse_user_id_from_url("https://api.example.com/user/admin") == "admin"

    def test_profile_path(self):
        assert parse_user_id_from_url("https://example.com/profile/john-doe") == "john-doe"

    def test_account_path(self):
        assert parse_user_id_from_url("https://example.com/accounts/abc_123") == "abc_123"

    def test_user_id_query_param(self):
        assert parse_user_id_from_url("https://example.com?user_id=42") == "42"

    def test_uid_query_param(self):
        assert parse_user_id_from_url("https://example.com?uid=99") == "99"

    def test_id_query_param(self):
        assert parse_user_id_from_url("https://example.com?id=abc") == "abc"

    def test_no_match_returns_none(self):
        assert parse_user_id_from_url("https://example.com/static/index.html") is None

    def test_empty_url(self):
        assert parse_user_id_from_url("") is None


class TestExtractPathParams:
    """Tests for extract_path_params."""

    def test_extracts_path_segments(self):
        result = extract_path_params("https://api.example.com/users/12345/profile")
        assert "users" in result
        assert "12345" in result
        assert "profile" in result

    def test_short_segments_excluded(self):
        result = extract_path_params("https://example.com/a/bc/def/ghij")
        assert "a" not in result
        assert "bc" not in result
        assert "def" not in result
        assert "ghij" in result

    def test_empty_path(self):
        result = extract_path_params("https://example.com")
        assert result == []


class TestExtractQueryParams:
    """Tests for extract_query_params."""

    def test_single_param(self):
        result = extract_query_params("https://example.com?id=42")
        assert result == {"id": "42"}

    def test_multiple_params(self):
        result = extract_query_params("https://example.com?id=42&name=test&role=admin")
        assert result == {"id": "42", "name": "test", "role": "admin"}

    def test_no_params(self):
        result = extract_query_params("https://example.com")
        assert result == {}


class TestGenerateConfigFromUrls:
    """Tests for generate_config_from_urls."""

    def test_generates_config_with_user_id(self, tmp_path):
        output = str(tmp_path / "config.json")
        urls = ["https://api.example.com/users/42/profile"]
        generate_config_from_urls(urls, output)

        with open(output) as f:
            config = json.load(f)

        assert len(config["credentials"]) > 0
        assert len(config["target_endpoints"]) > 0
        assert config["target_endpoints"][0]["original_ids"] == ["42"]
        assert "{user_id}" in config["target_endpoints"][0]["url"]

    def test_generates_config_with_query_id(self, tmp_path):
        output = str(tmp_path / "config.json")
        urls = ["https://api.example.com/data?user_id=100"]
        generate_config_from_urls(urls, output)

        with open(output) as f:
            config = json.load(f)

        assert len(config["target_endpoints"]) > 0

    def test_generates_defaults_when_no_ids(self, tmp_path):
        output = str(tmp_path / "config.json")
        urls = ["https://example.com/static/page.html"]
        generate_config_from_urls(urls, output)

        with open(output) as f:
            config = json.load(f)

        assert len(config["target_endpoints"]) > 0

    def test_valid_urls_populated(self, tmp_path):
        output = str(tmp_path / "config.json")
        urls = ["https://api.example.com/users/1", "https://api.example.com/users/2"]
        generate_config_from_urls(urls, output)

        with open(output) as f:
            config = json.load(f)

        assert len(config["valid_urls"]) == 2

    def test_deduplicates_endpoints(self, tmp_path):
        output = str(tmp_path / "config.json")
        urls = [
            "https://api.example.com/users/1",
            "https://api.example.com/users/2",
        ]
        generate_config_from_urls(urls, output)

        with open(output) as f:
            config = json.load(f)

        endpoint_urls = [e["url"] for e in config["target_endpoints"]]
        assert len(endpoint_urls) == len(set(endpoint_urls))


class TestGenerateConfigFromCreds:
    """Tests for generate_config_from_creds."""

    def test_generates_config_from_list(self, tmp_path):
        output = str(tmp_path / "config.json")
        creds = [
            {
                "type": "bearer_token",
                "value": "test-token-123",
                "valid_urls": [
                    {"url": "https://api.example.com/users/42", "status_code": 200}
                ]
            }
        ]
        generate_config_from_creds(creds, output)

        with open(output) as f:
            config = json.load(f)

        assert len(config["credentials"]) == 1
        assert len(config["valid_urls"]) == 1
        assert len(config["target_endpoints"]) > 0

    def test_handles_empty_creds(self, tmp_path):
        output = str(tmp_path / "config.json")
        generate_config_from_creds([], output)

        with open(output) as f:
            config = json.load(f)

        assert config["credentials"] == []
        assert config["target_endpoints"] == []


class TestParseUrlsFile:
    """Tests for parse_urls_file."""

    def test_reads_urls(self, tmp_path):
        url_file = tmp_path / "urls.txt"
        url_file.write_text("https://example.com\nhttps://test.com\n\nhttps://other.com\n")
        result = parse_urls_file(str(url_file))
        assert result == ["https://example.com", "https://test.com", "https://other.com"]

    def test_skips_blank_lines(self, tmp_path):
        url_file = tmp_path / "urls.txt"
        url_file.write_text("\n\nhttps://example.com\n\n")
        result = parse_urls_file(str(url_file))
        assert result == ["https://example.com"]
