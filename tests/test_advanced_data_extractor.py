"""Unit tests for Advanced_data_extractor module."""

import sys
import os
import re
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.Advanced_data_extractor import DataExtractor


class TestRiskClassification:
    """Tests for DataExtractor._risk_classification."""

    def _make_extractor(self, tmp_path):
        config_path = str(tmp_path / "config.yaml")
        return DataExtractor(config_path=config_path)

    def test_critical_risk(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        assert ext._risk_classification("aws_credentials") == "Critical"
        assert ext._risk_classification("jwt_token") == "Critical"
        assert ext._risk_classification("private_key") == "Critical"
        assert ext._risk_classification("credit_card_data") == "Critical"
        assert ext._risk_classification("email_credentials") == "Critical"

    def test_high_risk(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        assert ext._risk_classification("api_key") == "High"
        assert ext._risk_classification("github_token") == "High"
        assert ext._risk_classification("access_token") == "High"
        assert ext._risk_classification("database_connection_string") == "High"

    def test_medium_risk(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        assert ext._risk_classification("phone_number") == "Medium"

    def test_low_risk(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        assert ext._risk_classification("domain") == "Low"
        assert ext._risk_classification("ip_address") == "Low"

    def test_unknown_defaults_to_medium(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        assert ext._risk_classification("some_unknown_type") == "Medium"


class TestShouldProcessFile:
    """Tests for DataExtractor._should_process_file."""

    def _make_extractor(self, tmp_path):
        config_path = str(tmp_path / "config.yaml")
        return DataExtractor(config_path=config_path)

    def test_supported_extension(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "test.json"
        test_file.write_text("{}")
        assert ext._should_process_file(str(test_file)) is True

    def test_unsupported_extension(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "image.png"
        test_file.write_bytes(b"\x89PNG")
        assert ext._should_process_file(str(test_file)) is False

    def test_nonexistent_file(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        assert ext._should_process_file("/nonexistent/file.txt") is False

    def test_directory_not_file(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        assert ext._should_process_file(str(tmp_path)) is False

    def test_txt_extension(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "data.txt"
        test_file.write_text("some data")
        assert ext._should_process_file(str(test_file)) is True

    def test_py_extension(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "script.py"
        test_file.write_text("print('hello')")
        assert ext._should_process_file(str(test_file)) is True

    def test_env_extension(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "settings.env"
        test_file.write_text("KEY=VALUE")
        assert ext._should_process_file(str(test_file)) is True


class TestDeduplicateData:
    """Tests for DataExtractor._deduplicate_data."""

    def _make_extractor(self, tmp_path):
        config_path = str(tmp_path / "config.yaml")
        return DataExtractor(config_path=config_path)

    def test_removes_duplicates(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        data = [
            {"data_type": "api_key", "value": "ABC123", "file": "a.txt", "file_path": "a.txt", "risk_level": "High"},
            {"data_type": "api_key", "value": "ABC123", "file": "b.txt", "file_path": "b.txt", "risk_level": "High"},
            {"data_type": "jwt_token", "value": "eyJ...", "file": "c.txt", "file_path": "c.txt", "risk_level": "Critical"},
        ]
        result = ext._deduplicate_data(data)
        assert len(result) == 2

    def test_keeps_unique_entries(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        data = [
            {"data_type": "api_key", "value": "ABC", "file": "a.txt", "file_path": "a.txt", "risk_level": "High"},
            {"data_type": "api_key", "value": "DEF", "file": "b.txt", "file_path": "b.txt", "risk_level": "High"},
        ]
        result = ext._deduplicate_data(data)
        assert len(result) == 2

    def test_empty_data(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        assert ext._deduplicate_data([]) == []


class TestSensitivePatterns:
    """Tests for DataExtractor.sensitive_patterns regex validity."""

    def _make_extractor(self, tmp_path):
        config_path = str(tmp_path / "config.yaml")
        return DataExtractor(config_path=config_path)

    def test_all_patterns_compile(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        for name, pattern in ext.sensitive_patterns.items():
            if isinstance(pattern, str):
                re.compile(pattern)

    def test_jwt_pattern_matches(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        pattern = ext.sensitive_patterns['jwt_token']
        assert re.search(pattern, jwt) is not None

    def test_github_token_pattern_matches(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        pattern = ext.sensitive_patterns['github_token']
        assert re.search(pattern, token) is not None

    def test_md5_hash_pattern_matches(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        pattern = ext.sensitive_patterns['md5_hash']
        assert re.search(pattern, md5) is not None

    def test_sha256_hash_pattern_matches(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        pattern = ext.sensitive_patterns['sha256_hash']
        assert re.search(pattern, sha256) is not None

    def test_private_key_pattern_matches(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        pattern = ext.sensitive_patterns['private_key']
        assert re.search(pattern, key, re.DOTALL) is not None

    def test_bearer_auth_pattern_matches(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        bearer = "Bearer eyJhbGciOiJIUzI1NiJ9"
        pattern = ext.sensitive_patterns['authorization_bearer']
        assert re.search(pattern, bearer) is not None


class TestExtractSensitiveData:
    """Tests for DataExtractor.extract_sensitive_data."""

    def _make_extractor(self, tmp_path):
        config_path = str(tmp_path / "config.yaml")
        return DataExtractor(config_path=config_path)

    def test_finds_jwt_in_file(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "test.txt"
        test_file.write_text(
            "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        results = ext.extract_sensitive_data(str(test_file))
        types_found = [r['data_type'] for r in results]
        assert any("jwt" in t.lower() or "json_web_token" in t.lower() for t in types_found)

    def test_finds_github_token(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "test.txt"
        test_file.write_text("GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")
        results = ext.extract_sensitive_data(str(test_file))
        types_found = [r['data_type'] for r in results]
        assert any("github" in t.lower() for t in types_found)

    def test_empty_file(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "empty.txt"
        test_file.write_text("")
        results = ext.extract_sensitive_data(str(test_file))
        assert results == []

    def test_unsupported_file_returns_empty(self, tmp_path):
        ext = self._make_extractor(tmp_path)
        test_file = tmp_path / "image.png"
        test_file.write_bytes(b"\x89PNG\x0d\x0a\x1a\x0a")
        results = ext.extract_sensitive_data(str(test_file))
        assert results == []


class TestDataTypes:
    """Tests for DataExtractor.data_types list."""

    def test_has_expected_types(self, tmp_path):
        config_path = str(tmp_path / "config.yaml")
        ext = DataExtractor(config_path=config_path)
        assert "jwt_token" in ext.data_types
        assert "api_key" in ext.data_types
        assert "aws_credentials" in ext.data_types
        assert "github_token" in ext.data_types
        assert "private_key" in ext.data_types
        assert "ssh_key" in ext.data_types
        assert "credit_card_data" in ext.data_types

    def test_data_types_are_strings(self, tmp_path):
        config_path = str(tmp_path / "config.yaml")
        ext = DataExtractor(config_path=config_path)
        for dt in ext.data_types:
            assert isinstance(dt, str)
