"""Unit tests for Advanced_Credential_Validator_Exploitation module."""

import sys
import os
import re
import base64
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.Advanced_Credential_Validator_Exploitation import AdvancedCredentialValidator


class TestExtractTitle:
    """Tests for AdvancedCredentialValidator.extract_title."""

    def _make_validator(self, tmp_path):
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)
        return AdvancedCredentialValidator(output_dir=output_dir)

    def test_extracts_title(self, tmp_path):
        v = self._make_validator(tmp_path)
        html = "<html><head><title>Test Page</title></head><body></body></html>"
        assert v.extract_title(html) == "Test Page"

    def test_extracts_title_multiline(self, tmp_path):
        v = self._make_validator(tmp_path)
        html = "<html><head><title>\n  My Title\n</title></head></html>"
        assert v.extract_title(html).strip() == "My Title"

    def test_no_title_returns_none(self, tmp_path):
        v = self._make_validator(tmp_path)
        html = "<html><head></head><body>content</body></html>"
        assert v.extract_title(html) is None

    def test_empty_title(self, tmp_path):
        v = self._make_validator(tmp_path)
        html = "<html><head><title></title></head></html>"
        assert v.extract_title(html) == ""

    def test_case_insensitive(self, tmp_path):
        v = self._make_validator(tmp_path)
        html = "<html><head><TITLE>Page</TITLE></head></html>"
        assert v.extract_title(html) == "Page"


class TestDecodeJwtParts:
    """Tests for AdvancedCredentialValidator.decode_jwt_parts."""

    def _make_validator(self, tmp_path):
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)
        return AdvancedCredentialValidator(output_dir=output_dir)

    def test_valid_jwt(self, tmp_path):
        v = self._make_validator(tmp_path)
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "1234567890", "name": "Test"}).encode()).decode().rstrip("=")
        token = f"{header}.{payload}.signature"

        h, p, s = v.decode_jwt_parts(token)
        assert h["alg"] == "HS256"
        assert p["sub"] == "1234567890"
        assert s == "signature"

    def test_invalid_jwt_format(self, tmp_path):
        v = self._make_validator(tmp_path)
        h, p, s = v.decode_jwt_parts("not.a.valid.jwt.token")
        assert h is None
        assert p is None
        assert s is None

    def test_two_parts_returns_none(self, tmp_path):
        v = self._make_validator(tmp_path)
        h, p, s = v.decode_jwt_parts("part1.part2")
        assert h is None
        assert p is None
        assert s is None

    def test_single_part_returns_none(self, tmp_path):
        v = self._make_validator(tmp_path)
        h, p, s = v.decode_jwt_parts("justonepart")
        assert h is None
        assert p is None
        assert s is None


class TestLoadUrls:
    """Tests for AdvancedCredentialValidator.load_urls."""

    def _make_validator(self, tmp_path):
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)
        return AdvancedCredentialValidator(output_dir=output_dir)

    def test_loads_urls_from_file(self, tmp_path):
        v = self._make_validator(tmp_path)
        urls_file = tmp_path / "urls.txt"
        urls_file.write_text("https://example.com\nhttps://test.com\n\nhttps://other.com")
        result = v.load_urls(str(urls_file))
        assert result == ["https://example.com", "https://test.com", "https://other.com"]

    def test_nonexistent_file(self, tmp_path):
        v = self._make_validator(tmp_path)
        result = v.load_urls("/nonexistent/file.txt")
        assert result == []


class TestGetRandomUserAgent:
    """Tests for AdvancedCredentialValidator.get_random_user_agent."""

    def _make_validator(self, tmp_path):
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)
        return AdvancedCredentialValidator(output_dir=output_dir)

    def test_returns_string(self, tmp_path):
        v = self._make_validator(tmp_path)
        ua = v.get_random_user_agent()
        assert isinstance(ua, str)
        assert len(ua) > 0

    def test_returns_mozilla_based(self, tmp_path):
        v = self._make_validator(tmp_path)
        ua = v.get_random_user_agent()
        assert "Mozilla" in ua

    def test_returns_varied(self, tmp_path):
        v = self._make_validator(tmp_path)
        agents = {v.get_random_user_agent() for _ in range(50)}
        assert len(agents) > 1


class TestJwtCommonSecrets:
    """Tests for AdvancedCredentialValidator.jwt_common_secrets."""

    def _make_validator(self, tmp_path):
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)
        return AdvancedCredentialValidator(output_dir=output_dir)

    def test_has_common_secrets(self, tmp_path):
        v = self._make_validator(tmp_path)
        assert "secret" in v.jwt_common_secrets
        assert "password" in v.jwt_common_secrets
        assert "admin" in v.jwt_common_secrets

    def test_not_empty(self, tmp_path):
        v = self._make_validator(tmp_path)
        assert len(v.jwt_common_secrets) > 10


class TestLog:
    """Tests for AdvancedCredentialValidator.log."""

    def _make_validator(self, tmp_path, verbose=False):
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)
        return AdvancedCredentialValidator(output_dir=output_dir, verbose=verbose)

    def test_no_output_when_not_verbose(self, tmp_path, capsys):
        v = self._make_validator(tmp_path, verbose=False)
        v.log("test message")
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_output_when_verbose(self, tmp_path, capsys):
        v = self._make_validator(tmp_path, verbose=True)
        v.log("test message")
        captured = capsys.readouterr()
        assert "test message" in captured.out


class TestResultsInit:
    """Tests for AdvancedCredentialValidator results initialization."""

    def _make_validator(self, tmp_path):
        output_dir = str(tmp_path / "output")
        os.makedirs(output_dir, exist_ok=True)
        return AdvancedCredentialValidator(output_dir=output_dir)

    def test_initial_results(self, tmp_path):
        v = self._make_validator(tmp_path)
        assert v.results["valid"] == 0
        assert v.results["invalid"] == 0
        assert v.results["total"] == 0
        assert v.results["valid_credentials"] == []
