"""Unit tests for API_IDOR_Privilege_Escalation module."""

import sys
import os
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.API_IDOR_Privilege_Escalation import (
    encode_credentials,
    decode_credentials,
    IDORTest,
    IDORTester,
)


class TestEncodeCredentials:
    """Tests for encode_credentials."""

    def test_basic_encoding(self):
        result = encode_credentials("admin", "password")
        decoded = base64.b64decode(result).decode()
        assert decoded == "admin:password"

    def test_special_characters_in_password(self):
        result = encode_credentials("user", "p@ss:word!")
        decoded = base64.b64decode(result).decode()
        assert decoded == "user:p@ss:word!"

    def test_empty_username(self):
        result = encode_credentials("", "password")
        decoded = base64.b64decode(result).decode()
        assert decoded == ":password"

    def test_empty_password(self):
        result = encode_credentials("admin", "")
        decoded = base64.b64decode(result).decode()
        assert decoded == "admin:"

    def test_unicode_characters(self):
        result = encode_credentials("user", "p\u00e4ssw\u00f6rd")
        decoded = base64.b64decode(result).decode()
        assert decoded == "user:p\u00e4ssw\u00f6rd"


class TestDecodeCredentials:
    """Tests for decode_credentials."""

    def test_basic_decoding(self):
        encoded = base64.b64encode(b"admin:password").decode()
        username, password = decode_credentials(encoded)
        assert username == "admin"
        assert password == "password"

    def test_password_with_colon(self):
        encoded = base64.b64encode(b"admin:pass:word").decode()
        username, password = decode_credentials(encoded)
        assert username == "admin"
        assert password == "pass:word"

    def test_no_colon(self):
        encoded = base64.b64encode(b"justausername").decode()
        result, password = decode_credentials(encoded)
        assert result == "justausername"
        assert password is None

    def test_roundtrip(self):
        encoded = encode_credentials("testuser", "secret123")
        username, password = decode_credentials(encoded)
        assert username == "testuser"
        assert password == "secret123"


class TestIDORTestDataclass:
    """Tests for IDORTest dataclass."""

    def test_default_values(self):
        test = IDORTest(
            endpoint="https://api.example.com/users/1",
            method="GET",
            original_id="1",
            target_id="2",
        )
        assert test.headers == {}
        assert test.params == {}
        assert test.data == {}
        assert test.cookies == {}
        assert test.success_indicators == []
        assert test.failure_indicators == []
        assert test.success_status_codes == []
        assert test.id_locations == []

    def test_custom_values(self):
        test = IDORTest(
            endpoint="https://api.example.com/users/1",
            method="POST",
            original_id="1",
            target_id="admin",
            headers={"Authorization": "Bearer abc"},
            success_status_codes=[200, 201],
            id_locations=["url", "params"],
        )
        assert test.method == "POST"
        assert test.headers == {"Authorization": "Bearer abc"}
        assert test.success_status_codes == [200, 201]
        assert test.id_locations == ["url", "params"]


class TestIDORTesterReplaceIdInValue:
    """Tests for IDORTester._replace_id_in_value (static method via instance)."""

    def _make_tester(self, tmp_path):
        config = {
            "credentials": [],
            "target_endpoints": [],
            "test_parameters": {},
        }
        config_path = str(tmp_path / "config.json")
        import json
        with open(config_path, "w") as f:
            json.dump(config, f)
        return IDORTester(config_path, str(tmp_path / "output.json"))

    def test_replace_in_string(self, tmp_path):
        tester = self._make_tester(tmp_path)
        result = tester._replace_id_in_value("user_id=123", "123", "456")
        assert result == "user_id=456"

    def test_replace_in_dict(self, tmp_path):
        tester = self._make_tester(tmp_path)
        result = tester._replace_id_in_value({"id": "123", "name": "test"}, "123", "456")
        assert result == {"id": "456", "name": "test"}

    def test_replace_in_list(self, tmp_path):
        tester = self._make_tester(tmp_path)
        result = tester._replace_id_in_value(["123", "other"], "123", "456")
        assert result == ["456", "other"]

    def test_replace_in_nested(self, tmp_path):
        tester = self._make_tester(tmp_path)
        result = tester._replace_id_in_value(
            {"data": {"user_id": "123"}, "items": ["123"]},
            "123",
            "456",
        )
        assert result == {"data": {"user_id": "456"}, "items": ["456"]}

    def test_non_string_value_unchanged(self, tmp_path):
        tester = self._make_tester(tmp_path)
        assert tester._replace_id_in_value(42, "42", "99") == 42
        assert tester._replace_id_in_value(None, "x", "y") is None
        assert tester._replace_id_in_value(True, "True", "False") is True


class TestIDORTesterReplaceIds:
    """Tests for IDORTester._replace_ids."""

    def _make_tester(self, tmp_path):
        config = {
            "credentials": [],
            "target_endpoints": [],
            "test_parameters": {},
        }
        config_path = str(tmp_path / "config.json")
        import json
        with open(config_path, "w") as f:
            json.dump(config, f)
        return IDORTester(config_path, str(tmp_path / "output.json"))

    def test_replace_in_url(self, tmp_path):
        tester = self._make_tester(tmp_path)
        test = IDORTest(
            endpoint="https://api.example.com/users/42",
            method="GET",
            original_id="42",
            target_id="99",
            id_locations=["url"],
        )
        result = tester._replace_ids(test)
        assert "99" in result.endpoint
        assert "42" not in result.endpoint

    def test_replace_in_params(self, tmp_path):
        tester = self._make_tester(tmp_path)
        test = IDORTest(
            endpoint="https://api.example.com/data",
            method="GET",
            original_id="42",
            target_id="99",
            params={"user_id": "42"},
            id_locations=["params"],
        )
        result = tester._replace_ids(test)
        assert result.params["user_id"] == "99"

    def test_replace_in_json_body(self, tmp_path):
        tester = self._make_tester(tmp_path)
        test = IDORTest(
            endpoint="https://api.example.com/data",
            method="POST",
            original_id="42",
            target_id="99",
            data={"user_id": "42"},
            id_locations=["json"],
        )
        result = tester._replace_ids(test)
        assert result.data["user_id"] == "99"

    def test_replace_in_headers(self, tmp_path):
        tester = self._make_tester(tmp_path)
        test = IDORTest(
            endpoint="https://api.example.com/data",
            method="GET",
            original_id="42",
            target_id="99",
            headers={"X-User-Id": "42"},
            id_locations=["headers"],
        )
        result = tester._replace_ids(test)
        assert result.headers["X-User-Id"] == "99"

    def test_replace_in_cookies(self, tmp_path):
        tester = self._make_tester(tmp_path)
        test = IDORTest(
            endpoint="https://api.example.com/data",
            method="GET",
            original_id="42",
            target_id="99",
            cookies={"session_uid": "42"},
            id_locations=["cookies"],
        )
        result = tester._replace_ids(test)
        assert result.cookies["session_uid"] == "99"
