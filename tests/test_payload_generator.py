"""Unit tests for Payload_Generator module."""

import sys
import os
import base64
import urllib.parse
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.Payload_Generator import PayloadGenerator, add_signature, export_as_json


class TestPayloadEncoding:
    """Tests for the _encode_payload method."""

    def test_standard_encoding_returns_unchanged(self):
        gen = PayloadGenerator(encoding="standard")
        assert gen._encode_payload("hello") == "hello"

    def test_url_encoding(self):
        gen = PayloadGenerator(encoding="url")
        result = gen._encode_payload("<script>alert(1)</script>")
        assert "%3C" in result
        assert "%3E" in result
        assert "<" not in result

    def test_double_url_encoding(self):
        gen = PayloadGenerator(encoding="double_url")
        result = gen._encode_payload("<script>")
        assert "%25" in result

    def test_hex_encoding(self):
        gen = PayloadGenerator(encoding="hex")
        result = gen._encode_payload("AB")
        assert result == "%41%42"

    def test_unicode_encoding(self):
        gen = PayloadGenerator(encoding="unicode")
        result = gen._encode_payload("A")
        assert "\\u00" in result

    def test_html_entities_encoding(self):
        gen = PayloadGenerator(encoding="html_entities")
        result = gen._encode_payload("A")
        assert "&#65;" in result

    def test_base64_encoding(self):
        gen = PayloadGenerator(encoding="base64")
        result = gen._encode_payload("hello")
        assert result == base64.b64encode(b"hello").decode()

    def test_encoding_override(self):
        gen = PayloadGenerator(encoding="standard")
        result = gen._encode_payload("hello", encoding_override="base64")
        assert result == base64.b64encode(b"hello").decode()

    def test_unknown_encoding_returns_original(self):
        gen = PayloadGenerator(encoding="nonexistent")
        assert gen._encode_payload("test") == "test"


class TestRandomString:
    """Tests for _get_random_string."""

    def test_default_length(self):
        gen = PayloadGenerator()
        result = gen._get_random_string()
        assert len(result) == 8

    def test_custom_length(self):
        gen = PayloadGenerator()
        result = gen._get_random_string(16)
        assert len(result) == 16

    def test_alphabetic_only(self):
        gen = PayloadGenerator()
        result = gen._get_random_string(100)
        assert result.isalpha()

    def test_unique_strings(self):
        gen = PayloadGenerator()
        strings = {gen._get_random_string() for _ in range(50)}
        assert len(strings) > 1


class TestWAFEvasion:
    """Tests for _add_waf_evasion."""

    def test_no_evasion_when_disabled(self):
        gen = PayloadGenerator(waf_evasion=False)
        payload = "<script>alert(1)</script>"
        assert gen._add_waf_evasion(payload, "xss") == payload

    def test_evasion_applied_for_xss(self):
        gen = PayloadGenerator(waf_evasion=True)
        original = "<script>alert(1)</script>"
        modified = gen._add_waf_evasion(original, "xss")
        assert isinstance(modified, str)
        assert len(modified) > 0

    def test_evasion_applied_for_sqli(self):
        gen = PayloadGenerator(waf_evasion=True)
        original = "' OR '1'='1' --"
        modified = gen._add_waf_evasion(original, "sqli")
        assert isinstance(modified, str)

    def test_unknown_type_returns_unchanged(self):
        gen = PayloadGenerator(waf_evasion=True)
        payload = "some payload"
        assert gen._add_waf_evasion(payload, "unknown_type") == payload


class TestXSSPayloads:
    """Tests for generate_xss_payloads."""

    def test_returns_requested_count(self):
        gen = PayloadGenerator()
        result = gen.generate_xss_payloads(num=3)
        assert len(result) == 3

    def test_payloads_are_strings(self):
        gen = PayloadGenerator()
        for payload in gen.generate_xss_payloads(num=5):
            assert isinstance(payload, str)

    def test_high_complexity_obfuscation(self):
        gen = PayloadGenerator(complexity="high")
        payloads = gen.generate_xss_payloads(num=10)
        assert len(payloads) == 10

    def test_csp_bypass_payloads(self):
        gen = PayloadGenerator()
        normal = gen.generate_xss_payloads(num=50)
        csp = gen.generate_xss_payloads(num=50, bypass_csp=True)
        assert len(csp) == 50

    def test_url_encoded_payloads(self):
        gen = PayloadGenerator(encoding="url")
        payloads = gen.generate_xss_payloads(num=3)
        for p in payloads:
            assert "%" in p or p == urllib.parse.quote(p)


class TestSQLiPayloads:
    """Tests for generate_sqli_payloads."""

    def test_returns_requested_count(self):
        gen = PayloadGenerator()
        result = gen.generate_sqli_payloads(num=4)
        assert len(result) == 4

    def test_payloads_are_strings(self):
        gen = PayloadGenerator()
        for payload in gen.generate_sqli_payloads(num=5):
            assert isinstance(payload, str)

    def test_no_randomize(self):
        gen = PayloadGenerator()
        result = gen.generate_sqli_payloads(num=3, randomize=False)
        assert len(result) == 3


class TestXXEPayloads:
    """Tests for generate_xxe_payloads."""

    def test_returns_requested_count(self):
        gen = PayloadGenerator()
        result = gen.generate_xxe_payloads(num=3)
        assert len(result) == 3

    def test_contains_xml_declarations(self):
        gen = PayloadGenerator()
        payloads = gen.generate_xxe_payloads(num=10)
        xml_payloads = [p for p in payloads if "<?xml" in p or "<!DOCTYPE" in p.upper() or "xmlns" in p]
        assert len(xml_payloads) > 0


class TestSSRFPayloads:
    """Tests for generate_ssrf_payloads."""

    def test_returns_requested_count(self):
        gen = PayloadGenerator()
        result = gen.generate_ssrf_payloads(num=3)
        assert len(result) == 3

    def test_contains_internal_addresses(self):
        gen = PayloadGenerator(complexity="low")
        payloads = gen.generate_ssrf_payloads(num=20)
        has_internal = any(
            "127.0.0.1" in p or "localhost" in p or "169.254" in p
            or "10.0.0" in p or "192.168" in p or "172.16" in p
            or "metadata" in p or "0177" in p or "0x7f" in p
            or "file:///" in p or "gopher://" in p
            for p in payloads
        )
        assert has_internal


class TestWAFBypassPayloads:
    """Tests for generate_waf_bypass_payloads."""

    def test_all_types(self):
        gen = PayloadGenerator()
        result = gen.generate_waf_bypass_payloads(num=5, target_type="all")
        assert len(result) == 5

    def test_specific_type(self):
        gen = PayloadGenerator()
        result = gen.generate_waf_bypass_payloads(num=3, target_type="xss")
        assert len(result) == 3

    def test_invalid_type_returns_empty(self):
        gen = PayloadGenerator()
        result = gen.generate_waf_bypass_payloads(num=3, target_type="nonexistent")
        assert len(result) == 0


class TestGenerateAllPayloads:
    """Tests for generate_all_payloads."""

    def test_returns_all_types(self):
        gen = PayloadGenerator()
        result = gen.generate_all_payloads(num_each=2)
        assert "xss" in result
        assert "sqli" in result
        assert "xxe" in result
        assert "ssrf" in result
        assert "waf_bypass" in result

    def test_each_type_has_correct_count(self):
        gen = PayloadGenerator()
        result = gen.generate_all_payloads(num_each=3)
        for key, payloads in result.items():
            assert len(payloads) == 3


class TestAddSignature:
    """Tests for add_signature function."""

    def test_html_payload_gets_comment_signature(self):
        payloads = {"xss": ["<script>alert(1)</script>"]}
        add_signature(payloads)
        assert "<!-- test_sig:" in payloads["xss"][0]

    def test_xml_payload_gets_comment_signature(self):
        payloads = {"xxe": ['<?xml version="1.0"?><test></test>']}
        add_signature(payloads)
        assert "<!-- test_sig:" in payloads["xxe"][0]

    def test_plain_payload_gets_block_comment_signature(self):
        payloads = {"sqli": ["' OR 1=1 --"]}
        add_signature(payloads)
        assert "/*test_sig:" in payloads["sqli"][0]


class TestExportAsJson:
    """Tests for export_as_json function."""

    def test_writes_valid_json(self, tmp_path):
        import json
        payloads = {"xss": ["<script>alert(1)</script>"], "sqli": ["' OR 1=1"]}
        output = str(tmp_path / "test_payloads.json")
        export_as_json(payloads, output)

        with open(output) as f:
            data = json.load(f)
        assert data == payloads
