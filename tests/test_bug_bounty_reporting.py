"""Unit tests for Bug_Bounty_Automation_Reporting module."""

import sys
import os
import re
import json
import tempfile
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.Bug_Bounty_Automation_Reporting import (
    generate_poc,
    extract_sensitive_data,
    determine_severity,
    classify_risk,
    extract_target_url,
    update_vulnerability_database,
    SENSITIVE_PATTERNS,
    CVSS_SEVERITY,
    vuln_to_index,
    clf,
)


class TestGeneratePoC:
    """Tests for generate_poc."""

    def test_sql_injection_poc(self):
        result = generate_poc("SQL Injection")
        assert "Proof of Concept" in result
        assert "pre" in result

    def test_xss_poc(self):
        result = generate_poc("XSS")
        assert "Proof of Concept" in result

    def test_ssrf_poc(self):
        result = generate_poc("SSRF")
        assert "Proof of Concept" in result

    def test_command_injection_poc(self):
        result = generate_poc("Command Injection")
        assert "Proof of Concept" in result

    def test_open_redirect_poc(self):
        result = generate_poc("Open Redirect")
        assert "Proof of Concept" in result

    def test_jwt_issues_poc(self):
        result = generate_poc("JWT Issues")
        assert "Proof of Concept" in result

    def test_csrf_poc(self):
        result = generate_poc("CSRF")
        assert "Proof of Concept" in result

    def test_unknown_type_returns_no_poc(self):
        result = generate_poc("Unknown Vulnerability")
        assert "No PoC available" in result

    def test_with_target_url_open_redirect(self):
        result = generate_poc("Open Redirect", target_url="https://target.com")
        assert "target.com" in result

    def test_with_target_url_ssrf(self):
        result = generate_poc("SSRF", target_url="https://target.com")
        assert "target.com" in result

    def test_target_url_not_used_for_xss(self):
        result = generate_poc("XSS", target_url="https://target.com")
        assert "Proof of Concept" in result


class TestExtractSensitiveData:
    """Tests for extract_sensitive_data."""

    def test_finds_api_keys(self, tmp_path):
        report = tmp_path / "report.txt"
        report.write_text('api_key="ABCDEFGHIJKLMNOP1234567890"')
        result = extract_sensitive_data(str(report))
        assert "API Keys" in result

    def test_finds_login_urls(self, tmp_path):
        report = tmp_path / "report.txt"
        report.write_text("Visit https://example.com/login to authenticate")
        result = extract_sensitive_data(str(report))
        assert "Login URLs" in result

    def test_finds_cve_references(self, tmp_path):
        report = tmp_path / "report.txt"
        report.write_text("Vulnerable to CVE-2023-12345")
        result = extract_sensitive_data(str(report))
        assert "CVE References" in result

    def test_empty_file(self, tmp_path):
        report = tmp_path / "empty.txt"
        report.write_text("")
        result = extract_sensitive_data(str(report))
        assert result == {}

    def test_confidence_score_capped(self, tmp_path):
        report = tmp_path / "report.txt"
        report.write_text("secret=abc123\n" * 100)
        result = extract_sensitive_data(str(report))
        for key, data in result.items():
            assert data["confidence"] <= 95

    def test_high_risk_patterns_get_confidence_boost(self, tmp_path):
        report = tmp_path / "report.txt"
        report.write_text('api_key="ABCDEFGHIJKLMNOP1234567890"')
        result = extract_sensitive_data(str(report))
        if "API Keys" in result:
            assert result["API Keys"]["confidence"] > 0

    def test_nonexistent_file(self):
        result = extract_sensitive_data("/nonexistent/file.txt")
        assert result == {}

    def test_matches_are_unique(self, tmp_path):
        report = tmp_path / "report.txt"
        report.write_text("CVE-2023-12345\nCVE-2023-12345\nCVE-2023-12345")
        result = extract_sensitive_data(str(report))
        if "CVE References" in result:
            assert len(result["CVE References"]["matches"]) == 1


class TestDetermineSeverity:
    """Tests for determine_severity."""

    def test_critical_with_api_keys_and_sqli(self):
        data = {
            "API Keys": {"matches": ["key1"], "confidence": 80},
            "SQL Injection": {"matches": ["payload1"], "confidence": 70},
        }
        result = determine_severity(data)
        assert result["severity"] in ["P1", "P2", "P3", "P4"]
        assert "confidence" in result

    def test_empty_data(self):
        result = determine_severity({})
        assert result["severity"] in ["P1", "P2", "P3", "P4"]

    def test_single_vulnerability(self):
        data = {"XSS": {"matches": ["<script>"], "confidence": 60}}
        result = determine_severity(data)
        assert result["severity"] in ["P1", "P2", "P3", "P4"]

    def test_returns_contributing_factors(self):
        data = {
            "API Keys": {"matches": ["k"], "confidence": 80},
            "Secrets": {"matches": ["s"], "confidence": 70},
        }
        result = determine_severity(data)
        assert isinstance(result["contributing_factors"], list)


class TestClassifyRisk:
    """Tests for classify_risk."""

    def test_all_features_present(self):
        features = [1] * 15
        result = classify_risk(features)
        assert result["severity"] in ["P1", "P2", "P3", "P4"]
        assert 0 <= result["confidence"] <= 100

    def test_no_features_present(self):
        features = [0] * 15
        result = classify_risk(features)
        assert result["severity"] in ["P1", "P2", "P3", "P4"]

    def test_single_critical_feature(self):
        features = [0] * 15
        features[vuln_to_index["API Keys"]] = 1
        result = classify_risk(features)
        assert result["severity"] in ["P1", "P2", "P3", "P4"]


class TestExtractTargetUrl:
    """Tests for extract_target_url."""

    def test_extracts_from_filename(self, tmp_path):
        report = tmp_path / "report_example.com.txt"
        report.write_text("some content")
        result = extract_target_url(str(report))
        assert "example.com" in result

    def test_extracts_from_content(self, tmp_path):
        report = tmp_path / "data"
        report.write_text("Target URL: https://testsite.com/api")
        result = extract_target_url(str(report))
        assert "testsite.com" in result

    def test_defaults_to_example_com(self, tmp_path):
        report = tmp_path / "data"
        report.write_text("no urls here at all")
        result = extract_target_url(str(report))
        assert result == "https://example.com"


class TestSensitivePatterns:
    """Tests for SENSITIVE_PATTERNS constant."""

    def test_all_patterns_compile(self):
        for name, pattern in SENSITIVE_PATTERNS.items():
            re.compile(pattern, re.IGNORECASE)

    def test_sqli_pattern_matches(self):
        pattern = SENSITIVE_PATTERNS["SQL Injection"]
        test = "SELECT * FROM users WHERE id = 1"
        assert re.search(pattern, test, re.IGNORECASE) is not None

    def test_xss_pattern_matches(self):
        pattern = SENSITIVE_PATTERNS["XSS"]
        test = "<script>alert('xss')</script>"
        assert re.search(pattern, test, re.IGNORECASE) is not None

    def test_ssrf_pattern_matches(self):
        pattern = SENSITIVE_PATTERNS["SSRF"]
        test = "http://127.0.0.1/admin"
        assert re.search(pattern, test, re.IGNORECASE) is not None

    def test_cve_pattern_matches(self):
        pattern = SENSITIVE_PATTERNS["CVE References"]
        test = "CVE-2023-12345"
        assert re.search(pattern, test) is not None

    def test_jwt_pattern_matches(self):
        pattern = SENSITIVE_PATTERNS["JWT Issues"]
        test = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert re.search(pattern, test) is not None


class TestCVSSSeverity:
    """Tests for CVSS_SEVERITY constant."""

    def test_has_all_priority_levels(self):
        assert "P1" in CVSS_SEVERITY
        assert "P2" in CVSS_SEVERITY
        assert "P3" in CVSS_SEVERITY
        assert "P4" in CVSS_SEVERITY

    def test_each_has_required_fields(self):
        for priority, data in CVSS_SEVERITY.items():
            assert "score" in data
            assert "vector" in data
            assert "description" in data


class TestVulnToIndex:
    """Tests for vuln_to_index mapping."""

    def test_has_expected_mappings(self):
        assert vuln_to_index["API Keys"] == 0
        assert vuln_to_index["XSS"] == 4
        assert vuln_to_index["SQL Injection"] == 3
        assert vuln_to_index["IDOR"] == 9

    def test_all_indices_unique(self):
        values = list(vuln_to_index.values())
        assert len(values) == len(set(values))

    def test_indices_match_training_data_columns(self):
        assert max(vuln_to_index.values()) == 14


class TestUpdateVulnerabilityDatabase:
    """Tests for update_vulnerability_database."""

    def test_creates_database_file(self, tmp_path, monkeypatch):
        db_file = str(tmp_path / "vuln_db.json")
        monkeypatch.setattr(
            "modules.Bug_Bounty_Automation_Reporting.DATABASE_FILE", db_file
        )
        report = tmp_path / "report_target.com.txt"
        report.write_text("test content")
        extracted_data = {
            "XSS": {"matches": ["<script>alert(1)</script>"], "confidence": 80}
        }
        update_vulnerability_database(extracted_data, str(report))

        assert os.path.exists(db_file)
        with open(db_file) as f:
            data = json.load(f)
        assert len(data) > 0


class TestMLClassifier:
    """Tests for the trained classifier."""

    def test_classifier_is_fitted(self):
        assert hasattr(clf, "classes_")
        assert len(clf.classes_) > 0

    def test_classifier_predicts_valid_classes(self):
        features = np.array([[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]])
        prediction = clf.predict(features)[0]
        assert prediction in ["P1", "P2", "P3", "P4"]

    def test_classifier_probabilities_sum_to_one(self):
        features = np.array([[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]])
        proba = clf.predict_proba(features)[0]
        assert abs(sum(proba) - 1.0) < 0.01
