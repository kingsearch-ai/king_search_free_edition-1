"""Unit tests for AI-Powered_Bug_Analysis module."""

import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# The module name has hyphens, so we use importlib
import importlib
bug_analysis = importlib.import_module("modules.AI-Powered_Bug_Analysis")
BugAnalyzer = bug_analysis.BugAnalyzer


class TestExtractText:
    """Tests for BugAnalyzer._extract_text."""

    def test_returns_none_for_none(self):
        analyzer = BugAnalyzer()
        assert analyzer._extract_text(None) is None

    def test_extracts_text_from_element(self):
        analyzer = BugAnalyzer()
        mock_element = MagicMock()
        mock_element.get_text.return_value = "  Hello World  "
        result = analyzer._extract_text(mock_element)
        mock_element.get_text.assert_called_once_with(strip=True)
        assert result == "  Hello World  " or result == "Hello World"


class TestCalculateImportance:
    """Tests for BugAnalyzer._calculate_importance."""

    def test_no_keywords_returns_zero(self):
        analyzer = BugAnalyzer()
        assert analyzer._calculate_importance("nothing special here") == 0

    def test_single_keyword(self):
        analyzer = BugAnalyzer()
        score = analyzer._calculate_importance("An error occurred in the system")
        assert score >= 1

    def test_multiple_keywords(self):
        analyzer = BugAnalyzer()
        score = analyzer._calculate_importance("error crash fail memory leak")
        assert score >= 5

    def test_error_code_bonus(self):
        analyzer = BugAnalyzer()
        score_with_code = analyzer._calculate_importance("error abc-123 occurred")
        score_without_code = analyzer._calculate_importance("something happened")
        assert score_with_code > score_without_code

    def test_exception_bonus(self):
        analyzer = BugAnalyzer()
        score = analyzer._calculate_importance("NullPointerException thrown")
        assert score >= 2

    def test_stack_trace_bonus(self):
        analyzer = BugAnalyzer()
        score = analyzer._calculate_importance("stack trace found at line 42")
        assert score >= 2

    def test_case_insensitive(self):
        analyzer = BugAnalyzer()
        score_lower = analyzer._calculate_importance("error occurred")
        score_upper = analyzer._calculate_importance("ERROR occurred")
        assert score_lower == score_upper

    def test_all_keywords(self):
        analyzer = BugAnalyzer()
        text = " ".join(analyzer.config['important_keywords'])
        score = analyzer._calculate_importance(text)
        assert score >= len(analyzer.config['important_keywords'])


class TestParseSeverity:
    """Tests for BugAnalyzer._parse_severity."""

    def test_critical(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Critical") == 4

    def test_high(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("High Priority") == 4

    def test_blocker(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Blocker") == 4

    def test_severe(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Severe issue") == 4

    def test_major(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Major bug") == 3

    def test_medium(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Medium") == 3

    def test_moderate(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Moderate severity") == 3

    def test_minor(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Minor issue") == 1

    def test_low(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Low priority") == 1

    def test_trivial(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Trivial") == 1

    def test_unknown(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("Unknown") == 2

    def test_none(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity(None) == 2

    def test_empty_string(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("") == 2

    def test_unrecognized_string(self):
        analyzer = BugAnalyzer()
        assert analyzer._parse_severity("something else") == 2


class TestBugAnalyzerInit:
    """Tests for BugAnalyzer initialization."""

    def test_default_config(self):
        analyzer = BugAnalyzer()
        assert analyzer.config['similarity_threshold'] == 0.75
        assert analyzer.config['min_bug_cluster'] == 3
        assert analyzer.config['max_features'] == 5000
        assert len(analyzer.config['important_keywords']) > 0
        assert len(analyzer.config['ignored_patterns']) > 0

    def test_custom_config(self):
        config = {
            'similarity_threshold': 0.9,
            'min_bug_cluster': 5,
            'max_features': 1000,
            'important_keywords': ['test'],
            'ignored_patterns': [],
        }
        analyzer = BugAnalyzer(config=config)
        assert analyzer.config['similarity_threshold'] == 0.9
        assert analyzer.config['min_bug_cluster'] == 5

    def test_initial_state(self):
        analyzer = BugAnalyzer()
        assert analyzer.bug_data == []
        assert analyzer.feature_matrix is None
        assert analyzer.clusters is None
        assert analyzer.similarity_matrix is None

    def test_vectorize_empty_data_returns_false(self):
        analyzer = BugAnalyzer()
        assert analyzer.vectorize_data() is False
