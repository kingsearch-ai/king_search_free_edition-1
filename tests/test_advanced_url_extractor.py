"""Unit tests for Advanced_URL_extractor module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from modules.Advanced_URL_extractor import (
    get_domain,
    filter_urls_by_domain,
    filter_unique_urls,
    filter_unique_domain_urls,
    scan_folder_for_files,
    CATEGORY_PATTERNS,
)


class TestGetDomain:
    """Tests for get_domain."""

    def test_simple_url(self):
        assert get_domain("https://example.com/path") == "example.com"

    def test_url_with_port(self):
        assert get_domain("https://example.com:8080/path") == "example.com:8080"

    def test_url_with_subdomain(self):
        assert get_domain("https://api.v2.example.com/path") == "api.v2.example.com"

    def test_ip_address(self):
        assert get_domain("http://192.168.1.1/admin") == "192.168.1.1"

    def test_localhost(self):
        assert get_domain("http://localhost:3000") == "localhost:3000"


class TestFilterUrlsByDomain:
    """Tests for filter_urls_by_domain."""

    def test_filter_matching_domain(self):
        urls = [
            "https://example.com/page1",
            "https://other.com/page2",
            "https://sub.example.com/page3",
        ]
        result = filter_urls_by_domain(urls, "example.com")
        assert len(result) == 2
        assert "https://other.com/page2" not in result

    def test_no_domain_returns_all(self):
        urls = ["https://a.com", "https://b.com"]
        result = filter_urls_by_domain(urls, None)
        assert result == urls

    def test_empty_domain_returns_all(self):
        urls = ["https://a.com"]
        result = filter_urls_by_domain(urls, "")
        assert result == urls

    def test_no_matches(self):
        urls = ["https://example.com"]
        result = filter_urls_by_domain(urls, "other.com")
        assert result == []

    def test_case_insensitive(self):
        urls = ["https://Example.COM/page"]
        result = filter_urls_by_domain(urls, "example.com")
        assert len(result) == 1


class TestFilterUniqueUrls:
    """Tests for filter_unique_urls."""

    def test_removes_duplicates(self):
        urls = ["https://a.com", "https://b.com", "https://a.com"]
        result = filter_unique_urls(urls)
        assert result == ["https://a.com", "https://b.com"]

    def test_preserves_order(self):
        urls = ["https://c.com", "https://a.com", "https://b.com"]
        result = filter_unique_urls(urls)
        assert result == ["https://c.com", "https://a.com", "https://b.com"]

    def test_empty_list(self):
        assert filter_unique_urls([]) == []

    def test_all_same(self):
        urls = ["https://a.com"] * 5
        assert filter_unique_urls(urls) == ["https://a.com"]


class TestFilterUniqueDomainUrls:
    """Tests for filter_unique_domain_urls."""

    def test_keeps_one_per_domain(self):
        urls = [
            "https://example.com/page1",
            "https://example.com/page2",
            "https://other.com/page1",
        ]
        result = filter_unique_domain_urls(urls)
        assert len(result) == 2
        domains = [get_domain(u) for u in result]
        assert len(set(domains)) == 2

    def test_preserves_first_url_per_domain(self):
        urls = [
            "https://example.com/first",
            "https://example.com/second",
        ]
        result = filter_unique_domain_urls(urls)
        assert result == ["https://example.com/first"]

    def test_empty_list(self):
        assert filter_unique_domain_urls([]) == []


class TestScanFolderForFiles:
    """Tests for scan_folder_for_files."""

    def test_finds_supported_files(self, tmp_path):
        (tmp_path / "test.html").write_text("<html></html>")
        (tmp_path / "test.txt").write_text("hello")
        (tmp_path / "test.json").write_text("{}")
        (tmp_path / "test.jpg").write_bytes(b"\xff\xd8")

        result = scan_folder_for_files(str(tmp_path))
        extensions = [os.path.splitext(f)[1] for f in result]
        assert ".html" in extensions
        assert ".txt" in extensions
        assert ".json" in extensions
        assert ".jpg" not in extensions

    def test_scans_subdirectories(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "test.py").write_text("print('hi')")

        result = scan_folder_for_files(str(tmp_path))
        assert any("test.py" in f for f in result)

    def test_empty_directory(self, tmp_path):
        result = scan_folder_for_files(str(tmp_path))
        assert result == []


class TestCategoryPatterns:
    """Tests for CATEGORY_PATTERNS constant."""

    def test_has_expected_categories(self):
        assert "API Endpoint" in CATEGORY_PATTERNS
        assert "Login Page" in CATEGORY_PATTERNS
        assert "Sensitive Data" in CATEGORY_PATTERNS
        assert "Database Connection" in CATEGORY_PATTERNS
        assert "Payment" in CATEGORY_PATTERNS

    def test_patterns_are_lists(self):
        for category, patterns in CATEGORY_PATTERNS.items():
            assert isinstance(patterns, list)
            assert len(patterns) > 0

    def test_patterns_are_valid_regex(self):
        import re
        for category, patterns in CATEGORY_PATTERNS.items():
            for pattern in patterns:
                re.compile(pattern)
