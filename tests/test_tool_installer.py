"""Unit tests for tool_installer module."""

import sys
import os
import shutil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from tool_installer import is_installed, tools, git_urls, go_install_map


class TestIsInstalled:
    """Tests for is_installed."""

    def test_python_is_installed(self):
        assert is_installed("python3") is True

    def test_nonexistent_tool(self):
        assert is_installed("nonexistent_tool_xyz_12345") is False

    def test_git_installed(self):
        assert is_installed("git") is True

    def test_bash_installed(self):
        assert is_installed("bash") is True


class TestToolsDict:
    """Tests for the tools dictionary."""

    def test_tools_is_dict(self):
        assert isinstance(tools, dict)

    def test_tools_not_empty(self):
        assert len(tools) > 0

    def test_all_values_are_valid_methods(self):
        valid_methods = {"apt", "go", "git", "snap"}
        for tool, method in tools.items():
            assert method in valid_methods, f"Tool {tool} has invalid method: {method}"

    def test_common_tools_present(self):
        assert "nmap" in tools
        assert "curl" in tools
        assert "git" in tools
        assert "sqlmap" in tools

    def test_git_tools_have_urls(self):
        for tool, method in tools.items():
            if method == "git":
                assert tool in git_urls, f"Git tool {tool} missing URL"

    def test_go_tools_have_install_paths(self):
        for tool, method in tools.items():
            if method == "go":
                assert tool in go_install_map, f"Go tool {tool} missing install path"


class TestGitUrls:
    """Tests for git_urls dictionary."""

    def test_all_urls_valid(self):
        for tool, url in git_urls.items():
            assert url.startswith("https://"), f"Invalid URL for {tool}: {url}"
            assert url.endswith(".git"), f"URL for {tool} should end with .git"


class TestGoInstallMap:
    """Tests for go_install_map dictionary."""

    def test_all_paths_contain_github(self):
        for tool, path in go_install_map.items():
            assert "github.com" in path, f"Go install path for {tool} should be a GitHub path"

    def test_all_paths_end_with_latest(self):
        for tool, path in go_install_map.items():
            assert path.endswith("@latest"), f"Go install path for {tool} should end with @latest"
