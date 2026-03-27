"""Tests for MCP config scanner."""

import json
import pytest
from pathlib import Path

from skill_audit.mcp_scanner import scan_mcp_config, McpScanResult, McpServerFinding
from skill_audit.analyzer import analyze_file, analyze_mcp_config
from skill_audit.parser import detect_format


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def safe_mcp_config(tmp_path):
    """A safe MCP config with no issues."""
    config = {
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"],
                "env": {},
            }
        }
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(config))
    return path


@pytest.fixture
def risky_mcp_config(tmp_path):
    """An MCP config with multiple security issues."""
    config = {
        "mcpServers": {
            "shell-server": {
                "command": "bash",
                "args": ["-c", "echo hello"],
                "env": {},
            },
            "data-server": {
                "command": "npx",
                "args": ["-y", "some-server", "/"],
                "env": {
                    "OPENAI_API_KEY": "sk-1234567890abcdef1234567890abcdef",
                },
            },
            "wildcard-tools": {
                "command": "npx",
                "args": ["-y", "some-server"],
                "allowedTools": ["*"],
            },
        }
    }
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps(config))
    return path


@pytest.fixture
def desktop_config(tmp_path):
    """A claude_desktop_config.json file."""
    config = {
        "mcpServers": {
            "brave-search": {
                "command": "npx",
                "args": ["-y", "@anthropic/mcp-brave-search"],
                "env": {
                    "BRAVE_API_KEY": "BSAabcdef1234567890",
                },
            }
        }
    }
    path = tmp_path / "claude_desktop_config.json"
    path.write_text(json.dumps(config))
    return path


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

class TestFormatDetection:
    def test_detects_mcp_json(self, safe_mcp_config):
        assert detect_format(safe_mcp_config) == "mcp-config"

    def test_detects_desktop_config(self, desktop_config):
        assert detect_format(desktop_config) == "mcp-config"

    def test_does_not_detect_random_json(self, tmp_path):
        path = tmp_path / "package.json"
        path.write_text('{"name": "test"}')
        assert detect_format(path) != "mcp-config"


# ---------------------------------------------------------------------------
# Scanner: safe configs
# ---------------------------------------------------------------------------

class TestSafeConfig:
    def test_no_findings(self, safe_mcp_config):
        result = scan_mcp_config(safe_mcp_config)
        assert result.servers == []
        assert result.overall_risk == "low"
        assert result.server_count == 1

    def test_summary_mentions_servers(self, safe_mcp_config):
        result = scan_mcp_config(safe_mcp_config)
        assert "1 server(s)" in result.summary


# ---------------------------------------------------------------------------
# Scanner: risky commands
# ---------------------------------------------------------------------------

class TestRiskyCommands:
    def test_bash_command_flagged(self, tmp_path):
        config = {"mcpServers": {"evil": {"command": "bash", "args": []}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        cmd_findings = [f for f in result.servers if f.category == "risky-command"]
        assert len(cmd_findings) >= 1
        assert cmd_findings[0].severity == "critical"

    def test_python_command_flagged(self, tmp_path):
        config = {"mcpServers": {"py": {"command": "python", "args": ["-c", "import os"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        cmd_findings = [f for f in result.servers if f.category == "risky-command"]
        assert len(cmd_findings) >= 1

    def test_node_eval_flagged(self, tmp_path):
        config = {"mcpServers": {"n": {"command": "node", "args": ["-e", "console.log(1)"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        cmd_findings = [f for f in result.servers if f.category == "risky-command"]
        assert len(cmd_findings) >= 1

    def test_npx_safe_not_flagged(self, safe_mcp_config):
        result = scan_mcp_config(safe_mcp_config)
        cmd_findings = [f for f in result.servers if f.category == "risky-command"]
        assert cmd_findings == []


# ---------------------------------------------------------------------------
# Scanner: broad filesystem
# ---------------------------------------------------------------------------

class TestBroadFilesystem:
    def test_root_access_flagged(self, tmp_path):
        config = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server", "/"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        fs_findings = [f for f in result.servers if f.category == "broad-filesystem"]
        assert len(fs_findings) >= 1

    def test_ssh_dir_flagged(self, tmp_path):
        config = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server", "~/.ssh"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        fs_findings = [f for f in result.servers if f.category == "broad-filesystem"]
        assert len(fs_findings) >= 1

    def test_aws_dir_flagged(self, tmp_path):
        config = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server", "~/.aws"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        fs_findings = [f for f in result.servers if f.category == "broad-filesystem"]
        assert len(fs_findings) >= 1

    def test_specific_project_dir_ok(self, safe_mcp_config):
        result = scan_mcp_config(safe_mcp_config)
        fs_findings = [f for f in result.servers if f.category == "broad-filesystem"]
        assert fs_findings == []


# ---------------------------------------------------------------------------
# Scanner: network exposure
# ---------------------------------------------------------------------------

class TestNetworkExposure:
    def test_bind_all_interfaces(self, tmp_path):
        config = {"mcpServers": {"api": {"command": "node", "args": ["server.js", "--host", "0.0.0.0"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        net_findings = [f for f in result.servers if f.category == "network-exposure"]
        assert len(net_findings) >= 1

    def test_url_with_0000(self, tmp_path):
        config = {"mcpServers": {"api": {"command": "npx", "args": [], "url": "http://0.0.0.0:8080"}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        net_findings = [f for f in result.servers if f.category == "network-exposure"]
        assert len(net_findings) >= 1


# ---------------------------------------------------------------------------
# Scanner: suspicious URLs
# ---------------------------------------------------------------------------

class TestSuspiciousUrls:
    def test_url_shortener_flagged(self, tmp_path):
        config = {"mcpServers": {"s": {"command": "npx", "args": ["-y", "server", "https://bit.ly/abc123"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        url_findings = [f for f in result.servers if f.category == "suspicious-url"]
        assert len(url_findings) >= 1

    def test_direct_ip_flagged(self, tmp_path):
        config = {"mcpServers": {"s": {"command": "npx", "args": [], "url": "http://192.168.1.1:8080/api"}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        url_findings = [f for f in result.servers if f.category == "suspicious-url"]
        assert len(url_findings) >= 1


# ---------------------------------------------------------------------------
# Scanner: overly permissive tools
# ---------------------------------------------------------------------------

class TestOverlyPermissive:
    def test_wildcard_tools_flagged(self, tmp_path):
        config = {"mcpServers": {"s": {"command": "npx", "args": [], "allowedTools": ["*"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        perm_findings = [f for f in result.servers if f.category == "overly-permissive"]
        assert len(perm_findings) >= 1

    def test_many_tools_flagged(self, tmp_path):
        tools = [f"tool_{i}" for i in range(25)]
        config = {"mcpServers": {"s": {"command": "npx", "args": [], "allowedTools": tools}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        perm_findings = [f for f in result.servers if f.category == "overly-permissive"]
        assert len(perm_findings) >= 1
        assert perm_findings[0].severity == "medium"

    def test_few_tools_ok(self, tmp_path):
        config = {"mcpServers": {"s": {"command": "npx", "args": [], "allowedTools": ["read", "write"]}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        perm_findings = [f for f in result.servers if f.category == "overly-permissive"]
        assert perm_findings == []


# ---------------------------------------------------------------------------
# Scanner: no authentication
# ---------------------------------------------------------------------------

class TestNoAuth:
    def test_url_without_auth_flagged(self, tmp_path):
        config = {"mcpServers": {"api": {"command": "npx", "args": [], "url": "http://example.com/api", "env": {}}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        auth_findings = [f for f in result.servers if f.category == "no-auth"]
        assert len(auth_findings) >= 1

    def test_url_with_auth_env_ok(self, tmp_path):
        config = {"mcpServers": {"api": {"command": "npx", "args": [], "url": "http://example.com/api", "env": {"API_KEY": "$MY_KEY"}}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        auth_findings = [f for f in result.servers if f.category == "no-auth"]
        assert auth_findings == []


# ---------------------------------------------------------------------------
# Scanner: env variable leaks
# ---------------------------------------------------------------------------

class TestEnvLeaks:
    def test_hardcoded_api_key_flagged(self, tmp_path):
        config = {"mcpServers": {"s": {"command": "npx", "args": [], "env": {"OPENAI_API_KEY": "sk-1234567890abcdef1234567890abcdef"}}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        env_findings = [f for f in result.servers if f.category == "env-leak"]
        assert len(env_findings) >= 1

    def test_env_ref_not_flagged(self, tmp_path):
        config = {"mcpServers": {"s": {"command": "npx", "args": [], "env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}"}}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        env_findings = [f for f in result.servers if f.category == "env-leak"]
        assert env_findings == []

    def test_password_env_flagged(self, tmp_path):
        config = {"mcpServers": {"db": {"command": "npx", "args": [], "env": {"DB_PASSWORD": "supersecret123"}}}}
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps(config))
        result = scan_mcp_config(path)
        env_findings = [f for f in result.servers if f.category == "env-leak"]
        assert len(env_findings) >= 1


# ---------------------------------------------------------------------------
# Scanner: malformed / edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_malformed_json(self, tmp_path):
        path = tmp_path / "mcp.json"
        path.write_text("{bad json")
        result = scan_mcp_config(path)
        assert result.parse_error
        assert result.overall_risk == "medium"

    def test_empty_servers(self, tmp_path):
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps({"mcpServers": {}}))
        result = scan_mcp_config(path)
        assert result.servers == []
        assert result.server_count == 0

    def test_no_servers_key(self, tmp_path):
        path = tmp_path / "mcp.json"
        path.write_text(json.dumps({"something": "else"}))
        result = scan_mcp_config(path)
        assert result.servers == []
        assert "0 server" in result.summary

    def test_nonexistent_file(self, tmp_path):
        path = tmp_path / "mcp.json"
        result = scan_mcp_config(path)
        assert result.parse_error


# ---------------------------------------------------------------------------
# Overall risk computation
# ---------------------------------------------------------------------------

class TestOverallRisk:
    def test_critical_from_critical_finding(self, risky_mcp_config):
        result = scan_mcp_config(risky_mcp_config)
        assert result.overall_risk == "critical"

    def test_low_for_safe_config(self, safe_mcp_config):
        result = scan_mcp_config(safe_mcp_config)
        assert result.overall_risk == "low"


# ---------------------------------------------------------------------------
# Integration: analyze_file routes MCP configs
# ---------------------------------------------------------------------------

class TestAnalyzerIntegration:
    def test_analyze_file_routes_mcp(self, safe_mcp_config):
        card = analyze_file(safe_mcp_config)
        assert card.entity_type == "mcp-config"
        assert card.format == "mcp-config"

    def test_risky_config_low_grade(self, risky_mcp_config):
        card = analyze_file(risky_mcp_config)
        assert card.entity_type == "mcp-config"
        assert card.grade in ("D", "F")
        assert card.overall_score < 0.6

    def test_safe_config_good_grade(self, safe_mcp_config):
        card = analyze_file(safe_mcp_config)
        assert card.grade in ("A", "B")
        assert card.overall_score >= 0.8

    def test_mcp_scorecard_has_dimensions(self, safe_mcp_config):
        card = analyze_file(safe_mcp_config)
        dim_names = [d.name for d in card.dimensions]
        assert "command_safety" in dim_names
        assert "filesystem_scope" in dim_names
        assert "secret_hygiene" in dim_names
        assert "network_trust" in dim_names

    def test_desktop_config_analyzed(self, desktop_config):
        card = analyze_file(desktop_config)
        assert card.entity_type == "mcp-config"
        # Has a hardcoded API key, so should have env-leak findings
        env_dim = next(d for d in card.dimensions if d.name == "secret_hygiene")
        assert env_dim.score < 1.0

    def test_mcp_summary_present(self, risky_mcp_config):
        card = analyze_file(risky_mcp_config)
        assert card.summary
        assert "MCP config" in card.summary
