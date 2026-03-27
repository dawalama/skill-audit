"""Tests for config file support."""

import textwrap
from pathlib import Path

import pytest

from skill_audit.config import load_config, AuditConfig, LLMConfig, format_config


@pytest.fixture
def config_toml(tmp_path):
    """Write a skill-audit.toml file and return its path."""
    def _write(content: str) -> Path:
        p = tmp_path / "skill-audit.toml"
        p.write_text(textwrap.dedent(content))
        return p
    return _write


class TestLoadConfig:
    def test_defaults_when_no_file(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.toml")
        assert cfg.min_grade == ""
        assert cfg.output == "table"
        assert cfg.llm.enabled is False
        assert cfg.llm.provider == ""
        assert cfg.llm.model == ""
        assert "node_modules" in cfg.ignore_paths
        assert cfg.custom_patterns == []

    def test_load_min_grade(self, config_toml):
        path = config_toml('min-grade = "B"\n')
        cfg = load_config(path)
        assert cfg.min_grade == "B"

    def test_load_output_format(self, config_toml):
        path = config_toml('output = "json"\n')
        cfg = load_config(path)
        assert cfg.output == "json"

    def test_load_llm_section(self, config_toml):
        path = config_toml("""\
            [llm]
            enabled = true
            provider = "claude"
            model = "claude-sonnet-4-5"
        """)
        cfg = load_config(path)
        assert cfg.llm.enabled is True
        assert cfg.llm.provider == "claude"
        assert cfg.llm.model == "claude-sonnet-4-5"

    def test_load_ignore_paths(self, config_toml):
        path = config_toml("""\
            [ignore]
            paths = ["dist", "build"]
        """)
        cfg = load_config(path)
        assert cfg.ignore_paths == ["dist", "build"]

    def test_load_custom_patterns(self, config_toml):
        path = config_toml("""\
            [patterns]
            custom = [
                ["\\\\binternal-api\\\\.com\\\\b", "Internal API", "SUSPICIOUS_URL"],
            ]
        """)
        cfg = load_config(path)
        assert len(cfg.custom_patterns) == 1
        pat, desc, cat = cfg.custom_patterns[0]
        assert desc == "Internal API"
        assert cat == "SUSPICIOUS_URL"

    def test_invalid_toml_returns_defaults(self, tmp_path):
        p = tmp_path / "skill-audit.toml"
        p.write_text("this is not valid toml [[[")
        cfg = load_config(p)
        assert cfg.output == "table"

    def test_partial_config(self, config_toml):
        path = config_toml('min-grade = "C"\n')
        cfg = load_config(path)
        assert cfg.min_grade == "C"
        # Other fields still have defaults
        assert cfg.output == "table"
        assert cfg.llm.enabled is False

    def test_custom_patterns_skips_malformed(self, config_toml):
        path = config_toml("""\
            [patterns]
            custom = [
                ["only-two-elements", "desc"],
                ["ok-pattern", "desc", "CATEGORY"],
            ]
        """)
        cfg = load_config(path)
        # Should only include the valid 3-element entry
        assert len(cfg.custom_patterns) == 1
        assert cfg.custom_patterns[0][2] == "CATEGORY"


class TestMerge:
    def test_cwd_overrides_home(self, tmp_path, monkeypatch):
        # Create "home" config
        home_dir = tmp_path / "home" / ".config" / "skill-audit"
        home_dir.mkdir(parents=True)
        home_config = home_dir / "config.toml"
        home_config.write_text('min-grade = "C"\noutput = "json"\n')

        # Create "cwd" config
        cwd_dir = tmp_path / "project"
        cwd_dir.mkdir()
        cwd_config = cwd_dir / "skill-audit.toml"
        cwd_config.write_text('min-grade = "A"\n')

        # Monkeypatch the module-level paths
        import skill_audit.config as config_mod
        monkeypatch.setattr(config_mod, "_HOME_FILE", home_config)
        monkeypatch.chdir(cwd_dir)

        cfg = load_config()
        # CWD overrides home for min-grade
        assert cfg.min_grade == "A"
        # Home value used for output since CWD didn't set it
        assert cfg.output == "json"


class TestFormatConfig:
    def test_format_defaults(self):
        cfg = AuditConfig()
        text = format_config(cfg)
        assert "min-grade = (not set)" in text
        assert "output = 'table'" in text
        assert "enabled = false" in text

    def test_format_with_values(self):
        cfg = AuditConfig(
            min_grade="B",
            output="json",
            llm=LLMConfig(enabled=True, provider="claude", model="sonnet"),
            custom_patterns=[("\\bfoo\\b", "Foo pattern", "CUSTOM")],
        )
        text = format_config(cfg)
        assert "'B'" in text
        assert "'json'" in text
        assert "enabled = true" in text
        assert "'claude'" in text
        assert "[patterns]" in text
        assert "Foo pattern" in text
