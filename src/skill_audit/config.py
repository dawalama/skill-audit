"""Configuration file support for skill-audit.

Loads settings from skill-audit.toml in the current directory,
then ~/.config/skill-audit/config.toml as fallback.
"""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LLMConfig:
    enabled: bool = False
    provider: str = ""
    model: str = ""


@dataclass
class WeightsConfig:
    """Configurable rubric weights for skill and role scoring."""
    # Skill weights (must sum to 1.0)
    completeness: float = 0.20
    clarity: float = 0.15
    actionability: float = 0.20
    safety: float = 0.15
    testability: float = 0.10
    trust: float = 0.20
    # Role weights (must sum to 1.0)
    persona_clarity: float = 0.30
    principles_quality: float = 0.30
    anti_patterns: float = 0.20
    scope: float = 0.20
    # Entropy threshold
    entropy_threshold: float = 4.8


@dataclass
class AuditConfig:
    min_grade: str = ""
    output: str = "table"
    llm: LLMConfig = field(default_factory=LLMConfig)
    ignore_paths: list[str] = field(
        default_factory=lambda: ["node_modules", ".git", "vendor", "__pycache__"]
    )
    custom_patterns: list[tuple[str, str, str]] = field(default_factory=list)
    weights: WeightsConfig = field(default_factory=WeightsConfig)


_CWD_FILE = "skill-audit.toml"
_HOME_FILE = Path.home() / ".config" / "skill-audit" / "config.toml"


def _parse_toml(path: Path) -> dict:
    """Read and parse a TOML file, returning empty dict on any failure."""
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _merge(base: dict, override: dict) -> dict:
    """Shallow-merge override into base, recursing one level for sub-tables."""
    result = dict(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(result.get(key), dict):
            result[key] = {**result[key], **val}
        else:
            result[key] = val
    return result


def _dict_to_config(data: dict) -> AuditConfig:
    """Convert a raw TOML dict into an AuditConfig."""
    llm_data = data.get("llm", {})
    llm = LLMConfig(
        enabled=llm_data.get("enabled", False),
        provider=llm_data.get("provider", ""),
        model=llm_data.get("model", ""),
    )

    ignore_data = data.get("ignore", {})
    ignore_paths = ignore_data.get(
        "paths", ["node_modules", ".git", "vendor", "__pycache__"]
    )

    patterns_data = data.get("patterns", {})
    custom_raw = patterns_data.get("custom", [])
    custom_patterns = []
    for entry in custom_raw:
        if isinstance(entry, (list, tuple)) and len(entry) == 3:
            custom_patterns.append((str(entry[0]), str(entry[1]), str(entry[2])))

    # Weights
    weights_data = data.get("weights", {})
    defaults = WeightsConfig()
    weights = WeightsConfig(
        completeness=float(weights_data.get("completeness", defaults.completeness)),
        clarity=float(weights_data.get("clarity", defaults.clarity)),
        actionability=float(weights_data.get("actionability", defaults.actionability)),
        safety=float(weights_data.get("safety", defaults.safety)),
        testability=float(weights_data.get("testability", defaults.testability)),
        trust=float(weights_data.get("trust", defaults.trust)),
        persona_clarity=float(weights_data.get("persona_clarity", defaults.persona_clarity)),
        principles_quality=float(weights_data.get("principles_quality", defaults.principles_quality)),
        anti_patterns=float(weights_data.get("anti_patterns", defaults.anti_patterns)),
        scope=float(weights_data.get("scope", defaults.scope)),
        entropy_threshold=float(weights_data.get("entropy_threshold", defaults.entropy_threshold)),
    )

    return AuditConfig(
        min_grade=data.get("min-grade", ""),
        output=data.get("output", "table"),
        llm=llm,
        ignore_paths=ignore_paths,
        custom_patterns=custom_patterns,
        weights=weights,
    )


def load_config(path: Path | None = None) -> AuditConfig:
    """Load config from an explicit path, CWD, or home directory.

    Precedence: explicit path > CWD skill-audit.toml > ~/.config/skill-audit/config.toml.
    CWD values override home values. Returns defaults if no config file exists.
    """
    if path is not None:
        data = _parse_toml(path)
        return _dict_to_config(data)

    home_data = _parse_toml(_HOME_FILE)
    cwd_data = _parse_toml(Path.cwd() / _CWD_FILE)

    merged = _merge(home_data, cwd_data)
    return _dict_to_config(merged)


def format_config(cfg: AuditConfig) -> str:
    """Format an AuditConfig as a human-readable string."""
    lines = [
        f"min-grade = {cfg.min_grade!r}" if cfg.min_grade else "min-grade = (not set)",
        f"output = {cfg.output!r}",
        "",
        "[llm]",
        f"enabled = {str(cfg.llm.enabled).lower()}",
        f"provider = {cfg.llm.provider!r}" if cfg.llm.provider else "provider = (not set)",
        f"model = {cfg.llm.model!r}" if cfg.llm.model else "model = (not set)",
        "",
        "[ignore]",
        f"paths = {cfg.ignore_paths}",
    ]
    if cfg.custom_patterns:
        lines.append("")
        lines.append("[patterns]")
        for pat, desc, cat in cfg.custom_patterns:
            lines.append(f"  [{pat!r}, {desc!r}, {cat!r}]")

    # Only show weights if non-default
    defaults = WeightsConfig()
    w = cfg.weights
    non_default = []
    for field_name in ("completeness", "clarity", "actionability", "safety",
                       "testability", "trust", "persona_clarity", "principles_quality",
                       "anti_patterns", "scope", "entropy_threshold"):
        val = getattr(w, field_name)
        default_val = getattr(defaults, field_name)
        if val != default_val:
            non_default.append(f"{field_name} = {val}")
    if non_default:
        lines.append("")
        lines.append("[weights]")
        lines.extend(non_default)

    return "\n".join(lines)
