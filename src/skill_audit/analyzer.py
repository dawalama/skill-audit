"""Scoring engine: ties parser + rubrics together to produce ScoreCards."""

from __future__ import annotations

import os
from pathlib import Path

from .config import WeightsConfig
from .ignore import IgnoreConfig
from .models import ScoreCard, ScoreDimension
from .parser import ParsedArtifact, parse_file, parse_text, detect_format
from .rubrics.skill_rubrics import score_skill
from .rubrics.role_rubrics import score_role
from .verdict import interpret_card


def analyze_file(
    path: Path,
    force_format: str | None = None,
    ignore_config: IgnoreConfig | None = None,
    custom_patterns: list[tuple[str, str, str]] | None = None,
    weights: WeightsConfig | None = None,
    trust_inline: bool = True,
    security_only: bool = False,
) -> ScoreCard:
    """Analyze a single skill or role file and return a ScoreCard."""
    if path.is_file() and _is_script_file(path):
        return analyze_script_file(path, ignore_config=ignore_config, custom_patterns=custom_patterns, weights=weights, trust_inline=trust_inline)
    fmt = force_format or detect_format(path)
    if fmt == "mcp-config":
        return analyze_mcp_config(path)
    artifact = parse_file(path, force_format)
    return analyze_artifact(artifact, ignore_config=ignore_config, custom_patterns=custom_patterns, weights=weights, trust_inline=trust_inline, security_only=security_only)


def analyze_text(
    content: str,
    force_format: str | None = None,
    name: str = "inline",
    filename: str = "inline.md",
    ignore_config: IgnoreConfig | None = None,
    custom_patterns: list[tuple[str, str, str]] | None = None,
    weights: WeightsConfig | None = None,
    trust_inline: bool = True,
    security_only: bool = False,
) -> ScoreCard:
    """Analyze raw skill or role text without writing it to disk."""
    if _is_script_file(Path(filename)):
        artifact = ParsedArtifact(
            name=name if name != "inline" else filename,
            entity_type="script",
            format="script",
            raw_body=content,
            file_path=Path(filename),
        )
    else:
        artifact = parse_text(
            content,
            force_format=force_format,
            name=name,
            filename=filename,
        )
    return analyze_artifact(
        artifact,
        ignore_config=ignore_config,
        custom_patterns=custom_patterns,
        weights=weights,
        trust_inline=trust_inline,
        security_only=security_only,
    )


def analyze_artifact(
    artifact: ParsedArtifact,
    ignore_config: IgnoreConfig | None = None,
    custom_patterns: list[tuple[str, str, str]] | None = None,
    weights: WeightsConfig | None = None,
    trust_inline: bool = True,
    security_only: bool = False,
) -> ScoreCard:
    """Score a parsed artifact and return a ScoreCard.

    When trust_inline=False, inline suppression comments in the file are
    ignored entirely. This is used for remote/untrusted targets where the
    file author should not be able to influence their own audit score.
    """
    # Collect ignored categories from config file (operator-controlled)
    ignore_categories: set[str] = set()
    if ignore_config is not None:
        file_path = artifact.file_path if hasattr(artifact, "file_path") else None
        ignore_categories |= ignore_config.ignored_categories(file_path)
    # Parse inline ignores from raw content — only if the file is trusted
    if trust_inline:
        raw_content = artifact.raw_body or ""
        inline_ignored = IgnoreConfig.parse_inline_ignores(raw_content)
        ignore_categories |= inline_ignored

    w = weights or WeightsConfig()

    if security_only:
        from .rubrics.skill_rubrics import _score_trust

        dimensions = [
            _score_trust(
                artifact,
                ignore_categories=ignore_categories,
                custom_patterns=custom_patterns,
                weight=1.0,
                entropy_threshold=w.entropy_threshold,
                trust_inline=trust_inline,
            )
        ]
    elif artifact.entity_type == "role":
        dimensions = score_role(artifact, weights=w)
    else:
        dimensions = score_skill(artifact, ignore_categories=ignore_categories, custom_patterns=custom_patterns, weights=w, trust_inline=trust_inline)

    card = ScoreCard(
        entity_type=artifact.entity_type,
        entity_name=artifact.name,
        format=artifact.format,
        dimensions=dimensions,
        file_path=artifact.file_path,
    )

    card.compute_overall()
    card.summary = _generate_summary(card)
    card.verdict = interpret_card(card)
    return card


_DOC_FILES = {
    # Standard repo docs
    "readme.md", "changelog.md", "license.md", "licence.md",
    # Contribution / governance docs
    "contributing.md", "contributors.md", "code_of_conduct.md",
    "security.md", "governance.md",
    # Project management docs
    "installation.md", "setup.md", "getting-started.md",
    "architecture.md", "design.md", "roadmap.md",
    # Claude/AI config files (not skills)
    "claude.md", "gemini.md", "conventions.md",
    # Audit / pipeline docs
    "audit_report.md", "skill_pipeline.md", "store.md",
    # Project structure / meta docs
    "agents.md", "ethos.md", "todos.md", "browser.md",
    "todos.md", "vision.md", "philosophy.md",
}

_MCP_FILES = {"mcp.json", "claude_desktop_config.json"}

_SCRIPT_EXTENSIONS = {
    ".bash", ".cjs", ".fish", ".js", ".jsx", ".mjs", ".ps1", ".py",
    ".rb", ".sh", ".ts", ".tsx", ".zsh",
}

_SCRIPT_NAMES = {
    "bash", "sh", "zsh", "fish", "python", "python3", "node", "ruby",
}

_SKIP_DIRS = {
    ".git", ".hg", ".svn",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    ".venv", "venv", "env",
    "__pycache__", "node_modules",
    "build", "dist", "site-packages",
}

_AUDIT_CONTAINER_DIRS = {
    "agents", "commands", "contexts", "hooks", "roles", "rules", "skills",
}


def analyze_directory(
    dir_path: Path,
    force_format: str | None = None,
    ignore_config: IgnoreConfig | None = None,
    custom_patterns: list[tuple[str, str, str]] | None = None,
    weights: WeightsConfig | None = None,
    include_docs: bool = False,
    trust_inline: bool = True,
    security_only: bool = False,
) -> tuple[list[ScoreCard], int]:
    """Analyze all skill/role files in a directory.

    Recursively scans markdown skills/roles, MCP configs, and scripts attached
    to discovered skill surfaces. Documentation files such as README.md are
    skipped by default without stopping recursion into deeper skill directories.

    Returns (cards, skipped_count) where skipped_count is the number of
    documentation files that were skipped.
    """
    results: list[ScoreCard] = []
    candidates, skipped = _collect_audit_candidates(dir_path, include_docs=include_docs)

    for candidate in candidates:
        card = analyze_file(
            candidate,
            force_format,
            ignore_config=ignore_config,
            custom_patterns=custom_patterns,
            weights=weights,
            trust_inline=trust_inline,
            security_only=security_only,
        )
        results.append(card)

    return results, skipped


def _collect_audit_candidates(
    dir_path: Path,
    include_docs: bool = False,
) -> tuple[list[Path], int]:
    """Return auditable files under a directory in stable order."""
    markdown_candidates: list[Path] = []
    mcp_candidates: list[Path] = []
    skipped = 0

    if not dir_path.exists():
        return [], skipped

    for root, dirs, files in os.walk(dir_path):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.startswith("."))
        root_path = Path(root)
        for filename in sorted(files):
            path = root_path / filename
            if path.name in _MCP_FILES:
                mcp_candidates.append(path)
            elif path.suffix.lower() == ".md":
                if not include_docs and not _is_audit_markdown(path, dir_path):
                    skipped += 1
                    continue
                markdown_candidates.append(path)

    script_candidates = _collect_attached_script_candidates(dir_path, markdown_candidates)
    candidates = sorted({*mcp_candidates, *markdown_candidates, *script_candidates})
    return candidates, skipped


def _is_script_file(path: Path) -> bool:
    """Return True for source/script files worth trust scanning directly."""
    return path.suffix.lower() in _SCRIPT_EXTENSIONS or path.name in _SCRIPT_NAMES


def _is_audit_markdown(path: Path, base_dir: Path) -> bool:
    """Return True for markdown files that look like installable AI surfaces."""
    if path.name in {"SKILL.md", "main.md"}:
        return True
    if path.name.lower() in _DOC_FILES:
        return False

    rel_parts = [part.lower() for part in path.relative_to(base_dir).parts]
    if any(part in _AUDIT_CONTAINER_DIRS for part in rel_parts[:-1]):
        return True

    # Allow root-level files only when they declare a known skill/role format.
    if path.parent == base_dir:
        return detect_format(path) != "unknown"

    return False


def _collect_attached_script_candidates(base_dir: Path, markdown_candidates: list[Path]) -> list[Path]:
    """Collect scripts attached to skill files without scanning whole repos."""
    scripts: list[Path] = []
    seen_roots: set[Path] = set()

    for markdown in markdown_candidates:
        for root in _script_roots_for_markdown(base_dir, markdown):
            if root in seen_roots or not root.is_dir():
                continue
            seen_roots.add(root)
            scripts.extend(_script_files_under(root))

    return scripts


def _script_roots_for_markdown(base_dir: Path, markdown: Path) -> list[Path]:
    """Return script roots likely owned by a markdown skill surface."""
    if markdown.name in {"SKILL.md", "main.md"}:
        return [markdown.parent]

    roots = [markdown.parent / "scripts"]
    same_stem_dir = markdown.parent / markdown.stem
    if same_stem_dir.is_dir():
        roots.append(same_stem_dir)

    # For a root-level single-file skill, scan only conventional companion
    # scripts instead of every source/test script in the repository.
    if markdown.parent == base_dir:
        return roots

    return roots


def _script_files_under(root: Path) -> list[Path]:
    """Return script files under a bounded root, pruning dependencies."""
    results: list[Path] = []
    for walk_root, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not d.startswith("."))
        root_path = Path(walk_root)
        for filename in sorted(files):
            path = root_path / filename
            if _is_script_file(path):
                results.append(path)
    return results


def analyze_script_file(
    path: Path,
    ignore_config: IgnoreConfig | None = None,
    custom_patterns: list[tuple[str, str, str]] | None = None,
    weights: WeightsConfig | None = None,
    trust_inline: bool = True,
) -> ScoreCard:
    """Analyze an executable script file with the trust scanner."""
    from .rubrics.skill_rubrics import _score_trust

    try:
        content = path.read_text()
    except (OSError, UnicodeDecodeError):
        content = ""

    ignore_categories: set[str] = set()
    if ignore_config is not None:
        ignore_categories |= ignore_config.ignored_categories(path)
    if trust_inline and content:
        ignore_categories |= IgnoreConfig.parse_inline_ignores(content)

    w = weights or WeightsConfig()
    artifact = ParsedArtifact(
        name=path.name,
        entity_type="script",
        format="script",
        raw_body=content,
        file_path=path,
    )
    trust = _score_trust(
        artifact,
        ignore_categories=ignore_categories,
        custom_patterns=custom_patterns,
        weight=1.0,
        entropy_threshold=w.entropy_threshold,
        trust_inline=trust_inline,
    )
    card = ScoreCard(
        entity_type="script",
        entity_name=path.name,
        format="script",
        dimensions=[trust],
        file_path=path,
    )
    card.compute_overall()
    card.summary = _generate_summary(card)
    card.verdict = interpret_card(card)
    return card


def analyze_mcp_config(path: Path) -> ScoreCard:
    """Analyze an MCP config file and return a ScoreCard."""
    from .mcp_scanner import scan_mcp_config

    result = scan_mcp_config(path)

    dimensions: list[ScoreDimension] = []

    # --- Command safety dimension ---
    cmd_findings = [f for f in result.servers if f.category == "risky-command"]
    cmd_score = 1.0
    cmd_details: list[str] = []
    cmd_suggestions: list[str] = []
    if cmd_findings:
        for f in cmd_findings:
            deduction = 0.5 if f.severity == "critical" else 0.3
            cmd_score = max(0.0, cmd_score - deduction)
            cmd_suggestions.append(f"[{f.server_name}] {f.message}")
    else:
        cmd_details.append("No risky command patterns detected")
    dimensions.append(ScoreDimension(
        name="command_safety",
        score=cmd_score,
        weight=0.30,
        details=cmd_details,
        suggestions=cmd_suggestions,
    ))

    # --- Filesystem scope dimension ---
    fs_findings = [f for f in result.servers if f.category == "broad-filesystem"]
    fs_score = 1.0
    fs_details: list[str] = []
    fs_suggestions: list[str] = []
    if fs_findings:
        for f in fs_findings:
            fs_score = max(0.0, fs_score - 0.3)
            fs_suggestions.append(f"[{f.server_name}] {f.message}")
    else:
        fs_details.append("No overly broad filesystem access detected")
    dimensions.append(ScoreDimension(
        name="filesystem_scope",
        score=fs_score,
        weight=0.25,
        details=fs_details,
        suggestions=fs_suggestions,
    ))

    # --- Secrets / env leaks dimension ---
    env_findings = [f for f in result.servers if f.category == "env-leak"]
    env_score = 1.0
    env_details: list[str] = []
    env_suggestions: list[str] = []
    if env_findings:
        for f in env_findings:
            deduction = 0.4 if f.severity == "high" else 0.2
            env_score = max(0.0, env_score - deduction)
            env_suggestions.append(f"[{f.server_name}] {f.message}")
    else:
        env_details.append("No hardcoded secrets in environment variables")
    dimensions.append(ScoreDimension(
        name="secret_hygiene",
        score=env_score,
        weight=0.20,
        details=env_details,
        suggestions=env_suggestions,
    ))

    # --- Network / auth / URL dimension ---
    net_categories = {"network-exposure", "suspicious-url", "no-auth", "overly-permissive"}
    net_findings = [f for f in result.servers if f.category in net_categories]
    net_score = 1.0
    net_details: list[str] = []
    net_suggestions: list[str] = []
    if net_findings:
        for f in net_findings:
            deduction = {"critical": 0.5, "high": 0.3, "medium": 0.15}.get(f.severity, 0.1)
            net_score = max(0.0, net_score - deduction)
            net_suggestions.append(f"[{f.server_name}] {f.message}")
    else:
        net_details.append("No network exposure or suspicious URL issues")
    dimensions.append(ScoreDimension(
        name="network_trust",
        score=net_score,
        weight=0.25,
        details=net_details,
        suggestions=net_suggestions,
    ))

    card = ScoreCard(
        entity_type="mcp-config",
        entity_name=path.name,
        format="mcp-config",
        dimensions=dimensions,
        file_path=path,
    )
    card.compute_overall()
    card.summary = _generate_mcp_summary(card, result)
    card.verdict = interpret_card(card)
    return card


def _generate_mcp_summary(card: ScoreCard, result) -> str:
    """Generate a human-readable summary for an MCP config scorecard."""
    risk_label = result.overall_risk.upper()
    total_findings = len(result.servers)

    if card.grade in ("A", "B"):
        prefix = "Clean" if card.grade == "A" else "Mostly safe"
    elif card.grade == "C":
        prefix = "Some concerns"
    else:
        prefix = "Risky"

    parts = [f"{prefix} MCP config"]
    parts.append(f"({result.server_count} server(s), {total_findings} finding(s), risk: {risk_label})")

    weakest = min(card.dimensions, key=lambda d: d.score) if card.dimensions else None
    if weakest and weakest.score < 0.5:
        parts.append(f"(weakest: {weakest.name})")

    return " ".join(parts)


def _generate_summary(card: ScoreCard) -> str:
    """Generate a human-readable summary of the scorecard."""
    total_suggestions = sum(len(d.suggestions) for d in card.dimensions)

    if card.grade == "A":
        prefix = "Excellent"
    elif card.grade == "B":
        prefix = "Good"
    elif card.grade == "C":
        prefix = "Acceptable"
    elif card.grade == "D":
        prefix = "Needs work"
    else:
        prefix = "Poor"

    parts = [f"{prefix} {card.entity_type}"]
    if total_suggestions > 0:
        parts.append(f"with {total_suggestions} suggestions for improvement")

    # Highlight weakest dimension
    if card.dimensions:
        weakest = min(card.dimensions, key=lambda d: d.score)
        if weakest.score < 0.5:
            parts.append(f"(weakest: {weakest.name})")

    return " ".join(parts)
