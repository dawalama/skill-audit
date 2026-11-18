"""Scanner for AI agent lifecycle hook configurations.

Supports Claude Code / agent hook files such as:
- hooks.json / .claude/hooks.json
- .claude/settings.json / .claude/settings.local.json (when a "hooks" key is present)

Extracts shell commands from PreToolUse, PostToolUse, SessionStart,
UserPromptSubmit, Stop, and related hook events, and runs the trust scanner
against them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import Finding, ScoreCard
from .parser import ParsedArtifact


@dataclass(frozen=True)
class HookCommand:
    """A single command extracted from a hook configuration."""

    event: str
    matcher: str
    command: str


def is_hook_config_file(path: Path) -> bool:
    """Return True if *path* is a hook config or a settings file containing hooks."""
    if path.name == "hooks.json":
        return True
    if path.name in ("settings.json", "settings.local.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return False
        return isinstance(data, dict) and isinstance(data.get("hooks"), dict)
    return False


def extract_hook_commands(data: object) -> list[HookCommand]:
    """Recursively extract hook command entries from a parsed JSON object."""
    if not isinstance(data, dict):
        return []

    hooks_root = data.get("hooks", data)
    if not isinstance(hooks_root, dict):
        return []

    commands: list[HookCommand] = []
    for event_name, entries in hooks_root.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            matcher = str(entry.get("matcher", "*"))
            # Nested Claude Code format: {"matcher": "...", "hooks": [{"type": "command", "command": "..."}]}
            nested = entry.get("hooks")
            if isinstance(nested, list):
                for item in nested:
                    if isinstance(item, dict) and isinstance(item.get("command"), str):
                        commands.append(HookCommand(event=event_name, matcher=matcher, command=item["command"]))
            # Flat format: {"matcher": "...", "command": "..."}
            elif isinstance(entry.get("command"), str):
                commands.append(HookCommand(event=event_name, matcher=matcher, command=entry["command"]))

    return commands


def analyze_hook_config(path: Path) -> ScoreCard:
    """Analyze an agent hook configuration file and return a ScoreCard."""
    from .analyzer import _generate_summary
    from .rubrics.skill_rubrics import _score_trust
    from .verdict import interpret_card

    try:
        raw_text = path.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        from .models import ScoreDimension

        dim = ScoreDimension(
            name="trust",
            score=0.5,
            weight=1.0,
            details=[f"Could not parse hook config: {exc}"],
            findings=[
                Finding(
                    id="HOOK_PARSE_ERROR",
                    category="CAPABILITY",
                    severity="medium",
                    message=f"Could not parse hook config: {exc}",
                    source="hooks",
                )
            ],
        )
        card = ScoreCard(
            entity_type="agent-hooks",
            entity_name=path.name,
            format="agent-hooks",
            dimensions=[dim],
            file_path=path,
        )
        card.compute_overall()
        card.summary = _generate_summary(card)
        card.verdict = interpret_card(card)
        return card

    commands = extract_hook_commands(data)
    if not commands:
        from .models import ScoreDimension

        dim = ScoreDimension(
            name="trust",
            score=1.0,
            weight=1.0,
            details=["No hook commands configured"],
        )
        card = ScoreCard(
            entity_type="agent-hooks",
            entity_name=path.name,
            format="agent-hooks",
            dimensions=[dim],
            file_path=path,
        )
        card.compute_overall()
        card.summary = _generate_summary(card)
        card.verdict = interpret_card(card)
        return card

    # Render extracted commands as shell blocks so the trust scanner inspects them
    # using its full multi-layer ruleset without false positives from JSON syntax.
    blocks = [
        f"## {cmd.event} (matcher: {cmd.matcher})\n```bash\n{cmd.command}\n```"
        for cmd in commands
    ]
    rendered_body = "\n\n".join(blocks)
    artifact = ParsedArtifact(
        name=path.name,
        description=f"Agent lifecycle hooks ({len(commands)} command(s))",
        entity_type="agent-hooks",
        format="agent-hooks",
        raw_body=rendered_body,
        file_path=path,
    )
    trust = _score_trust(artifact, weight=1.0, trust_inline=False)
    trust.details.insert(0, f"Scanned {len(commands)} hook command(s)")

    card = ScoreCard(
        entity_type="agent-hooks",
        entity_name=path.name,
        format="agent-hooks",
        description=artifact.description,
        dimensions=[trust],
        file_path=path,
    )
    card.compute_overall()
    card.summary = _generate_summary(card)
    card.verdict = interpret_card(card)
    return card
