"""Whitelist/ignore mechanism for suppressing specific finding categories.

Supports two mechanisms:
1. `.skill-audit-ignore` config file (per-directory or in home dir)
2. Inline HTML comments in markdown files
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# Valid categories that can be ignored
VALID_CATEGORIES = frozenset({
    "DESTRUCTIVE", "EXFILTRATION", "OBFUSCATION", "PRIVILEGE",
    "INJECTION", "SECRET", "SUSPICIOUS_URL", "ENTROPY",
})

# Inline comment patterns
_INLINE_IGNORE_RE = re.compile(
    r"<!--\s*skill-audit:\s*ignore\s+([\w\s,]+?)\s*-->",
    re.IGNORECASE,
)
_INLINE_IGNORE_NEXT_LINE_RE = re.compile(
    r"<!--\s*skill-audit:\s*ignore-next-line\s*-->",
    re.IGNORECASE,
)


@dataclass
class IgnoreConfig:
    """Holds ignore rules: global categories and per-file categories."""

    global_ignores: set[str] = field(default_factory=set)
    per_file_ignores: dict[str, set[str]] = field(default_factory=dict)

    def is_ignored(self, category: str, file_path: Path | None = None) -> bool:
        """Check if a category should be ignored for a given file."""
        cat = category.upper()
        if cat in self.global_ignores:
            return True
        if file_path is not None:
            file_name = file_path.name
            per_file = self.per_file_ignores.get(file_name, set())
            if cat in per_file:
                return True
        return False

    def ignored_categories(self, file_path: Path | None = None) -> set[str]:
        """Return the full set of ignored categories for a given file."""
        result = set(self.global_ignores)
        if file_path is not None:
            file_name = file_path.name
            result |= self.per_file_ignores.get(file_name, set())
        return result

    @staticmethod
    def parse_inline_ignores(content: str) -> set[str]:
        """Extract ignored categories from inline HTML comments in markdown.

        Supports:
            <!-- skill-audit: ignore EXFILTRATION -->
            <!-- skill-audit: ignore DESTRUCTIVE, PRIVILEGE -->
            <!-- skill-audit: ignore-next-line -->  (ignores all categories for next line)

        Returns a set of uppercase category names. If ignore-next-line is found,
        all valid categories are returned since it's a blanket suppression.
        """
        ignored: set[str] = set()

        # Match explicit category ignores
        for match in _INLINE_IGNORE_RE.finditer(content):
            cats_str = match.group(1)
            for cat in cats_str.split(","):
                cat = cat.strip().upper()
                if cat in VALID_CATEGORIES:
                    ignored.add(cat)

        # Match ignore-next-line (blanket ignore)
        if _INLINE_IGNORE_NEXT_LINE_RE.search(content):
            ignored |= VALID_CATEGORIES

        return ignored


def _parse_ignore_file(text: str) -> IgnoreConfig:
    """Parse the contents of a .skill-audit-ignore file.

    Format:
        # Comments start with #
        DESTRUCTIVE          # Global ignore
        PRIVILEGE            # Global ignore

        deploy.md: DESTRUCTIVE, PRIVILEGE   # Per-file ignore
        cleanup.md: DESTRUCTIVE             # Per-file ignore
    """
    config = IgnoreConfig()

    for line in text.splitlines():
        line = line.strip()
        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            # Per-file rule: "filename: CAT1, CAT2"
            file_part, cats_part = line.split(":", 1)
            file_name = file_part.strip()
            cats = set()
            for cat in cats_part.split(","):
                cat = cat.strip().upper()
                if cat in VALID_CATEGORIES:
                    cats.add(cat)
            if file_name and cats:
                existing = config.per_file_ignores.get(file_name, set())
                config.per_file_ignores[file_name] = existing | cats
        else:
            # Global rule: just a category name
            cat = line.upper()
            if cat in VALID_CATEGORIES:
                config.global_ignores.add(cat)

    return config


def load_ignore_config(scan_path: Path) -> IgnoreConfig:
    """Load .skill-audit-ignore from the scan directory, then home directory.

    Rules from both files are merged (union). The scan directory file takes
    precedence in the sense that its rules are loaded first, but since we
    merge, both apply.
    """
    config = IgnoreConfig()

    # Determine the directory to look in
    if scan_path.is_file():
        scan_dir = scan_path.parent
    else:
        scan_dir = scan_path

    # Load from scan directory first, then home directory
    locations = [
        scan_dir / ".skill-audit-ignore",
        Path.home() / ".skill-audit-ignore",
    ]

    for ignore_path in locations:
        if ignore_path.is_file():
            try:
                text = ignore_path.read_text(encoding="utf-8")
                parsed = _parse_ignore_file(text)
                config.global_ignores |= parsed.global_ignores
                for fname, cats in parsed.per_file_ignores.items():
                    existing = config.per_file_ignores.get(fname, set())
                    config.per_file_ignores[fname] = existing | cats
            except OSError:
                pass  # Silently skip unreadable files

    return config
