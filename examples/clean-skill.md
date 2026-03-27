---
name: Code Review
description: Review code changes for correctness, style, and potential issues
trigger: When the user asks for a code review or submits changes for review
category: development
allowed-tools: Read, Grep, Glob
---

## Steps

1. Read the changed files using `git diff` or the provided file paths
2. Check for correctness — does the code do what it claims?
3. Verify style consistency with the existing codebase
4. Identify potential bugs, edge cases, or security issues
5. Suggest concrete improvements with specific code examples
6. Summarize findings with a clear pass/needs-changes verdict

## Inputs

- `scope` (optional): Specific files or directories to review
- `focus` (optional): Area to focus on — "security", "performance", "style"

## Examples

- Review all staged changes: `/review`
- Review specific file: `/review scope=src/auth.py`
- Security-focused review: `/review focus=security`

## Gotchas

- Don't nitpick formatting if the project uses an autoformatter — check for .prettierrc, .eslintrc, or pyproject.toml format config first
- Large diffs (>500 lines) should be reviewed in logical chunks, not all at once
- Flag but don't block on subjective style preferences — focus on correctness and maintainability
