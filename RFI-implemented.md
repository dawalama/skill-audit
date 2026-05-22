# RFI Implementation Response

This response covers the first implementation pass from `RFI.md`.

## Implemented

### Security-only audit mode

Installers need to answer a narrow question: "Is this skill safe enough to install?"
That should not be mixed with whether the skill is complete, clear, or useful.

Added:

- `analyze_file(..., security_only=True)`
- `analyze_artifact(..., security_only=True)`
- `analyze_directory(..., security_only=True)`
- CLI flag: `--security-only`

Security-only mode runs only the `trust` dimension. It skips quality dimensions
such as completeness, clarity, actionability, safety, and testability.

Example:

```bash
ai-skill-audit audit path/to/SKILL.md --security-only
ai-skill-audit audit path/to/SKILL.md --security-only --output json
```

### Stable audit payload

Added `ScoreCard.to_audit_payload()` for agents and service wrappers.

The payload includes:

- `summary`: entity, score, risk, mode, file path, active finding count, severity counts
- `verdict`: context-aware recommendation
- `dimensions`: compact dimension summary
- `findings`: structured findings

When the CLI is run with `--security-only --output json`, it emits this stable
payload shape instead of the full quality scorecard.

## Intentionally Deferred

### `to_service_payload()`

Deferred as named. The base scanner should not know about one service wrapper.
The implemented method is `to_audit_payload()`, which is service-friendly without
coupling the library to `ai-skill-audit-service`.

### Text input API

Still worth doing next. `analyze_text()` and `parse_text()` remain the highest
value API improvement after security-only mode.

### Differential scanning

Deferred to the service layer. Caching and previous-run comparison require
state, and the base scanner should stay stateless for now.

### Findings threshold mode

Deferred in core scoring. Filtering findings for display or gating is useful,
but changing dispositions and score deductions based on a threshold could hide
raw risk. The safer first step is output-level filtering while preserving raw
findings.

### Package and registry awareness

Deferred. This is valuable, but it needs careful package-ecosystem rules and
false-positive tests before becoming part of the trust scanner.

### `.env` discovery

Deferred. Scanning environment files can expose secrets in audit output. If
added, it should include evidence masking and likely be opt-in or scoped to a
specific repo-security mode.

## Verification

```bash
uv run ai-skill-audit audit examples/clean-skill.md --security-only --output json
uv run pytest
```

Result:

```text
245 passed
```
