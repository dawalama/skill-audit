# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
semantic versioning.

## [Unreleased]

## [0.11.0] - 2026-11-20

### Added
- **Trust verdict CI gate (`--fail-on`).** Added `--fail-on warn|human_review|block` CLI flag and `fail-on` config option to exit `1` when any audited file's trust verdict meets or exceeds the threshold (exit `2` on invalid values).
- **SARIF v2.1.0 output (`--output sarif`).** Added SARIF formatter (`format_sarif`) for GitHub Code Scanning and CI integrations, including optional LLM findings.
- **Agent hook config scanning (`agent-hooks`).** Added `hook_scanner.py` to detect and scan `hooks.json`, `.claude/hooks.json`, and `.claude/settings.json` / `.claude/settings.local.json` (when a `"hooks"` key is present) across lifecycle events (`PreToolUse`, `PostToolUse`, `SessionStart`, etc.).
- **Repo AI instruction opt-in (`--include-repo-instructions`).** Added `--include-repo-instructions` flag to include `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, and `.cursor/rules/*.mdc` in directory scans; `detect_format_from_text` now recognizes `.cursorrules` and `.mdc` as `claude-native`.
- **Agent dot-directory traversal.** Directory scans now descend into `.claude`, `.cursor`, `.vscode`, and `.claude-plugin` to surface hidden MCP and hook configs.
- **2025–2026 agentic attack vector patterns.** Added detection for Unicode Tag block ASCII smuggling (`\U000e0000–\U000e007f`), bidirectional override characters (`\u202a–\u202e`, `\u2066–\u2069`), hidden `<system>`/`<tool_instruction>`/`<hidden_instruction>` XML tags, MCP tool-shadowing & cross-tool parameter smuggling (`MCP03:2025`), agent permission-bypass flags (`--dangerously-skip-permissions`, `--trust-all-tools`), non-PyPI/non-npm package-index hijacking, writes to agent context/config files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.mcp.json`, `.claude/settings*.json`), `git config core.hooksPath`/`core.fsmonitor`, and MCP `autoApprove`/`alwaysAllow` wildcards. Also updated `--llm` review prompts and added `examples/hooks.json`.

### Changed
- **Hardened MCP config scanning.** Added `.mcp.json` detection, ephemeral remote runner checks (`npx`/`uvx`/`bunx`/`pnpx` targeting `https://`, `git+`, `github:`, `.tgz`, `.tar.gz`), cloud metadata SSRF endpoint detection (`169.254.169.254`, `metadata.google.internal`), unencrypted `http://` transport warnings, hardcoded credentials in HTTP `headers`, and stricter `_has_auth` checks. MCP findings also map into structured `Finding` objects on `ScoreDimension` for SARIF/verdict consistency.

### Fixed
- **Remote git branch validation.** Validated git branch names in `fetcher.py` before performing DNS lookups, and resolved ruff lint issues across `cli.py`, `code_projection.py`, `config.py`, `fetcher.py`, `formatters.py`, and `skill_rubrics.py`.

## [0.10.4] - 2026-07-14

### Fixed — defensive secret-audit false positives
- Explicit guidance to scan for and redact credentials no longer triggers the
  broad EXFILTRATION proximity heuristics merely because it mentions printing,
  logging, or private-key signatures.
- Separate `rg`/`grep` audit expressions in one code block are no longer joined
  into an invented credential-exposure relationship. Concrete outbound sinks,
  credential logging, uploads, and malicious counterparts remain flagged.

## [0.10.3] - 2026-06-30

### Fixed — real-world false positives in trust scoring
- **`rm -rf` on scoped paths.** The `[/~]` pattern matched any absolute path, so
  `rm -rf /tmp/x` or `rm -rf ./build` was mislabeled DESTRUCTIVE "on root or home
  directory." Now only root/home/`$HOME` (and globs of them) match, plus a separate
  pattern for critical system directories (`/etc`, `/usr`, …) that excludes `/tmp`.
  A path-traversal guard keeps `rm -rf /tmp/../../../` (which escapes `/tmp` back to
  root) flagged, so the scoped-path allowance can't be used as an evasion.
- **Shell-profile PERSISTENCE.** Merely *mentioning* or `source`-ing a profile
  ("add `source ~/.env` to `~/.zshrc`", "`source ~/.zshrc` to reload") fired
  PERSISTENCE. Now it requires an actual write (`>>`/`tee`) into the profile.
- **`0.0.0.0/0` and localhost SUSPICIOUS_URL.** A CIDR in a security warning
  ("never allow `0.0.0.0/0`") and `127.0.0.1` were flagged as direct-IP C2
  endpoints. Placeholder/loopback/broadcast addresses are now skipped.
- **Webhook EXFILTRATION.** A transparent `curl -X POST "$WEBHOOK"` (notification,
  Discord/Slack hook) was counted as exfiltration. Generic outbound POSTs are now
  reclassified to CAPABILITY; they stay EXFILTRATION only when the payload carries
  sensitive data (api key/token/secret/env/`.pem`/…) or is obfuscated.
- Regression coverage in `tests/test_false_positive_fixes.py` and updated
  `tests/test_case_folding.py`; each fix keeps its genuinely-malicious counterpart
  flagged.

## [0.10.2] - 2026-06-11

### Changed — trust verdict reads independently of the quality grade
- HTML report headers now show a prominent **trust badge** (`⛔ Block` / `⚠ Review`
  / `Warn` / `✓ Allow`, coloured by recommendation) next to the quality grade. A
  well-written malicious skill is a quality `C` *and* a trust `Block`; the badge
  makes the safety decision impossible to miss, so the grade can't be misread as
  "acceptable."

## [0.10.1] - 2026-06-11

### Added — LLM review feeds the verdict
- The optional `--llm` semantic review was previously display-only. Its findings
  now fold into the verdict: a high/critical `INJECTION`, `HIDDEN_BEHAVIOR`, or
  `INTENT_MISMATCH` escalates the recommendation (`human_review`/`block`), raises
  malice, and can set `intent_mismatch`. Each adds an explanatory reason.
- Escalate-only: the semantic layer can add scrutiny but never downgrade the
  verdict, and `QUALITY` findings never touch trust — a clean LLM pass is not
  evidence of safety (same principle as never trusting provenance). Verified by
  `tests/test_llm_verdict.py` and an end-to-end `--llm` run.

## [0.10.0] - 2026-06-11

### Added — nuance-aware trust (transparency axis, issue #2)
- Findings now carry a **`transparency`** signal (`declared` vs `hidden`). Trust is
  derived from *behaviour*, never from provenance — a reputable name or high quality
  score never lowers scrutiny.
- **Capability ≠ malice.** Execution primitives (`subprocess`, `os.system`,
  `exec.Command`, …) declared in the open are reclassified to a new **`CAPABILITY`**
  category — surfaced for review, not counted as malice. The *same* primitive hidden
  in a concealing skill (obfuscated/encoded evidence, or co-occurring with
  obfuscation/injection) stays `EXFILTRATION` malice.
- The verdict escalates **any hidden finding** to malice, and a hidden
  exfil/secret/backdoor now **blocks regardless of profile** — concealment removes the
  "expected capability in context" benefit of the doubt.
- Net effect: a legitimate dev/deploy toolkit that openly uses powerful primitives
  reads as `capability` / `human_review` instead of a malice-driven `F`; a polished,
  reputable-looking skill that *hides* an exfil call still blocks. Verified by
  `tests/test_transparency.py` (incl. the "reputable-but-compromised must still block"
  case) and adversarial encode-then-exec / wrapped-payload probes.

### Added — intent–capability coherence (issue #2, layer 2)
- The verdict gains an **`intent_mismatch`** signal: a system-level capability
  (shell/privilege/persistence/destructive) in a *purely textual* skill
  (summarize/translate/proofread/…) is flagged as not matching the stated purpose
  and escalated to `human_review` — even when declared.
- Coherence only ADDS scrutiny. A capability that *matches* the claimed purpose is
  never treated as evidence of safety (a malicious author can claim any purpose;
  hidden behaviour is judged separately). Deliberately tight scope (network is
  excluded, vague purposes aren't guessed) keeps false positives near zero —
  verified by adversarial probes (code-reviewer+linter, translator+API,
  summarizer+LLM-API all correctly NOT flagged).
- `ScoreCard` now carries `description`; the verdict surfaces `intent_mismatch` in
  the table and HTML outputs.

### Changed — lead with the verdict
- Outputs now present the letter grade explicitly as a **quality** grade and the
  **trust verdict** as a separate axis (table header `Quality: C  ·  Trust: block`,
  HTML/markdown likewise). A low quality grade can no longer be misread as a malice
  verdict, and a powerful-but-legitimate toolkit reads as `Trust: human_review`
  rather than a scary `F`.

## [0.9.0] - 2026-06-10

### Fixed
- **Dead threat patterns revived.** Case-insensitive pattern groups were matched
  against pre-lowercased text, which silently disabled every pattern containing
  an uppercase literal. Seven patterns never fired, including `curl -X POST`/`PUT`
  exfiltration, `chmod -R 777`, recursive `chown … root`, `subprocess.Popen`,
  Go `exec.Command` reverse shells, `JSON.stringify(credentials)`, and the `DAN`
  jailbreak injection pattern. The scanner now matches the original text with
  `re.IGNORECASE`, fixing the whole class of bug at once.

### Security
- **SSRF hardening in the remote fetcher.** All remote fetches now validate that
  the target host resolves only to globally-routable addresses, rejecting
  loopback, link-local/cloud-metadata (`169.254.169.254`), private (RFC1918),
  reserved, and unspecified addresses (IPv4 and IPv6, including IPv4-mapped).
  Redirects are re-validated per hop, responses are capped at 10 MiB, and
  downloaded filenames are sanitised against path traversal.
- **DNS-rebinding / TOCTOU fix.** File fetches now pin the connection to the IP
  validated at check time (via a custom `HTTP(S)Connection` that connects to the
  pinned IP while keeping the original hostname for TLS SNI and certificate
  verification), so a hostname cannot resolve to a public IP during validation
  and a private/metadata IP at connect. Each redirect hop is independently
  re-validated and re-pinned.
- **Git clone hardening.** Remote repo cloning is restricted to `http(s)`
  transports (`protocol.allow=never` + per-protocol allowlist), blocking
  `ext::`, `file://`, and `ssh://` transport abuse. Option-injection via
  leading-dash URLs/branches is rejected and positional args are `--`-separated.
- **Safer temp cleanup.** `cleanup_temp` now removes only the `skill-audit-`
  prefixed `mkdtemp` directory it created, instead of deleting by broad `/tmp`
  path prefix.

### Added
- `ruff` and `mypy` are now dev dependencies, configured in `pyproject.toml`, and
  run as a dedicated `lint` job in CI. The codebase is lint- and type-clean.
- Regression tests for the case-folding fix (`tests/test_case_folding.py`) and
  for the new SSRF / git / cleanup guards (`tests/test_fetcher.py`).

### Changed
- Modernised type hints (`Optional[X]` → `X | None`) and removed dead code
  (`_parse_body_ast`) and unused assignments flagged by the new linters.
- Expanded `.gitignore` to cover local AI-agent config and scratch files.
