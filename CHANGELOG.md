# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
semantic versioning.

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
