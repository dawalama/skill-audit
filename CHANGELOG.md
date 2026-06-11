# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
semantic versioning.

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
