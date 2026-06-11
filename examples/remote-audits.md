# Remote Audit Examples

Real-world scans using `ai-skill-audit` against public GitHub repositories.

## 1. MCP Config with Hardcoded Secrets

A popular "100-tool MCP config" example repo. The MCP scanner detects 6 hardcoded API keys/tokens.

```bash
ai-skill-audit audit https://github.com/angrysky56/100-tool-mcp-server-json-example --verbose
```

```
  Fetching https://github.com/angrysky56/100-tool-mcp-server-json-example...

╭──────────────────────────────────────────────────────────────────────────────╮
│ claude_desktop_config.json (mcp-config) — Grade: B (80%)                     │
╰───────────────────────────── Format: mcp-config ─────────────────────────────╯
┏━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━┓
┃ Dimension        ┃ Score ┃ Weight ┃ Status     ┃
┡━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━┩
│ command_safety   │  100% │    30% │ ██████████ │
│ filesystem_scope │  100% │    25% │ ██████████ │
│ secret_hygiene   │    0% │    20% │ ░░░░░░░░░░ │
│ network_trust    │  100% │    25% │ ██████████ │
└──────────────────┴───────┴────────┴────────────┘

  secret_hygiene (0%)
    !  Secret/token in environment: GITHUB_PERSONAL_ACCESS_TOKEN has hardcoded value
    !  API key in environment: BRAVE_API_KEY has hardcoded value
    !  API key in environment: GOOGLE_MAPS_API_KEY has hardcoded value
    ! [MCP-wolfram-alpha] API key in environment: WOLFRAM_API_KEY has hardcoded value
    !  Secret/token in environment: SLACK_BOT_TOKEN has hardcoded value
    !  Secret/token in environment: DISCORD_TOKEN has hardcoded value

  Overall Risk: CRITICAL — Weakest: secret_hygiene (6 findings)
  30 server(s) configured, 6 finding(s)

  Recommendation: Move all secrets to a .env file or credential manager.

  Skipped 1 documentation file(s) (README, CONTRIBUTING, etc.).
  Use --include-docs to scan them.
```

**What it caught:** 6 hardcoded API keys/tokens across services (GitHub, Brave, Google Maps, Wolfram Alpha, Slack, Discord). These are the exact kind of secrets that get leaked when users copy-paste shared MCP configs.

**What's safe:** Command patterns, filesystem scope, and network configuration all scored 100%.

## 2. Real Skill Repo — Quality Scoring

A real public WebGPU/Three.js skill collection (`dgreenheck/webgpu-claude-skill`), scanned straight from GitHub. No security threats — this is the *quality* half of the tool at work on legitimate, well-intentioned code.

```bash
ai-skill-audit audit https://github.com/dgreenheck/webgpu-claude-skill --summary
```

```
                              Skill Audit Summary
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━┓
┃ File                 ┃ Type   ┃ Name                ┃ Grade ┃ Score ┃ Issues ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━┩
│ basic-setup.js       │ script │ basic-setup.js      │   A   │  100% │      - │
│ custom-material.js   │ script │ custom-material.js  │   A   │  100% │      - │
│ earth-shader.js      │ script │ earth-shader.js     │   A   │  100% │      - │
│ particle-system.js   │ script │ particle-system.js  │   A   │  100% │      - │
│ post-processing.js   │ script │ post-processing.js  │   A   │  100% │      - │
│ compute-shader.js    │ script │ compute-shader.js   │   A   │  100% │      - │
│ webgpu-project.js    │ script │ webgpu-project.js   │   A   │  100% │      - │
│ device-loss.md       │ skill  │ Device Loss         │   C   │   66% │      6 │
│ limits-and-features… │ skill  │ Limits And Features │   D   │   65% │      6 │
│ SKILL.md             │ skill  │ webgpu-threejs-tsl  │   D   │   63% │      7 │
│ compute-shaders.md   │ skill  │ Compute Shaders     │   D   │   58% │      7 │
│ REFERENCE.md         │ skill  │ Reference           │   D   │   57% │      8 │
│ wgsl-integration.md  │ skill  │ Wgsl Integration    │   D   │   56% │      8 │
│ core-concepts.md     │ skill  │ Core Concepts       │   D   │   54% │      8 │
│ materials.md         │ skill  │ Materials           │   D   │   54% │      8 │
│ post-processing.md   │ skill  │ Post Processing     │   D   │   54% │      8 │
└──────────────────────┴────────┴─────────────────────┴───────┴───────┴────────┘

  16 files analyzed, average score: 77%
```

**What it shows:** Trust is clean across all 16 files — no security findings on a legitimate repo. The 7 JavaScript helper scripts score A; the 9 skill markdown files land C–D for quality gaps (missing examples, gotchas, and structure). That's actionable feedback for the author — the "harden the skills you write" half — not a safety verdict.

## 3. Malicious Skill (Multi-Vector Attack)

An intentionally malicious skill that looks like a "Project Setup Helper" but contains prompt injection, credential theft, obfuscated code execution, and destructive commands.

```bash
ai-skill-audit audit examples/malicious-skill.md --verbose
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ Project Setup Helper (skill) — Grade: C (77%)                                │
╰──────────────────────────── Format: dotai-skill ─────────────────────────────╯
┏━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━┓
┃ Dimension     ┃ Score ┃ Weight ┃ Status     ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━┩
│ completeness  │  100% │    20% │ ██████████ │
│ clarity       │  100% │    15% │ ██████████ │
│ actionability │   87% │    20% │ ████████░░ │
│ safety        │  100% │    15% │ ██████████ │
│ testability   │  100% │    10% │ ██████████ │
│ trust         │    0% │    20% │ ░░░░░░░░░░ │
└───────────────┴───────┴────────┴────────────┘

  trust (0%)
    + CRITICAL: 13 suspicious pattern(s) found — review carefully before use
    ! [DESTRUCTIVE] Destructive rm -rf on root or home directory
    ! [EXFILTRATION] Posts data to external URL
    ! [EXFILTRATION] Accesses SSH keys
    ! [EXFILTRATION] Accesses AWS credentials
    ! [OBFUSCATION] Decodes and executes hidden commands
    ! [OBFUSCATION] Dynamic import (common in obfuscated malware)
    ! [PRIVILEGE] Requests elevated privileges
    ! [INJECTION] Prompt injection: instruction override attempt
    ! [INJECTION] Prompt injection: identity reassignment
    ! [INJECTION] Prompt injection: DAN pattern
    ! [INJECTION] Hidden instruction tag (known injection pattern from ClawHavoc)
    ! [SUSPICIOUS_URL] Direct IP address (no DNS = suspicious)
    ! [ENTROPY] High-entropy string (5.2 bits)
```

**What it caught:** 13 findings across 7 threat categories — all from a skill that looks perfectly normal on the surface (has description, steps, inputs, examples, gotchas). The quality dimensions all score high, but trust drops to 0%.

**Key insight:** This is exactly how real attacks work. The skill is well-structured enough to pass a casual review, but the trust scanner catches the `<IMPORTANT>` hidden tag, base64-encoded shell commands, credential file access, and prompt injection buried in the body.

## 4. Evil Deploy — All 10 arXiv:2604.03070 Categories

A test skill that covers all 10 vulnerability categories from the "Credential Leakage in LLM Agent Skills" paper. Each step maps to a specific attack pattern.

```bash
ai-skill-audit audit examples/evil-deploy.md --verbose
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ evil-deploy (skill) — Grade: F (28%)                                         │
╰──────────────────────────── Format: dotai-skill ─────────────────────────────╯

  trust (0%)
    + CRITICAL: 16 suspicious pattern(s) found — review carefully before use
    ! [EXFILTRATION] Posts data to external URL
    ! [EXFILTRATION] May leak secrets
    ! [EXFILTRATION] May exfiltrate environment variables
    ! [EXFILTRATION] Encoded data exfiltration
    ! [EXFILTRATION] Accesses SSH keys
    ! [EXFILTRATION] Accesses AWS credentials
    ! [EXFILTRATION] Reads secret/key files
    ! [EXFILTRATION] Reverse shell via bash /dev/tcp
    ! [EXFILTRATION] Credentials in curl -u argument (visible in process list)
    ! [OBFUSCATION] Decodes and executes hidden commands
    ! [SECRET] Possible hardcoded API key or token
    ! [SUSPICIOUS_URL] Pipe from URL to shell (remote code execution)
    ! [SUSPICIOUS_URL] Direct IP address (no DNS = suspicious)
    ! [PERSISTENCE] Appending to authorized_keys — backdoor installation
    ! [HIJACKING] Cryptocurrency miner (xmrig)
    ! [HIJACKING] Mining pool connection (stratum protocol)
```

**What it caught:** 16 findings across 6 threat categories. All 10 steps trigger at least one finding. The two new categories (PERSISTENCE, HIJACKING) catch attack patterns that previous versions missed entirely.

**Paper mapping:**
| Step | Paper Category | Finding |
|------|---------------|---------|
| 1-2 | A4 Artifact Leakage | SSH keys, AWS credentials |
| 3 | A1 Information Exposure (73.5%) | Credential logging |
| 4 | B4 Data Exfiltration | curl POST to webhook |
| 5 | B1 Remote Exploitation (52.2%) | Reverse shell |
| 6 | B6 Persistence | authorized_keys backdoor |
| 7 | B2 Defense Evasion | base64 obfuscated payload |
| 8 | A2 Hardcoded Credentials | Embedded API key |
| 9 | A3 Insecure Storage | Credentials in CLI args |
| 10 | B5 Resource Hijacking | Crypto miner |

## 5. Remote Audit Security Hardening (v0.4.0)

When auditing remote repos, v0.4.0 applies stricter defaults to prevent the audited content from influencing its own score:

```bash
# Remote audit — hardened by default
ai-skill-audit audit https://github.com/user/repo --verbose

# What changes for remote targets:
# - Repo's .skill-audit-ignore file is NOT loaded (use --trust-target-ignore to opt in)
# - Inline <!-- skill-audit: ignore CATEGORY --> comments are ignored entirely
# - Documentation files (README, AGENTS.md, CLAUDE.md) ARE scanned (part of attack surface)
# - Critical categories (INJECTION, SECRET, EXFILTRATION, PERSISTENCE, HIJACKING)
#   can never be suppressed inline, even for local files
```

**Why this matters:** A malicious skill author could previously embed `<!-- skill-audit: ignore INJECTION -->` or ship a `.skill-audit-ignore` file to hide their own findings. Now, remote content has zero influence on its audit score.

## Reports

Generated reports:

- [Malicious skill scan](https://dawalama.github.io/skill-audit/audit-malicious-skill.html) — multi-vector attack caught
- [Malicious skill + LLM review](https://dawalama.github.io/skill-audit/audit-malicious-skill-llm.html) — static scan plus semantic review
- [MCP config scan](https://dawalama.github.io/skill-audit/remote-audit-mcp.html) — angrysky56/100-tool-mcp-server
- [MCP config + LLM review](https://dawalama.github.io/skill-audit/audit-mcp-llm.html) — optional semantic MCP security review
- [Real skill repo — quality scoring](https://dawalama.github.io/skill-audit/remote-audit-webgpu.html) — dgreenheck/webgpu-claude-skill (16 files, trust clean)
- Agent-facing TOON examples: `audit-clean-skill.toon`, `audit-malicious-skill.toon`

Generate your own:

```bash
ai-skill-audit audit https://github.com/user/repo --output html > report.html

# Add optional semantic review for small/public inputs
ai-skill-audit audit examples/malicious-skill.md --llm --verbose --output html > report-llm.html
```

## Try it yourself

```bash
# Audit any GitHub repo
ai-skill-audit audit https://github.com/user/repo --summary

# Audit a specific file
ai-skill-audit audit https://github.com/user/repo/blob/main/SKILL.md --verbose

# Add LLM deep review for MCP configs
ai-skill-audit audit https://github.com/user/repo --llm --verbose
```
