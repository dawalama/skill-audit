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

## 2. Large Skills Collection

A collection of 200+ domain-specific Claude skills (engineering, marketing, product, C-level advisor, etc.). Scanned with `--min-grade B` to flag skills that need improvement.

```bash
ai-skill-audit audit https://github.com/alirezarezvani/claude-skills --summary --min-grade B
```

```
                              Skill Audit Summary
┏━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━┓
┃ File                 ┃ Type  ┃ Name                 ┃ Grade ┃ Score ┃ Issues ┃
┡━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━┩
│ SKILL.md             │ skill │ "engineering-skills" │   C   │   72% │      5 │
│ SKILL.md             │ skill │ "c-level-advisor"    │   C   │   70% │      6 │
│ SKILL.md             │ skill │ "finance-skills"     │   C   │   66% │      6 │
│ SKILL.md             │ skill │ "pm-skills"          │   C   │   65% │      7 │
│ SKILL.md             │ skill │ "ra-qm-skills"       │   C   │   65% │      7 │
│ SKILL.md             │ skill │ "business-growth-sk… │   D   │   63% │      7 │
│ SKILL.md             │ skill │ "engineering-advanc… │   D   │   63% │      7 │
│ SKILL.md             │ skill │ "product-skills"     │   D   │   63% │      7 │
│ SKILL.md             │ skill │ "marketing-skills"   │   D   │   63% │      7 │
│ SKILL-AUTHORING-STA… │ skill │ Skill Authoring      │   D   │   60% │      8 │
│                      │       │ Standard             │       │       │        │
└──────────────────────┴───────┴──────────────────────┴───────┴───────┴────────┘

  10 files analyzed, average score: 65%

  Skipped 12 documentation file(s) (README, CONTRIBUTING, etc.).
  Use --include-docs to scan them.

10 file(s) below minimum grade B
```

**What it shows:** All 10 skill files scored below B (65% average). Common issues: missing examples, missing gotchas/caveats, and limited testability. No security threats detected — these are quality issues, not safety issues.

**Doc filtering in action:** 12 documentation files (README, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, INSTALLATION, etc.) were automatically skipped. In the previous version without filtering, these inflated the results to 20 files with many false low grades.

## HTML Reports

The same scans are available as self-contained HTML reports:

- [MCP config scan](https://dawalama.github.io/skill-audit/remote-audit-mcp.html) — angrysky56/100-tool-mcp-server
- [Skills collection scan](https://dawalama.github.io/skill-audit/remote-audit-skills.html) — alirezarezvani/claude-skills

Generate your own:

```bash
ai-skill-audit audit https://github.com/user/repo --output html > report.html
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
