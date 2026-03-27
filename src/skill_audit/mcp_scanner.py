"""Scanner for MCP (Model Context Protocol) configuration files.

Detects risky server permissions, suspicious command patterns, and
overly broad tool access in mcp.json and claude_desktop_config.json.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class McpServerFinding:
    """A single finding for an MCP server."""

    server_name: str
    category: str  # e.g. "risky-command", "broad-filesystem", "network-exposure"
    severity: str  # "low", "medium", "high", "critical"
    message: str
    detail: str = ""


@dataclass
class McpScanResult:
    """Result of scanning an MCP config file."""

    servers: list[McpServerFinding] = field(default_factory=list)
    overall_risk: str = "low"  # "low", "medium", "high", "critical"
    summary: str = ""
    server_count: int = 0
    parse_error: str = ""


# ---------------------------------------------------------------------------
# Pattern tables
# ---------------------------------------------------------------------------

# Commands that allow arbitrary code execution
_RISKY_COMMANDS = [
    (r"^(bash|sh|zsh|fish|csh)$", "Shell interpreter allows arbitrary command execution"),
    (r"^(python|python3|ruby|perl)$", "Script interpreter allows arbitrary code execution"),
    (r"^cmd(\.exe)?$", "Windows shell allows arbitrary command execution"),
    (r"^powershell(\.exe)?$", "PowerShell allows arbitrary command execution"),
]

# Arg patterns that indicate inline code execution
_RISKY_ARG_PATTERNS = [
    (r"(^|\s)-[ce]\b", "Inline code execution flag"),
    (r"(^|\s)--eval\b", "Eval flag allows arbitrary code execution"),
    (r"\beval\b", "Eval allows arbitrary code execution"),
    (r"\bexec\b", "Exec allows arbitrary code execution"),
]

# Broad filesystem paths
_BROAD_FS_PATHS = [
    (r'^"?/"?$', "Root filesystem access (/)"),
    (r'^"?~"?$', "Full home directory access (~)"),
    (r'^"?(/Users|/home)/[^/]+"?$', "Full user home directory access"),
    (r"~?/?\.(ssh|gnupg|gpg)\b", "Access to SSH/GPG key directory"),
    (r"~?/?\.(aws|azure|gcloud)\b", "Access to cloud credential directory"),
    (r"~?/?\.(kube|docker)/?(config)?", "Access to container/orchestration credentials"),
    (r"/etc/(passwd|shadow|sudoers)", "Access to system credential files"),
    (r"~?/?\.env\b", "Access to environment file with secrets"),
]

# Suspicious URL patterns (reuse patterns from skill trust scan)
_SUSPICIOUS_URL_PATTERNS = [
    (r"\b(bit\.ly|tinyurl|t\.co|rb\.gy|is\.gd)/", "URL shortener hides true destination"),
    (r"\bpastebin\.com/", "Pastebin URL (common malware hosting)"),
    (r"\bngrok\.io\b", "Ngrok tunnel (potential C2 or exfil endpoint)"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/]", "Direct IP address (no DNS = suspicious)"),
    (r"\bgist\.github\.com/", "Gist URL (unreviewed code source)"),
]

# Env var names that likely hold secrets
_SENSITIVE_ENV_PATTERNS = [
    (r"(API_KEY|APIKEY)", "API key in environment"),
    (r"(SECRET|_TOKEN|AUTH_TOKEN)", "Secret/token in environment"),
    (r"(PASSWORD|PASSWD)", "Password in environment"),
    (r"(PRIVATE_KEY|SIGNING_KEY)", "Private/signing key in environment"),
    (r"(AWS_SECRET|AWS_ACCESS)", "AWS credential in environment"),
    (r"(DATABASE_URL|DB_PASSWORD)", "Database credential in environment"),
]

# Network exposure patterns
_NETWORK_PATTERNS = [
    (r"\b0\.0\.0\.0\b", "Listening on all interfaces (0.0.0.0)"),
    (r"--host\s+0\.0\.0\.0", "Explicitly binding to all interfaces"),
    (r"\bINADDR_ANY\b", "Binding to all interfaces"),
]


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_mcp_config(path: Path) -> McpScanResult:
    """Scan an MCP config file for security issues."""
    result = McpScanResult()

    # Parse JSON
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
    except json.JSONDecodeError as e:
        result.parse_error = f"Malformed JSON: {e}"
        result.overall_risk = "medium"
        result.summary = f"Could not parse {path.name}: {e}"
        return result
    except OSError as e:
        result.parse_error = f"Cannot read file: {e}"
        result.overall_risk = "medium"
        result.summary = f"Cannot read {path.name}: {e}"
        return result

    # Find the servers dict — supports both top-level and nested
    servers = data.get("mcpServers") or data.get("mcp_servers") or data.get("servers") or {}
    if not isinstance(servers, dict):
        result.summary = "No MCP servers found in config"
        return result

    result.server_count = len(servers)

    for name, config in servers.items():
        if not isinstance(config, dict):
            continue
        _scan_server(name, config, result)

    # Compute overall risk
    result.overall_risk = _compute_overall_risk(result.servers)
    result.summary = _build_summary(result)
    return result


def _scan_server(name: str, config: dict, result: McpScanResult) -> None:
    """Scan a single MCP server configuration."""
    command = config.get("command", "")
    args = config.get("args", [])
    env = config.get("env", {})
    url = config.get("url", "")

    if not isinstance(args, list):
        args = [str(args)]
    if not isinstance(env, dict):
        env = {}

    args_str = " ".join(str(a) for a in args)
    full_cmd = f"{command} {args_str}"

    # --- Risky commands ---
    for pattern, desc in _RISKY_COMMANDS:
        if re.search(pattern, command):
            result.servers.append(McpServerFinding(
                server_name=name,
                category="risky-command",
                severity="critical",
                message=desc,
                detail=f"command: {command}",
            ))

    # --- Risky arg patterns ---
    for pattern, desc in _RISKY_ARG_PATTERNS:
        if re.search(pattern, args_str):
            result.servers.append(McpServerFinding(
                server_name=name,
                category="risky-command",
                severity="high",
                message=f"{desc} in args",
                detail=f"args: {args_str[:100]}",
            ))

    # --- Broad filesystem access ---
    for arg in args:
        arg_s = str(arg)
        for pattern, desc in _BROAD_FS_PATHS:
            if re.search(pattern, arg_s):
                result.servers.append(McpServerFinding(
                    server_name=name,
                    category="broad-filesystem",
                    severity="high",
                    message=desc,
                    detail=f"path: {arg_s}",
                ))

    # --- Network exposure ---
    for pattern, desc in _NETWORK_PATTERNS:
        if re.search(pattern, full_cmd) or re.search(pattern, url):
            result.servers.append(McpServerFinding(
                server_name=name,
                category="network-exposure",
                severity="high",
                message=desc,
                detail=f"in: {full_cmd[:100] if re.search(pattern, full_cmd) else url[:100]}",
            ))

    # --- Suspicious URLs ---
    texts_to_check = [full_cmd, url] + [str(v) for v in env.values()]
    for text in texts_to_check:
        for pattern, desc in _SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                result.servers.append(McpServerFinding(
                    server_name=name,
                    category="suspicious-url",
                    severity="high",
                    message=desc,
                    detail=f"in: {text[:100]}",
                ))

    # --- Overly permissive tools ---
    allowed_tools = config.get("allowedTools", config.get("allowed_tools", []))
    if isinstance(allowed_tools, list):
        if "*" in allowed_tools or "all" in [str(t).lower() for t in allowed_tools]:
            result.servers.append(McpServerFinding(
                server_name=name,
                category="overly-permissive",
                severity="high",
                message="Wildcard tool access (allowedTools: [\"*\"]) grants unrestricted capabilities",
                detail=f"allowedTools: {allowed_tools}",
            ))
        elif len(allowed_tools) > 20:
            result.servers.append(McpServerFinding(
                server_name=name,
                category="overly-permissive",
                severity="medium",
                message=f"Very broad tool list ({len(allowed_tools)} tools) — consider restricting",
                detail=f"allowedTools count: {len(allowed_tools)}",
            ))

    # --- No authentication ---
    if url and not _has_auth(config, env):
        result.servers.append(McpServerFinding(
            server_name=name,
            category="no-auth",
            severity="medium",
            message="Server exposes API via URL without apparent authentication",
            detail=f"url: {url[:100]}",
        ))

    # --- Environment variable leaks ---
    for env_name, env_val in env.items():
        env_upper = env_name.upper()
        for pattern, desc in _SENSITIVE_ENV_PATTERNS:
            if re.search(pattern, env_upper):
                # Check if the value looks like an actual secret (not a reference)
                val_str = str(env_val)
                if val_str and not val_str.startswith("$") and not val_str.startswith("${"):
                    severity = "high" if len(val_str) > 8 else "medium"
                    result.servers.append(McpServerFinding(
                        server_name=name,
                        category="env-leak",
                        severity=severity,
                        message=f"{desc}: {env_name} has hardcoded value",
                        detail=f"{env_name}={val_str[:4]}{'*' * max(0, len(val_str) - 4)}",
                    ))
                break  # one match per env var is enough


def _has_auth(config: dict, env: dict) -> bool:
    """Heuristically check if a server config includes authentication."""
    # Check for auth-related keys in config
    auth_keys = {"auth", "authentication", "authorization", "apiKey", "api_key",
                 "token", "bearer", "headers"}
    if any(k.lower() in (ck.lower() for ck in config.keys()) for k in auth_keys):
        return True
    # Check for auth-related env vars
    auth_env = {"API_KEY", "TOKEN", "SECRET", "AUTH", "BEARER", "PASSWORD"}
    for env_name in env:
        if any(pat in env_name.upper() for pat in auth_env):
            return True
    return False


def _compute_overall_risk(findings: list[McpServerFinding]) -> str:
    """Compute overall risk level from all findings."""
    if not findings:
        return "low"

    severities = [f.severity for f in findings]
    if "critical" in severities:
        return "critical"
    if severities.count("high") >= 2:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


def _build_summary(result: McpScanResult) -> str:
    """Build human-readable summary of scan results."""
    if result.parse_error:
        return f"Parse error: {result.parse_error}"

    if not result.servers:
        return f"Scanned {result.server_count} server(s) — no issues found"

    # Count findings by category
    categories: dict[str, int] = {}
    for f in result.servers:
        categories[f.category] = categories.get(f.category, 0) + 1

    parts = [f"{result.server_count} server(s), {len(result.servers)} finding(s)"]

    # Summarize top categories
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        label = cat.replace("-", " ")
        parts.append(f"{count} {label}")

    return "; ".join(parts)
