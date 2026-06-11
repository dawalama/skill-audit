"""Context-aware audit interpretation.

The scanner should stay strict. This module explains what the findings mean for
installation/use decisions without hiding raw evidence.
"""

from __future__ import annotations

from .models import AuditVerdict, Finding, ScoreCard

MALICE_CATEGORIES = {
    "INJECTION", "SECRET", "EXFILTRATION", "PERSISTENCE", "HIJACKING", "OBFUSCATION",
}

CAPABILITY_CATEGORIES = {
    "DESTRUCTIVE", "PRIVILEGE", "SUSPICIOUS_URL", "ENTROPY",
    # Declared execution primitives (subprocess/os.system/…) — powerful capability,
    # not malice on their own. They are routed here only when declared in the open;
    # the same primitive hidden in a concealing skill stays EXFILTRATION (malice).
    "CAPABILITY",
}


def _is_malice_finding(finding: Finding) -> bool:
    """A finding signals malice if it is an intrinsically-malicious category, or
    if its behaviour is HIDDEN. Concealment is the tell — a hidden capability is
    no longer just capability. Provenance/quality never enter this decision."""
    return finding.category in MALICE_CATEGORIES or finding.transparency == "hidden"


# Purely textual purposes: text-in, text-out operations that genuinely never need
# shell/privilege/persistence/destructive capability. Kept deliberately tight so
# the mismatch signal almost never fires a false positive. (Network is excluded —
# a text skill may legitimately call a translation/LLM API.)
_PURELY_TEXTUAL_PURPOSE = (
    "summari", "paraphras", "proofread", "rephrase", "spellcheck", "spell check",
    "word count", "rewrite", "grammar", "glossary", "translate", "translation",
)

# System-level capability that a purely textual skill has no reason to hold.
_SYSTEM_CAPABILITY = {"CAPABILITY", "PRIVILEGE", "PERSISTENCE", "HIJACKING", "DESTRUCTIVE"}


def _intent_mismatch(card: ScoreCard, findings: list[Finding]) -> bool:
    """True when a purely textual purpose is paired with system capability.

    Mismatch only ADDS scrutiny — a capability that *matches* the stated purpose
    is never treated as evidence of safety (a malicious author can claim any
    purpose; hidden behaviour is judged separately).
    """
    # The description is the strongest purpose signal; the name backs it up.
    purpose = f"{card.entity_name} {card.description}".lower()
    purely_textual = any(term in purpose for term in _PURELY_TEXTUAL_PURPOSE)
    if not purely_textual:
        return False
    return any(f.category in _SYSTEM_CAPABILITY for f in findings)


def interpret_card(card: ScoreCard) -> AuditVerdict:
    """Return a context-aware verdict for a scorecard."""
    findings = _active_findings(card)
    categories = {f.category for f in findings}
    profile = _infer_profile(card)
    malice = _malice_level(findings)
    capability = _capability_level(findings, profile)
    intent_mismatch = _intent_mismatch(card, findings)
    recommendation = _recommendation(
        card, findings, profile, malice, capability, intent_mismatch
    )
    reasons = _reasons(
        card, findings, profile, malice, capability, recommendation, intent_mismatch
    )

    summary = _summary(
        recommendation=recommendation,
        profile=profile,
        malice=malice,
        capability=capability,
        categories=categories,
    )

    return AuditVerdict(
        profile=profile,
        recommendation=recommendation,
        capability_risk=capability,
        malice_indicators=malice,
        intent_mismatch=intent_mismatch,
        quality=card.grade,
        summary=summary,
        reasons=reasons,
    )


def _active_findings(card: ScoreCard) -> list[Finding]:
    return [
        finding
        for dim in card.dimensions
        for finding in dim.findings
        if finding.disposition == "active"
    ]


def _infer_profile(card: ScoreCard) -> str:
    if card.entity_type == "mcp-config" or card.format == "mcp-config":
        return "mcp-config"

    path_parts = []
    if card.file_path:
        path_parts = [part.lower() for part in card.file_path.parts[-6:]]

    text = " ".join(
        part.lower()
        for part in [
            card.entity_name,
            card.file_path.name if card.file_path else "",
            card.file_path.parent.name if card.file_path else "",
            " ".join(path_parts),
        ]
    )

    if any(term in text for term in (
        "deploy", "ship", "release", "canary", "cloud", "kubernetes",
        "homelab", "wireguard", "pihole", "dns", "ssh", "service",
    )):
        return "deployment"
    if any(term in text for term in ("browser", "scrape", "cookie", "chrome")):
        return "browser-automation"
    if any(term in text for term in (
        "gstack", "devtool", "developer", "review", "qa", "benchmark",
        "codex", "git", "workflow", "django", "swiftui", "vite",
        "pytorch", "mysql", "jira", "verification", "patterns",
        "testing", "e2e", "netmiko",
    )):
        return "developer-toolkit"
    if any(term in text for term in ("payment", "x402", "evm", "token", "wallet", "blockchain", "crypto")):
        return "developer-toolkit"
    if any(term in text for term in ("security", "threat", "audit", "malicious", "injection")):
        return "security-research"
    if card.file_path and card.file_path.name.lower() not in {"skill.md", "main.md"}:
        return "documentation"
    return "general"


def _malice_level(findings: list[Finding]) -> str:
    malice_findings = [f for f in findings if _is_malice_finding(f)]
    if any(f.severity == "critical" for f in malice_findings):
        return "high"
    if any(f.severity == "high" for f in malice_findings):
        return "medium"
    if malice_findings:
        return "low"
    return "low"


def _capability_level(findings: list[Finding], profile: str) -> str:
    capability_findings = [f for f in findings if f.category in CAPABILITY_CATEGORIES]
    if not capability_findings:
        return "low"
    count = len(capability_findings)
    high_capability_profiles = {"developer-toolkit", "deployment", "browser-automation", "mcp-config"}
    if profile in high_capability_profiles:
        if count >= 6:
            return "high"
        return "medium"
    if any(f.severity in {"critical", "high"} for f in capability_findings) or count >= 3:
        return "high"
    return "medium"


def _recommendation(
    card: ScoreCard,
    findings: list[Finding],
    profile: str,
    malice: str,
    capability: str,
    intent_mismatch: bool = False,
) -> str:
    categories = {f.category for f in findings}
    hidden_malice = any(_is_malice_finding(f) and f.transparency == "hidden" for f in findings)

    if "INJECTION" in categories:
        return "block"
    if categories & {"SECRET", "EXFILTRATION", "PERSISTENCE", "HIJACKING"}:
        # Concealment removes the benefit of the doubt: a HIDDEN exfil/secret/
        # backdoor blocks regardless of how the skill profiles or who shipped it.
        if hidden_malice:
            return "block"
        if profile in {"developer-toolkit", "deployment", "browser-automation", "security-research", "documentation"}:
            return "human_review"
        return "block"
    if "OBFUSCATION" in categories:
        return "human_review"
    if malice == "high":
        return "human_review"
    # A capability that doesn't match the stated purpose is suspicious even when
    # declared — surface it for a human.
    if intent_mismatch:
        return "human_review"
    if capability == "high":
        return "human_review"
    if capability == "medium":
        return "warn"
    if card.grade in {"A", "B"}:
        return "allow"
    return "warn"


def _reasons(
    card: ScoreCard,
    findings: list[Finding],
    profile: str,
    malice: str,
    capability: str,
    recommendation: str,
    intent_mismatch: bool = False,
) -> list[str]:
    categories = sorted({f.category for f in findings})
    reasons: list[str] = []
    if categories:
        reasons.append(f"Active finding categories: {', '.join(categories)}")
    if profile != "general":
        reasons.append(f"Interpreted as {profile}; expected capabilities are reviewed in that context")
    if intent_mismatch:
        reasons.append("Capability does not match the stated purpose (system access in a text-only skill)")
    if malice != "low":
        reasons.append(f"Malice indicators are {malice}")
    if capability != "low":
        reasons.append(f"Capability risk is {capability}")
    if card.grade not in {"A", "B"}:
        reasons.append(f"Quality grade is {card.grade}")
    if recommendation in {"human_review", "block"}:
        reasons.append("Raw findings are preserved; reputation/profile should not suppress evidence")
    return reasons


def _summary(
    *,
    recommendation: str,
    profile: str,
    malice: str,
    capability: str,
    categories: set[str],
) -> str:
    if not categories:
        return f"{recommendation}: no active security findings; profile={profile}"
    return (
        f"{recommendation}: profile={profile}, "
        f"malice={malice}, capability={capability}, "
        f"categories={', '.join(sorted(categories))}"
    )
