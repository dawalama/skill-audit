"""Data models for skill-lint scoring."""

from pathlib import Path

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A structured audit finding for machine consumers."""

    id: str
    category: str
    severity: str
    message: str
    evidence: str = ""
    source: str = "content"
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    disposition: str = "active"
    # "declared" = the operation is in the open (a documented, readable command);
    # "hidden" = concealed (obfuscated/encoded, or a capability primitive used in a
    # skill that is otherwise concealing behaviour). Transparency, not provenance,
    # is what separates powerful-but-legitimate from malicious.
    transparency: str = "declared"


class ScoreDimension(BaseModel):
    """A single scoring dimension with score and feedback."""

    name: str
    score: float = Field(ge=0.0, le=1.0)
    max_score: float = 1.0
    weight: float = 0.2
    details: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class AuditVerdict(BaseModel):
    """Context-aware interpretation of a scorecard."""

    profile: str = "general"
    recommendation: str = "warn"
    capability_risk: str = "low"
    malice_indicators: str = "low"
    # True when a system-level capability has no connection to the skill's stated
    # purpose (e.g. a "text summarizer" that runs a shell). Adds scrutiny; a match
    # never removes it.
    intent_mismatch: bool = False
    quality: str = "unknown"
    summary: str = ""
    reasons: list[str] = Field(default_factory=list)


class ScoreCard(BaseModel):
    """Complete scoring result for a skill or role."""

    entity_type: str  # "skill" or "role"
    entity_name: str
    format: str  # "dotai-skill", "dotai-role", "claude-native", "unknown"
    description: str = ""
    dimensions: list[ScoreDimension] = Field(default_factory=list)
    overall_score: float = 0.0
    grade: str = "F"
    summary: str = ""
    file_path: Path | None = None
    verdict: AuditVerdict | None = None

    def compute_overall(self) -> None:
        """Compute weighted overall score and grade from dimensions."""
        if not self.dimensions:
            self.overall_score = 0.0
            self.grade = "F"
            return

        total_weight = sum(d.weight for d in self.dimensions)
        if total_weight == 0:
            self.overall_score = 0.0
        else:
            self.overall_score = sum(d.score * d.weight for d in self.dimensions) / total_weight

        self.grade = _score_to_grade(self.overall_score)

    def to_dict(self) -> dict:
        """Serialize to dict for JSON output."""
        return {
            "entity_type": self.entity_type,
            "entity_name": self.entity_name,
            "format": self.format,
            "overall_score": round(self.overall_score, 3),
            "grade": self.grade,
            "summary": self.summary,
            "file_path": str(self.file_path) if self.file_path else None,
            "verdict": self.verdict.model_dump() if self.verdict else None,
            "dimensions": [
                {
                    "name": d.name,
                    "score": round(d.score, 3),
                    "weight": d.weight,
                    "details": d.details,
                    "suggestions": d.suggestions,
                    "findings": [f.model_dump() for f in d.findings],
                }
                for d in self.dimensions
            ],
        }

    def to_audit_payload(self) -> dict:
        """Serialize to a stable payload for agents and service wrappers."""
        findings = [
            finding.model_dump()
            for dimension in self.dimensions
            for finding in dimension.findings
        ]
        active = [finding for finding in findings if finding["disposition"] == "active"]
        severity_counts = {
            severity: sum(1 for finding in active if finding["severity"] == severity)
            for severity in ("critical", "high", "medium", "low")
        }
        risk = _risk_from_findings(severity_counts, self.overall_score)

        return {
            "summary": {
                "entity_type": self.entity_type,
                "entity_name": self.entity_name,
                "format": self.format,
                "grade": self.grade,
                "score": round(self.overall_score, 3),
                "risk": risk,
                "file_path": str(self.file_path) if self.file_path else None,
                "mode": "security" if _is_security_only(self.dimensions) else "full",
                "active_findings": len(active),
                "severity_counts": severity_counts,
            },
            "verdict": self.verdict.model_dump() if self.verdict else None,
            "dimensions": [
                {
                    "name": dimension.name,
                    "score": round(dimension.score, 3),
                    "weight": dimension.weight,
                    "findings": len(dimension.findings),
                }
                for dimension in self.dimensions
            ],
            "findings": findings,
        }


def _score_to_grade(score: float) -> str:
    """Convert a 0-1 score to a letter grade."""
    if score >= 0.9:
        return "A"
    elif score >= 0.8:
        return "B"
    elif score >= 0.65:
        return "C"
    elif score >= 0.5:
        return "D"
    else:
        return "F"


def _is_security_only(dimensions: list[ScoreDimension]) -> bool:
    return len(dimensions) == 1 and dimensions[0].name == "trust"


def _risk_from_findings(severity_counts: dict[str, int], score: float) -> str:
    if severity_counts["critical"]:
        return "critical"
    if severity_counts["high"]:
        return "high"
    if severity_counts["medium"] or score < 0.7:
        return "medium"
    return "low"
