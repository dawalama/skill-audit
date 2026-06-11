"""Spec for folding LLM review findings into the verdict (issue #2 follow-up).

The optional --llm semantic review used to be display-only. Its findings now feed
the verdict — but only to ADD scrutiny. The semantic layer can escalate the
recommendation/malice; it can never downgrade them (a clean LLM pass is not
evidence of safety, mirroring the static "never trust provenance" rule).
"""

from skill_audit.llm_reviewer import LLMFinding
from skill_audit.models import AuditVerdict
from skill_audit.verdict import fold_llm_findings


def _verdict(recommendation="allow", malice="low", intent=False):
    return AuditVerdict(
        recommendation=recommendation,
        malice_indicators=malice,
        intent_mismatch=intent,
        summary=f"{recommendation}: profile=general, malice={malice}, capability=low",
    )


def _f(category, severity="high"):
    return LLMFinding(category=category, severity=severity, message="x")


class TestEscalation:
    def test_injection_blocks(self):
        v = fold_llm_findings(_verdict("allow"), [_f("INJECTION", "critical")])
        assert v.recommendation == "block"
        assert v.malice_indicators == "high"

    def test_hidden_behaviour_escalates(self):
        v = fold_llm_findings(_verdict("allow"), [_f("HIDDEN_BEHAVIOR", "high")])
        assert v.recommendation == "human_review"
        assert v.malice_indicators in {"medium", "high"}

    def test_intent_mismatch_sets_flag_and_reviews(self):
        v = fold_llm_findings(_verdict("warn"), [_f("INTENT_MISMATCH", "high")])
        assert v.intent_mismatch is True
        assert v.recommendation == "human_review"

    def test_reason_is_recorded(self):
        v = fold_llm_findings(_verdict("allow"), [_f("INTENT_MISMATCH", "high")])
        assert any("llm" in r.lower() for r in v.reasons)

    def test_summary_reflects_new_recommendation(self):
        v = fold_llm_findings(_verdict("allow", malice="low"), [_f("INJECTION", "critical")])
        assert v.summary.startswith("block:")
        assert "malice=high" in v.summary


class TestNeverDowngrades:
    def test_block_stays_block(self):
        v = fold_llm_findings(_verdict("block", malice="high"), [_f("QUALITY", "low")])
        assert v.recommendation == "block"
        assert v.malice_indicators == "high"

    def test_human_review_not_downgraded_by_lesser_signal(self):
        v = fold_llm_findings(_verdict("human_review"), [_f("INTENT_MISMATCH", "high")])
        assert v.recommendation == "human_review"  # not "warn"/"allow"


class TestOnlyStrongFindingsCount:
    def test_low_severity_intent_mismatch_ignored(self):
        v = fold_llm_findings(_verdict("allow"), [_f("INTENT_MISMATCH", "low")])
        assert v.recommendation == "allow"
        assert v.intent_mismatch is False

    def test_quality_findings_never_touch_trust(self):
        v = fold_llm_findings(_verdict("allow"), [_f("QUALITY", "critical")])
        assert v.recommendation == "allow"


class TestGuards:
    def test_none_verdict(self):
        assert fold_llm_findings(None, [_f("INJECTION", "critical")]) is None

    def test_empty_findings_unchanged(self):
        base = _verdict("allow")
        assert fold_llm_findings(base, []) is base
