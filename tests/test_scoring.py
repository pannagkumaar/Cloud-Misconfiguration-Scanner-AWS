"""
Tests for engine.scoring: risk scores must always respect severity-tier
ordering (a finding of a higher severity must always outscore any finding
of a lower severity, exposure boost or not), while still differentiating
within a tier.
"""

import itertools

import pytest

from cloudscan.engine.finding import Finding, Severity
from cloudscan.engine.scoring import (
    EXPOSURE_RULE_IDS,
    SEVERITY_BASE_SCORE,
    compute_score,
    score_findings,
)


def make_finding(rule_id="TEST-001", severity=Severity.HIGH):
    return Finding(
        rule_id=rule_id, title="t", description="d", severity=severity,
        service="test", resource_id="r1",
    )


class TestComputeScore:
    def test_score_within_0_to_100(self):
        for severity in Severity:
            for rule_id in ["NOT-EXPOSURE", *EXPOSURE_RULE_IDS]:
                score = compute_score(make_finding(rule_id=rule_id, severity=severity))
                assert 0 <= score <= 100

    def test_exposure_rule_scores_higher_than_non_exposure_same_severity(self):
        non_exposure = compute_score(make_finding(rule_id="IAM-009", severity=Severity.HIGH))
        exposure = compute_score(make_finding(rule_id="SG-001", severity=Severity.HIGH))
        assert exposure > non_exposure

    def test_unknown_rule_id_gets_no_boost(self):
        score = compute_score(make_finding(rule_id="UNKNOWN-999", severity=Severity.HIGH))
        assert score == SEVERITY_BASE_SCORE[Severity.HIGH]


class TestSeverityTierOrderingGuarantee:
    """The property that must never break: exposure-boosting a lower
    severity can never let it outscore a higher severity, boosted or not.
    """

    @pytest.mark.parametrize("lower,higher", list(itertools.combinations(
        [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL], 2
    )))
    def test_lower_tier_boosted_never_beats_higher_tier_unboosted(self, lower, higher):
        # lower comes second in the pair (itertools.combinations preserves
        # input order: INFO < LOW < MEDIUM < HIGH < CRITICAL)
        boosted_lower = compute_score(make_finding(rule_id="SG-001", severity=lower))
        unboosted_higher = compute_score(make_finding(rule_id="UNRELATED", severity=higher))
        assert boosted_lower < unboosted_higher, f"{lower} boosted ({boosted_lower}) >= {higher} unboosted ({unboosted_higher})"


class TestScoreFindings:
    def test_sets_score_on_every_finding(self):
        findings = [make_finding(rule_id="A"), make_finding(rule_id="B", severity=Severity.LOW)]
        result = score_findings(findings)
        assert all(f.score is not None for f in result)

    def test_sorts_by_score_descending(self):
        findings = [
            make_finding(rule_id="A", severity=Severity.LOW),
            make_finding(rule_id="B", severity=Severity.CRITICAL),
            make_finding(rule_id="C", severity=Severity.MEDIUM),
        ]
        result = score_findings(findings)
        scores = [f.score for f in result]
        assert scores == sorted(scores, reverse=True)
        assert result[0].rule_id == "B"  # CRITICAL first

    def test_ties_broken_by_rule_id_for_stable_output(self):
        findings = [
            make_finding(rule_id="Z-001", severity=Severity.HIGH),
            make_finding(rule_id="A-001", severity=Severity.HIGH),
        ]
        result = score_findings(findings)
        assert [f.rule_id for f in result] == ["A-001", "Z-001"]

    def test_empty_list(self):
        assert score_findings([]) == []
