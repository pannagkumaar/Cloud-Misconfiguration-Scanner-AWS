"""Tests for the compliance mapping/coverage module."""

import pytest

from cloudscan.compliance.mappings import (
    build_cis_coverage,
    filter_findings_by_framework,
    format_coverage_summary,
    get_cis_mapped_rules,
)
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class _CisRuleA(BaseRule):
    id = "TEST-CIS-A"
    title = "Test CIS rule A"
    severity = Severity.HIGH
    service = "test"
    cis_id = "1.1"

    def evaluate(self, context):
        return []


class _CisRuleB(BaseRule):
    id = "TEST-CIS-B"
    title = "Test CIS rule B"
    severity = Severity.MEDIUM
    service = "test"
    cis_id = "1.1"  # same control as A -- covered by two rules

    def evaluate(self, context):
        return []


class _NoCisRule(BaseRule):
    id = "TEST-NOCIS"
    title = "Test rule with no CIS mapping"
    severity = Severity.LOW
    service = "test"
    cis_id = None

    def evaluate(self, context):
        return []


def make_finding(rule_id, severity=Severity.HIGH):
    return Finding(
        rule_id=rule_id, title="t", description="d", severity=severity,
        service="test", resource_id="r1",
    )


class TestGetCisMappedRules:
    def test_groups_by_control_id(self):
        rules = [_CisRuleA(), _CisRuleB(), _NoCisRule()]
        mapped = get_cis_mapped_rules(rules)
        assert set(mapped.keys()) == {"1.1"}
        assert len(mapped["1.1"]) == 2

    def test_rules_without_cis_id_excluded(self):
        rules = [_NoCisRule()]
        assert get_cis_mapped_rules(rules) == {}


class TestBuildCisCoverage:
    def test_control_passes_when_no_findings(self):
        rules = [_CisRuleA()]
        coverage = build_cis_coverage(rules, findings=[])
        assert len(coverage) == 1
        assert coverage[0].status == "PASS"

    def test_control_fails_when_mapped_rule_has_finding(self):
        rules = [_CisRuleA()]
        findings = [make_finding("TEST-CIS-A")]
        coverage = build_cis_coverage(rules, findings)
        assert coverage[0].status == "FAIL"
        assert coverage[0].failed_rule_ids == ["TEST-CIS-A"]

    def test_control_with_multiple_rules_lists_all(self):
        rules = [_CisRuleA(), _CisRuleB()]
        coverage = build_cis_coverage(rules, findings=[])
        assert set(coverage[0].rule_ids) == {"TEST-CIS-A", "TEST-CIS-B"}

    def test_unmapped_findings_do_not_affect_coverage(self):
        rules = [_CisRuleA()]
        findings = [make_finding("TEST-NOCIS")]  # not a CIS-mapped rule
        coverage = build_cis_coverage(rules, findings)
        assert coverage[0].status == "PASS"

    def test_sorted_numerically_by_dotted_segments(self):
        class _R110(BaseRule):
            id = "R110"
            title = "t"
            severity = Severity.LOW
            service = "test"
            cis_id = "1.10"

            def evaluate(self, context):
                return []

        class _R2(BaseRule):
            id = "R2"
            title = "t"
            severity = Severity.LOW
            service = "test"
            cis_id = "1.2"

            def evaluate(self, context):
                return []

        coverage = build_cis_coverage([_R110(), _R2()], findings=[])
        assert [c.control_id for c in coverage] == ["1.2", "1.10"]


class TestFilterFindingsByFramework:
    def test_only_mapped_findings_returned(self):
        rules = [_CisRuleA(), _NoCisRule()]
        findings = [make_finding("TEST-CIS-A"), make_finding("TEST-NOCIS")]
        result = filter_findings_by_framework(findings, rules, "cis")
        assert len(result) == 1
        assert result[0].rule_id == "TEST-CIS-A"

    def test_unknown_framework_raises(self):
        with pytest.raises(ValueError):
            filter_findings_by_framework([], [], "nist")


class TestFormatCoverageSummary:
    def test_empty_coverage_message(self):
        assert "No CIS-mapped rules" in format_coverage_summary([])

    def test_summary_includes_pass_fail_counts(self):
        rules = [_CisRuleA()]
        coverage = build_cis_coverage(rules, findings=[make_finding("TEST-CIS-A")])
        summary = format_coverage_summary(coverage)
        assert "Failed: 1" in summary
        assert "[FAIL] 1.1" in summary
