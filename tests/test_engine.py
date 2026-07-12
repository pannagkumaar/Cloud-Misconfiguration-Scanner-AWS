"""Tests for the rule engine: dynamic loading, evaluation, sorting, error isolation."""

from cloudscan.engine.finding import Severity
from cloudscan.engine.rule_engine import RuleEngine
from cloudscan.rules.base import BaseRule
from tests.conftest import make_context


class TestRuleEngineLoading:
    def test_load_rules_discovers_all_rule_files(self):
        engine = RuleEngine()
        engine.load_rules()
        rule_ids = {rule.id for rule in engine.rules}
        assert {"S3-001", "SG-001", "IAM-001", "RDS-001"}.issubset(rule_ids)

    def test_load_rules_skips_base_and_init(self):
        engine = RuleEngine()
        engine.load_rules()
        # BaseRule itself should never be instantiated as a "rule"
        assert all(rule.id != "RULE-000" for rule in engine.rules)

    def test_load_rules_produces_no_duplicate_ids(self):
        """Every rule must be loaded exactly once. Regression test for a
        real bug: cloudscan/rules/sg_any_port_open.py imported
        SecurityGroupOpenRule from sg_open_world.py to reuse a constant.
        Because that import is resolved through Python's normal import
        machinery (sg_open_world is a real installed module, independent
        of the engine's own ad-hoc file loader), the imported class showed
        up in sg_any_port_open's namespace too -- and since
        inspect.getmembers() doesn't distinguish "defined here" from
        "merely imported here", the loader instantiated SG-001 a second
        time while loading sg_any_port_open.py. Fixed by checking
        obj.__module__ == module.__name__ before instantiating."""
        engine = RuleEngine()
        engine.load_rules()
        ids = [rule.id for rule in engine.rules]
        assert len(ids) == len(set(ids)), f"duplicate rule ids: {ids}"


class _AlwaysFindsRule(BaseRule):
    id = "TEST-001"
    title = "Test rule"
    severity = Severity.LOW
    service = "test"

    def evaluate(self, context):
        return [self._create_finding(
            resource_id="r1", resource_type="test", risk="none",
            evidence={}, remediation="none",
        )]


class _AlwaysRaisesRule(BaseRule):
    id = "TEST-002"
    title = "Broken rule"
    severity = Severity.LOW
    service = "test"

    def evaluate(self, context):
        raise RuntimeError("boom")


class _CriticalRule(BaseRule):
    id = "TEST-003"
    title = "Critical rule"
    severity = Severity.CRITICAL
    service = "test"

    def evaluate(self, context):
        return [self._create_finding(
            resource_id="r2", resource_type="test", risk="none",
            evidence={}, remediation="none",
        )]


class TestRuleEngineEvaluation:
    def test_error_in_one_rule_does_not_block_others(self):
        engine = RuleEngine()
        engine.rules = [_AlwaysRaisesRule(), _AlwaysFindsRule()]
        ctx = make_context()
        findings = engine.evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "TEST-001"

    def test_findings_sorted_by_severity_critical_first(self):
        engine = RuleEngine()
        engine.rules = [_AlwaysFindsRule(), _CriticalRule()]
        ctx = make_context()
        findings = engine.evaluate(ctx)
        assert [f.rule_id for f in findings] == ["TEST-003", "TEST-001"]

    def test_get_rules_by_service(self):
        engine = RuleEngine()
        engine.rules = [_AlwaysFindsRule(), _CriticalRule()]
        assert len(engine.get_rules_by_service("test")) == 2
        assert engine.get_rules_by_service("other") == []

    def test_get_rules_by_severity(self):
        engine = RuleEngine()
        engine.rules = [_AlwaysFindsRule(), _CriticalRule()]
        assert len(engine.get_rules_by_severity(Severity.CRITICAL)) == 1
