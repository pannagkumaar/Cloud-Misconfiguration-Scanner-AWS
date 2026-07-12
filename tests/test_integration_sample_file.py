"""
End-to-end regression test: scanning examples/sample-aws-config.json.

This is the exact scenario that used to silently produce 0 findings,
because the raw AWS export shape didn't match what rules expected. Pins
the fix in place: the sample file's known-bad resources must be flagged,
and its known-good resources must not be.
"""

from pathlib import Path

from cloudscan.engine.context import ScanContext
from cloudscan.engine.rule_engine import RuleEngine
from cloudscan.loaders.file_loader import FileLoader

SAMPLE_FILE = Path(__file__).parent.parent / "examples" / "sample-aws-config.json"


def _scan_sample():
    loader = FileLoader(str(SAMPLE_FILE))
    data = loader.load()
    ctx = ScanContext("unknown", "unknown", data)
    engine = RuleEngine()
    engine.load_rules()
    return engine.evaluate(ctx)


def test_sample_file_produces_findings():
    findings = _scan_sample()
    assert len(findings) > 0, "offline scan of the sample file regressed to 0 findings"


def test_sample_file_flags_known_bad_resources():
    findings = _scan_sample()
    flagged = {f.resource_id for f in findings}

    assert "public-logs-bucket" in flagged
    assert "sg-0123456789abcdef0" in flagged
    assert "prod-mysql-db" in flagged
    assert "arn:aws:iam::123456789012:policy/admin-access" in flagged


def test_sample_file_does_not_flag_known_good_resources():
    findings = _scan_sample()
    flagged = {f.resource_id for f in findings}

    assert "private-data-bucket" not in flagged
    assert "sg-0987654321fedcba0" not in flagged  # db-tier-sg, restricted CIDR
    assert "dev-postgres-db" not in flagged


def test_sample_file_rds_finding_is_critical():
    findings = _scan_sample()
    rds001_findings = [f for f in findings if f.resource_id == "prod-mysql-db" and f.rule_id == "RDS-001"]
    assert len(rds001_findings) == 1
    assert rds001_findings[0].severity.value == "CRITICAL"
