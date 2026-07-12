"""
End-to-end integration test against a moto-simulated AWS account.

Unlike the unit tests (which build ScanContext directly from hand-crafted
normalized dicts) and test_integration_sample_file.py (which exercises the
file-loading path), this test runs the REAL boto3 collectors against real
boto3 API calls -- moto intercepts them before they reach the network. It
proves the collector -> normalized-context -> rule-engine pipeline works
against actual AWS API response shapes, not just our own fixtures.

No real AWS account, credentials, or cost involved.
"""


import pytest
from moto import mock_aws

from cloudscan.aws_client import AWSClient
from cloudscan.collectors.manager import CollectorManager
from cloudscan.engine.context import ScanContext
from cloudscan.engine.rule_engine import RuleEngine
from demo.seed_demo_account import (
    DEMO_POLICY,
    DEMO_USER,
    OPEN_SG_NAME,
    PUBLIC_BUCKET,
    PUBLIC_DB,
    REGION,
    RESTRICTED_SG_NAME,
    SECURE_BUCKET,
    SECURE_DB,
    seed_vulnerable_account,
)


@pytest.fixture(autouse=True)
def dummy_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@mock_aws
def _run_full_scan():
    aws_client = AWSClient(region=REGION)
    seed_vulnerable_account(aws_client)

    manager = CollectorManager(aws_client)
    collected = manager.collect_all()

    context = ScanContext("123456789012", REGION, collected)
    engine = RuleEngine()
    engine.load_rules()
    return engine.evaluate(context)


class TestMotoIntegration:
    def test_scan_completes_and_produces_findings(self):
        findings = _run_full_scan()
        assert len(findings) > 0

    def test_public_bucket_flagged(self):
        findings = _run_full_scan()
        ids = {f.resource_id for f in findings}
        assert PUBLIC_BUCKET in ids

    def test_secure_bucket_has_no_serious_findings(self):
        """SECURE_BUCKET is hardened against every *serious* gap the rules
        check (public exposure, missing encryption/versioning/TLS,
        incomplete Block Public Access). It may still trip low-severity
        best-practice advisories (e.g. access logging) -- that's a
        legitimate, real finding, not a false positive to eliminate."""
        findings = _run_full_scan()
        secure_bucket_findings = [f for f in findings if f.resource_id == SECURE_BUCKET]
        assert all(f.severity.value == "LOW" for f in secure_bucket_findings)
        assert not any(f.rule_id == "S3-001" for f in secure_bucket_findings)

    def test_open_security_group_flagged(self):
        findings = _run_full_scan()
        sg_findings = [f for f in findings if f.rule_id == "SG-001"]
        assert len(sg_findings) == 1
        assert sg_findings[0].evidence["security_group_name"] == OPEN_SG_NAME

    def test_restricted_security_group_not_flagged(self):
        findings = _run_full_scan()
        flagged_sg_names = {
            f.evidence.get("security_group_name") for f in findings if f.rule_id == "SG-001"
        }
        assert RESTRICTED_SG_NAME not in flagged_sg_names

    def test_wildcard_iam_user_and_policy_flagged(self):
        findings = _run_full_scan()
        iam_findings = [f for f in findings if f.rule_id == "IAM-001"]
        resource_ids = {f.resource_id for f in iam_findings}
        assert any(DEMO_USER in rid for rid in resource_ids)
        assert any(DEMO_POLICY in rid for rid in resource_ids)

    def test_public_unencrypted_rds_flagged_critical(self):
        findings = _run_full_scan()
        rds001_findings = [f for f in findings if f.resource_id == PUBLIC_DB and f.rule_id == "RDS-001"]
        assert len(rds001_findings) == 1
        assert rds001_findings[0].severity.value == "CRITICAL"

    def test_secure_rds_not_flagged(self):
        """SECURE_DB is hardened against every gap the RDS rules check
        (public access, encryption, backup retention, deletion
        protection, Multi-AZ, auto minor version upgrade)."""
        findings = _run_full_scan()
        secure_db_findings = [f for f in findings if f.resource_id == SECURE_DB]
        assert secure_db_findings == []

    def test_expected_rule_ids_present(self):
        findings = _run_full_scan()
        rule_ids = {f.rule_id for f in findings}
        assert {"S3-001", "SG-001", "IAM-001", "RDS-001"}.issubset(rule_ids)

    def test_no_cloudtrail_flagged_critical(self):
        """The demo account has no CloudTrail trail configured at all --
        a realistic and common real-world gap."""
        findings = _run_full_scan()
        ct001 = [f for f in findings if f.rule_id == "CT-001"]
        assert len(ct001) == 1
        assert ct001[0].severity.value == "CRITICAL"
