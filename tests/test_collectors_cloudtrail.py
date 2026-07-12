"""
Moto-based test for CloudTrailCollector + the CT-* rules, against a
deliberately misconfigured trail (single-region, no log validation, no
KMS encryption, logging stopped) -- distinct from the main demo account,
which has no trail at all (that scenario is covered by CT-001 in the
demo/moto integration suite).
"""

import pytest
from moto import mock_aws

from cloudscan.aws_client import AWSClient
from cloudscan.collectors.cloudtrail import CloudTrailCollector
from cloudscan.engine.context import ScanContext
from cloudscan.engine.rule_engine import RuleEngine

REGION = "us-east-1"
TRAIL_NAME = "misconfigured-trail"
BUCKET_NAME = "misconfigured-trail-logs"


@pytest.fixture(autouse=True)
def dummy_aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)


@mock_aws
def _seed_and_collect():
    aws_client = AWSClient(region=REGION)
    s3 = aws_client.get_client("s3")
    s3.create_bucket(Bucket=BUCKET_NAME)
    s3.put_bucket_policy(Bucket=BUCKET_NAME, Policy='{"Version": "2012-10-17", "Statement": []}')

    ct = aws_client.get_client("cloudtrail")
    ct.create_trail(
        Name=TRAIL_NAME, S3BucketName=BUCKET_NAME,
        IsMultiRegionTrail=False, EnableLogFileValidation=False,
    )
    # Deliberately never call start_logging -- trail exists but isn't logging.

    collector = CloudTrailCollector(aws_client)
    collected = {"services": ["cloudtrail"], "data": {"cloudtrail": collector.collect()}}

    context = ScanContext("123456789012", REGION, collected)
    engine = RuleEngine()
    engine.load_rules()
    return engine.evaluate(context)


class TestCloudTrailMotoIntegration:
    def test_misconfigured_trail_triggers_all_gap_rules(self):
        """Only cloudtrail service data was collected in this isolated
        test, so other services' rules (e.g. IAM-007 password policy) also
        fire against their empty defaults -- that's expected engine
        behavior, not something to suppress here. Scope the assertion to
        the CloudTrail rules under test."""
        findings = _seed_and_collect()
        ct_rule_ids = {f.rule_id for f in findings if f.service == "cloudtrail"}
        assert ct_rule_ids == {"CT-002", "CT-003", "CT-004", "CT-005"}

    def test_no_trail_rule_does_not_fire_when_trail_exists(self):
        findings = _seed_and_collect()
        assert "CT-001" not in {f.rule_id for f in findings}

    def test_severities_are_correct(self):
        findings = _seed_and_collect()
        by_id = {f.rule_id: f.severity.value for f in findings}
        assert by_id["CT-002"] == "HIGH"
        assert by_id["CT-003"] == "MEDIUM"
        assert by_id["CT-004"] == "MEDIUM"
        assert by_id["CT-005"] == "HIGH"
