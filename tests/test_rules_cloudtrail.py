"""Tests for the CloudTrail rules: trail existence, multi-region, log
file validation, KMS encryption, and active logging status."""

from cloudscan.rules.cloudtrail_log_validation_disabled import LogFileValidationDisabledRule
from cloudscan.rules.cloudtrail_logging_stopped import TrailLoggingStoppedRule
from cloudscan.rules.cloudtrail_no_trail import NoCloudTrailRule
from cloudscan.rules.cloudtrail_not_encrypted import TrailNotEncryptedRule
from cloudscan.rules.cloudtrail_not_multi_region import NoMultiRegionTrailRule
from tests.conftest import make_context


def trail(**overrides):
    base = {
        "name": "org-trail", "arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail",
        "is_multi_region_trail": True, "log_file_validation_enabled": True,
        "kms_key_id": "arn:aws:kms:us-east-1:123456789012:key/abc", "is_logging": True,
        "s3_bucket_name": "org-trail-logs", "include_global_service_events": True,
    }
    base.update(overrides)
    return base


def cloudtrail_service(trails):
    return {"service": "cloudtrail", "trails": trails}


class TestNoCloudTrailRule:
    def test_no_trails_flagged_critical(self):
        ctx = make_context(cloudtrail=cloudtrail_service([]))
        findings = NoCloudTrailRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "CRITICAL"
        assert findings[0].resource_id == "account"

    def test_trail_exists_not_flagged(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail()]))
        assert NoCloudTrailRule().evaluate(ctx) == []


class TestNoMultiRegionTrailRule:
    def test_no_trails_not_flagged_here(self):
        """Total absence is CT-001's territory, not this rule's."""
        ctx = make_context(cloudtrail=cloudtrail_service([]))
        assert NoMultiRegionTrailRule().evaluate(ctx) == []

    def test_single_region_trail_flagged(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail(is_multi_region_trail=False)]))
        findings = NoMultiRegionTrailRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_one_multi_region_trail_among_many_satisfies(self):
        ctx = make_context(cloudtrail=cloudtrail_service([
            trail(name="regional", is_multi_region_trail=False),
            trail(name="global", is_multi_region_trail=True),
        ]))
        assert NoMultiRegionTrailRule().evaluate(ctx) == []


class TestLogFileValidationDisabledRule:
    def test_disabled_flagged(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail(log_file_validation_enabled=False)]))
        findings = LogFileValidationDisabledRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_enabled_not_flagged(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail(log_file_validation_enabled=True)]))
        assert LogFileValidationDisabledRule().evaluate(ctx) == []


class TestTrailNotEncryptedRule:
    def test_no_kms_key_flagged(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail(kms_key_id=None)]))
        findings = TrailNotEncryptedRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_kms_key_present_not_flagged(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail(kms_key_id="arn:aws:kms:...")]))
        assert TrailNotEncryptedRule().evaluate(ctx) == []


class TestTrailLoggingStoppedRule:
    def test_not_logging_flagged(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail(is_logging=False)]))
        findings = TrailLoggingStoppedRule().evaluate(ctx)
        assert len(findings) == 1
        assert findings[0].severity.value == "HIGH"

    def test_actively_logging_not_flagged(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail(is_logging=True)]))
        assert TrailLoggingStoppedRule().evaluate(ctx) == []


class TestFullyCompliantTrail:
    def test_well_configured_trail_triggers_nothing(self):
        ctx = make_context(cloudtrail=cloudtrail_service([trail()]))
        all_findings = (
            NoCloudTrailRule().evaluate(ctx)
            + NoMultiRegionTrailRule().evaluate(ctx)
            + LogFileValidationDisabledRule().evaluate(ctx)
            + TrailNotEncryptedRule().evaluate(ctx)
            + TrailLoggingStoppedRule().evaluate(ctx)
        )
        assert all_findings == []
