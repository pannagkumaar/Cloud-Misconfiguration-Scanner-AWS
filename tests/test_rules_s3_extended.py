"""Tests for the expanded S3 rules: encryption, versioning, logging,
Block Public Access completeness, and TLS enforcement."""

from cloudscan.rules.s3_encryption_disabled import S3EncryptionDisabledRule
from cloudscan.rules.s3_logging_disabled import S3LoggingDisabledRule
from cloudscan.rules.s3_no_tls_enforcement import S3NoTLSEnforcementRule
from cloudscan.rules.s3_public_access_block_incomplete import S3PublicAccessBlockIncompleteRule
from cloudscan.rules.s3_versioning_disabled import S3VersioningDisabledRule
from tests.conftest import make_bucket, make_context

FULL_PAB = {
    "block_public_acls": True, "ignore_public_acls": True,
    "block_public_policy": True, "restrict_public_buckets": True,
}

TLS_DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Deny", "Principal": "*", "Action": "s3:*",
        "Resource": ["arn:aws:s3:::bucket", "arn:aws:s3:::bucket/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }],
}


def evaluate(rule_cls, bucket, s3_service):
    ctx = make_context(s3=s3_service([bucket]))
    return rule_cls().evaluate(ctx)


class TestS3EncryptionDisabledRule:
    def test_no_encryption_flagged(self, s3_service):
        bucket = make_bucket(name="b1", encryption=None)
        findings = evaluate(S3EncryptionDisabledRule, bucket, s3_service)
        assert len(findings) == 1
        assert findings[0].severity.value == "MEDIUM"

    def test_encryption_present_not_flagged(self, s3_service):
        bucket = make_bucket(name="b1", encryption={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        })
        assert evaluate(S3EncryptionDisabledRule, bucket, s3_service) == []


class TestS3VersioningDisabledRule:
    def test_no_versioning_flagged(self, s3_service):
        bucket = make_bucket(name="b1", versioning=None)
        findings = evaluate(S3VersioningDisabledRule, bucket, s3_service)
        assert len(findings) == 1
        assert findings[0].severity.value == "LOW"

    def test_suspended_versioning_flagged(self, s3_service):
        bucket = make_bucket(name="b1", versioning={"status": "Suspended", "mfa_delete": None})
        findings = evaluate(S3VersioningDisabledRule, bucket, s3_service)
        assert len(findings) == 1

    def test_enabled_versioning_not_flagged(self, s3_service):
        bucket = make_bucket(name="b1", versioning={"status": "Enabled", "mfa_delete": None})
        assert evaluate(S3VersioningDisabledRule, bucket, s3_service) == []


class TestS3LoggingDisabledRule:
    def test_no_logging_flagged(self, s3_service):
        bucket = make_bucket(name="b1", logging=None)
        findings = evaluate(S3LoggingDisabledRule, bucket, s3_service)
        assert len(findings) == 1

    def test_empty_logging_dict_flagged(self, s3_service):
        bucket = make_bucket(name="b1", logging={})
        findings = evaluate(S3LoggingDisabledRule, bucket, s3_service)
        assert len(findings) == 1

    def test_logging_enabled_not_flagged(self, s3_service):
        bucket = make_bucket(name="b1", logging={"TargetBucket": "log-bucket", "TargetPrefix": "logs/"})
        assert evaluate(S3LoggingDisabledRule, bucket, s3_service) == []


class TestS3PublicAccessBlockIncompleteRule:
    def test_partial_pab_flagged(self, s3_service):
        bucket = make_bucket(name="b1", public_access_block={
            "block_public_acls": True, "ignore_public_acls": True,
            "block_public_policy": False, "restrict_public_buckets": True,
        })
        findings = evaluate(S3PublicAccessBlockIncompleteRule, bucket, s3_service)
        assert len(findings) == 1
        assert "BlockPublicPolicy" in findings[0].evidence["missing_settings"]

    def test_full_pab_not_flagged(self, s3_service):
        bucket = make_bucket(name="b1", public_access_block=FULL_PAB)
        assert evaluate(S3PublicAccessBlockIncompleteRule, bucket, s3_service) == []

    def test_all_settings_off_flagged_with_all_four_missing(self, s3_service):
        bucket = make_bucket(name="b1", public_access_block={
            "block_public_acls": False, "ignore_public_acls": False,
            "block_public_policy": False, "restrict_public_buckets": False,
        })
        findings = evaluate(S3PublicAccessBlockIncompleteRule, bucket, s3_service)
        assert len(findings[0].evidence["missing_settings"]) == 4


class TestS3NoTLSEnforcementRule:
    def test_no_policy_flagged(self, s3_service):
        bucket = make_bucket(name="b1", policy=None)
        findings = evaluate(S3NoTLSEnforcementRule, bucket, s3_service)
        assert len(findings) == 1

    def test_policy_without_tls_deny_flagged(self, s3_service):
        bucket = make_bucket(name="b1", policy={
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:root"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b1/*"}],
        })
        findings = evaluate(S3NoTLSEnforcementRule, bucket, s3_service)
        assert len(findings) == 1

    def test_policy_with_tls_deny_not_flagged(self, s3_service):
        bucket = make_bucket(name="b1", policy=TLS_DENY_POLICY)
        assert evaluate(S3NoTLSEnforcementRule, bucket, s3_service) == []
