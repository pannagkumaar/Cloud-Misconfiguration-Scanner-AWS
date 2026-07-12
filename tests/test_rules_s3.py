"""Tests for S3-001: public S3 bucket detection."""

from cloudscan.rules.s3_public_bucket import S3PublicBucketRule
from tests.conftest import make_bucket, make_context, public_policy_statement


def evaluate(bucket, s3_service):
    ctx = make_context(s3=s3_service([bucket]))
    return S3PublicBucketRule().evaluate(ctx)


class TestS3PublicBucketRule:
    def test_public_policy_flagged(self, s3_service):
        bucket = make_bucket(
            name="leaky-bucket",
            policy=public_policy_statement("leaky-bucket"),
            public_access_block={
                "block_public_acls": False, "ignore_public_acls": False,
                "block_public_policy": False, "restrict_public_buckets": False,
            },
        )
        findings = evaluate(bucket, s3_service)
        assert len(findings) == 1
        assert findings[0].rule_id == "S3-001"
        assert findings[0].resource_id == "leaky-bucket"
        assert findings[0].severity.value == "HIGH"

    def test_fully_blocked_bucket_not_flagged(self, s3_service):
        bucket = make_bucket(name="safe-bucket")  # default PAB is fully blocked
        findings = evaluate(bucket, s3_service)
        assert findings == []

    def test_public_acl_flagged(self, s3_service):
        bucket = make_bucket(
            name="acl-bucket",
            acl={"owner": {}, "grants": [
                {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}
            ]},
            public_access_block={
                "block_public_acls": False, "ignore_public_acls": False,
                "block_public_policy": False, "restrict_public_buckets": False,
            },
        )
        findings = evaluate(bucket, s3_service)
        assert len(findings) == 1

    def test_bucket_with_no_acl_or_policy_does_not_crash(self, s3_service):
        """Regression test: bucket.get('acl', {}) used to crash when acl was
        explicitly None (as normalized data produces for buckets with no
        ACL data), because dict.get(key, default) returns the stored None,
        not the default."""
        bucket = make_bucket(
            name="no-data-bucket",
            acl=None,
            policy=None,
            public_access_block={
                "block_public_acls": False, "ignore_public_acls": False,
                "block_public_policy": False, "restrict_public_buckets": False,
            },
        )
        findings = evaluate(bucket, s3_service)
        assert findings == []  # no evidence of public access -> not flagged

    def test_no_findings_across_multiple_secure_buckets(self, s3_service):
        buckets = [make_bucket(name=f"bucket-{i}") for i in range(3)]
        ctx = make_context(s3=s3_service(buckets))
        findings = S3PublicBucketRule().evaluate(ctx)
        assert findings == []

    def test_evidence_includes_bucket_name_and_pab_status(self, s3_service):
        bucket = make_bucket(
            name="evidence-bucket",
            policy=public_policy_statement("evidence-bucket"),
            public_access_block={
                "block_public_acls": False, "ignore_public_acls": False,
                "block_public_policy": False, "restrict_public_buckets": False,
            },
        )
        findings = evaluate(bucket, s3_service)
        assert findings[0].evidence["bucket_name"] == "evidence-bucket"
        assert "public_block_status" in findings[0].evidence
