"""
S3-005: S3 bucket does not have all Block Public Access settings enabled

Defense-in-depth check, distinct from S3-001 (which only fires when a
policy/ACL is *currently* granting public access). This fires whenever
any of the four Block Public Access settings is off, even for a bucket
that happens to be private today -- so a future policy/ACL change can't
silently make it public.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule

PAB_SETTINGS = [
    ("block_public_acls", "BlockPublicAcls"),
    ("ignore_public_acls", "IgnorePublicAcls"),
    ("block_public_policy", "BlockPublicPolicy"),
    ("restrict_public_buckets", "RestrictPublicBuckets"),
]


class S3PublicAccessBlockIncompleteRule(BaseRule):
    """Detects S3 buckets without all four Block Public Access settings on."""

    id = "S3-005"
    title = "S3 bucket does not have all Block Public Access settings enabled"
    description = (
        "S3 bucket has one or more Block Public Access settings disabled, "
        "leaving it one policy or ACL change away from becoming public"
    )
    severity = Severity.MEDIUM
    service = "s3"
    cis_id = "2.1.5.1"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for bucket in context.get_s3_buckets():
            pab = bucket.get("public_access_block") or {}
            missing = [
                label for key, label in PAB_SETTINGS if not pab.get(key)
            ]
            if not missing:
                continue

            finding = self._create_finding(
                resource_id=bucket["name"],
                resource_type="S3 Bucket",
                risk=(
                    "Any of these settings being off means a future policy "
                    "or ACL change could expose this bucket to the internet "
                    "without any additional safeguard catching it"
                ),
                evidence={"bucket_name": bucket["name"], "missing_settings": missing},
                remediation=(
                    "1. Enable all four Block Public Access settings for "
                    "the bucket (or the whole account, if no bucket needs "
                    "to be public)\n"
                    "2. If a bucket genuinely needs to be public, document "
                    "why and restrict it to the minimum required actions"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
                    "access-control-block-public-access.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(
                f"Incomplete Block Public Access on {bucket['name']}: {missing}"
            )

        return findings
