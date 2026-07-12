"""
S3-003: S3 bucket versioning is disabled

Versioning protects against accidental deletion/overwrite and is a
prerequisite for reliable ransomware/data-loss recovery.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class S3VersioningDisabledRule(BaseRule):
    """Detects S3 buckets without versioning enabled."""

    id = "S3-003"
    title = "S3 bucket versioning is disabled"
    description = (
        "S3 bucket does not have versioning enabled, so accidental or "
        "malicious deletion/overwrite of objects cannot be recovered from"
    )
    severity = Severity.LOW
    service = "s3"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for bucket in context.get_s3_buckets():
            versioning = bucket.get("versioning") or {}
            if versioning.get("status") == "Enabled":
                continue

            finding = self._create_finding(
                resource_id=bucket["name"],
                resource_type="S3 Bucket",
                risk=(
                    "Without versioning, an accidental delete/overwrite "
                    "(or a compromised credential doing so deliberately) "
                    "is unrecoverable"
                ),
                evidence={
                    "bucket_name": bucket["name"],
                    "versioning_status": versioning.get("status"),
                },
                remediation=(
                    "1. Enable versioning on the bucket\n"
                    "2. Consider MFA Delete for buckets holding critical data\n"
                    "3. Pair with a lifecycle policy to manage noncurrent "
                    "version storage costs"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
                    "Versioning.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Versioning disabled: {bucket['name']}")

        return findings
