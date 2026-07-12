"""
S3-002: S3 bucket does not have default encryption enabled

CIS AWS Foundations Benchmark 2.1.1: S3 buckets should have default
server-side encryption configured so objects are encrypted at rest
even if a client uploads them without specifying encryption.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class S3EncryptionDisabledRule(BaseRule):
    """Detects S3 buckets without default server-side encryption."""

    id = "S3-002"
    title = "S3 bucket does not have default encryption enabled"
    description = (
        "S3 bucket has no default server-side encryption configuration, "
        "so objects uploaded without explicit encryption are stored in "
        "plaintext"
    )
    severity = Severity.MEDIUM
    service = "s3"
    cis_id = "2.1.1"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for bucket in context.get_s3_buckets():
            if bucket.get("encryption"):
                continue

            finding = self._create_finding(
                resource_id=bucket["name"],
                resource_type="S3 Bucket",
                risk=(
                    "Objects stored without encryption at rest are exposed "
                    "if the underlying storage is ever accessed directly"
                ),
                evidence={"bucket_name": bucket["name"], "encryption": None},
                remediation=(
                    "1. Enable default encryption on the bucket "
                    "(SSE-S3 or SSE-KMS)\n"
                    "2. Consider a bucket policy that denies unencrypted "
                    "PutObject requests"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
                    "bucket-encryption.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"No default encryption: {bucket['name']}")

        return findings
