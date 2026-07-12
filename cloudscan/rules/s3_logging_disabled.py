"""
S3-004: S3 bucket access logging is disabled

Server access logging provides an audit trail of who accessed a
bucket's objects and when -- essential for detecting and investigating
unauthorized access.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class S3LoggingDisabledRule(BaseRule):
    """Detects S3 buckets without server access logging enabled."""

    id = "S3-004"
    title = "S3 bucket access logging is disabled"
    description = (
        "S3 bucket does not have server access logging enabled, so there "
        "is no audit trail of requests made against it"
    )
    severity = Severity.LOW
    service = "s3"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for bucket in context.get_s3_buckets():
            if bucket.get("logging"):
                continue

            finding = self._create_finding(
                resource_id=bucket["name"],
                resource_type="S3 Bucket",
                risk=(
                    "Without access logging, unauthorized or anomalous "
                    "access to this bucket's objects cannot be detected "
                    "or investigated after the fact"
                ),
                evidence={"bucket_name": bucket["name"], "logging_enabled": False},
                remediation=(
                    "1. Enable server access logging on the bucket\n"
                    "2. Send logs to a dedicated, access-restricted logging bucket\n"
                    "3. Consider AWS CloudTrail data events for API-level "
                    "audit logging as well"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
                    "ServerLogs.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Access logging disabled: {bucket['name']}")

        return findings
