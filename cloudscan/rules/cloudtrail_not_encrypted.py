"""
CT-004: CloudTrail trail is not encrypted with KMS

CIS AWS Foundations Benchmark 3.7: CloudTrail logs often contain
sensitive details about account activity (resource names, IAM
principals, source IPs). SSE-KMS encryption adds an additional access
control layer beyond the S3 bucket policy alone.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class TrailNotEncryptedRule(BaseRule):
    """Detects CloudTrail trails without SSE-KMS encryption configured."""

    id = "CT-004"
    title = "CloudTrail trail is not encrypted with KMS"
    description = (
        "CloudTrail trail does not have SSE-KMS encryption configured, "
        "relying solely on the destination S3 bucket's access controls "
        "to protect potentially sensitive log content"
    )
    severity = Severity.MEDIUM
    service = "cloudtrail"
    cis_id = "3.7"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for trail in context.get_cloudtrail_trails():
            if trail.get("kms_key_id"):
                continue

            finding = self._create_finding(
                resource_id=trail.get("arn") or trail.get("name", ""),
                resource_type="CloudTrail Trail",
                risk=(
                    "Log files containing account activity details are "
                    "protected only by S3 bucket policy, with no "
                    "additional key-based access control layer"
                ),
                evidence={"trail_name": trail.get("name"), "kms_key_id": None},
                remediation=(
                    "1. Create or choose a KMS key for CloudTrail\n"
                    "2. Update the trail to use SSE-KMS encryption with "
                    "that key\n"
                    "3. Restrict key usage to the CloudTrail service and "
                    "authorized log readers"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
                    "encrypting-cloudtrail-log-files-with-aws-kms.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Trail not KMS-encrypted: {trail.get('name')}")

        return findings
