"""
S3-006: S3 bucket policy does not enforce TLS

Without a policy statement denying non-HTTPS requests
(aws:SecureTransport=false), requests to the bucket can be made over
plain HTTP, exposing data and credentials in transit.
"""

from typing import Any, Dict, List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class S3NoTLSEnforcementRule(BaseRule):
    """Detects S3 buckets whose policy doesn't deny non-TLS requests."""

    id = "S3-006"
    title = "S3 bucket policy does not enforce TLS"
    description = (
        "S3 bucket policy has no statement denying requests made without "
        "TLS (aws:SecureTransport=false), allowing data and credentials "
        "to be sent in plaintext over HTTP"
    )
    severity = Severity.MEDIUM
    service = "s3"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for bucket in context.get_s3_buckets():
            if self._enforces_tls(bucket.get("policy")):
                continue

            finding = self._create_finding(
                resource_id=bucket["name"],
                resource_type="S3 Bucket",
                risk=(
                    "Requests made over plain HTTP can be intercepted on "
                    "the network, exposing object data and any credentials "
                    "included in the request"
                ),
                evidence={"bucket_name": bucket["name"], "enforces_tls": False},
                remediation=(
                    "1. Add a bucket policy statement that denies all "
                    "actions when aws:SecureTransport is false\n"
                    "2. Verify no legitimate clients still rely on "
                    "unencrypted HTTP access before enforcing"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
                    "security-best-practices.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"No TLS enforcement: {bucket['name']}")

        return findings

    @staticmethod
    def _enforces_tls(policy: Any) -> bool:
        if not policy:
            return False

        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Deny":
                continue

            condition = statement.get("Condition", {})
            secure_transport = S3NoTLSEnforcementRule._get_secure_transport(condition)
            if secure_transport in (False, "false"):
                return True

        return False

    @staticmethod
    def _get_secure_transport(condition: Dict[str, Any]):
        # AWS accepts both "Bool" and "NumericLessThan"-style operators for
        # this condition key in practice; "Bool" is the documented one.
        bool_condition = condition.get("Bool", {})
        return bool_condition.get("aws:SecureTransport")
