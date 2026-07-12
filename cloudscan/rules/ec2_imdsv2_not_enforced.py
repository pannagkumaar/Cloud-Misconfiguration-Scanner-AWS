"""
EC2-002: EC2 instance does not enforce IMDSv2

Instance Metadata Service v1 (IMDSv1) is vulnerable to SSRF-based
credential theft: a request-forwarding bug in an application on the
instance can be tricked into fetching the instance's IAM role
credentials from the metadata endpoint. IMDSv2 requires a session
token obtained via a PUT request, which most SSRF vectors can't
replicate.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class IMDSv2NotEnforcedRule(BaseRule):
    """Detects EC2 instances that don't require IMDSv2."""

    id = "EC2-002"
    title = "EC2 instance does not enforce IMDSv2"
    description = (
        "EC2 instance metadata options allow IMDSv1 (HttpTokens is not "
        "'required'), leaving it vulnerable to SSRF-based credential theft "
        "via the instance metadata service"
    )
    severity = Severity.MEDIUM
    service = "ec2"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for instance in context.get_ec2_instances():
            metadata_options = instance.get("metadata_options") or {}
            if metadata_options.get("http_tokens") == "required":
                continue

            finding = self._create_finding(
                resource_id=instance["id"],
                resource_type="EC2 Instance",
                risk=(
                    "An SSRF vulnerability in any application running on "
                    "this instance could be used to steal its IAM role "
                    "credentials via the unauthenticated IMDSv1 endpoint"
                ),
                evidence={
                    "instance_id": instance["id"],
                    "http_tokens": metadata_options.get("http_tokens", "optional"),
                },
                remediation=(
                    "1. Modify the instance metadata options to set "
                    "HttpTokens=required (enforces IMDSv2)\n"
                    "2. Update any application code that assumes IMDSv1 "
                    "before enforcing, since IMDSv2 requires a session "
                    "token\n"
                    "3. Set IMDSv2 as the default for new launch templates"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/"
                    "configuring-instance-metadata-service.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"IMDSv2 not enforced: {instance['id']}")

        return findings
