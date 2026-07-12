"""
CT-001: No CloudTrail trail exists in the account

CIS AWS Foundations Benchmark 3.1 (existence check): without any
CloudTrail trail, there is no record of API activity in the account at
all -- no way to investigate an incident, detect unauthorized changes,
or prove what happened after the fact.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class NoCloudTrailRule(BaseRule):
    """Detects an account with no CloudTrail trail configured at all."""

    id = "CT-001"
    title = "No CloudTrail trail exists in the account"
    description = (
        "The account has no CloudTrail trail configured, so there is no "
        "audit log of API activity to investigate after an incident"
    )
    severity = Severity.CRITICAL
    service = "cloudtrail"
    cis_id = "3.1"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        trails = context.get_cloudtrail_trails()
        if trails:
            return []

        finding = self._create_finding(
            resource_id="account",
            resource_type="AWS Account",
            risk=(
                "Without any trail, a compromised credential, misconfigured "
                "resource, or insider action leaves no audit record -- "
                "incident response has nothing to investigate"
            ),
            evidence={"trail_count": 0},
            remediation=(
                "1. Create a CloudTrail trail covering all regions\n"
                "2. Enable log file validation and SSE-KMS encryption\n"
                "3. Send logs to a dedicated, access-restricted S3 bucket"
            ),
            remediation_url=(
                "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
                "cloudtrail-create-a-trail-using-the-console-first-time.html"
            ),
        )
        self.logger.warning("No CloudTrail trail exists in the account")
        return [finding]
