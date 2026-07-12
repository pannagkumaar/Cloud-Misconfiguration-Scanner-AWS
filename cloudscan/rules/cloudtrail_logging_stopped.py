"""
CT-005: CloudTrail trail exists but is not actively logging

A trail can be correctly configured yet have logging stopped (e.g. via
StopLogging), which looks identical to "properly monitored" in
every way except the one that matters -- it silently stops recording
API activity.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class TrailLoggingStoppedRule(BaseRule):
    """Detects CloudTrail trails that exist but aren't actively logging."""

    id = "CT-005"
    title = "CloudTrail trail is not actively logging"
    description = (
        "CloudTrail trail is configured but logging has been stopped, so "
        "it is not actually recording API activity despite existing"
    )
    severity = Severity.HIGH
    service = "cloudtrail"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for trail in context.get_cloudtrail_trails():
            if trail.get("is_logging"):
                continue

            finding = self._create_finding(
                resource_id=trail.get("arn") or trail.get("name", ""),
                resource_type="CloudTrail Trail",
                risk=(
                    "This trail gives a false sense of coverage: it "
                    "exists and appears configured, but StopLogging has "
                    "been called (accidentally or by an attacker covering "
                    "their tracks) and no activity is being recorded"
                ),
                evidence={"trail_name": trail.get("name"), "is_logging": False},
                remediation=(
                    "1. Investigate why logging was stopped -- this may "
                    "itself be a sign of compromise\n"
                    "2. Re-enable logging via StartLogging\n"
                    "3. Alert on cloudtrail:StopLogging API calls going forward"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
                    "cloudtrail-working-with-log-files.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Trail exists but is not logging: {trail.get('name')}")

        return findings
