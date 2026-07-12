"""
CT-003: CloudTrail log file validation is disabled

CIS AWS Foundations Benchmark 3.2: log file validation adds a digital
signature to delivered log files, so tampering (e.g. an attacker
covering their tracks after a compromise) can be detected.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class LogFileValidationDisabledRule(BaseRule):
    """Detects CloudTrail trails without log file validation enabled."""

    id = "CT-003"
    title = "CloudTrail log file validation is disabled"
    description = (
        "CloudTrail trail does not have log file validation enabled, so "
        "tampering with delivered log files cannot be detected"
    )
    severity = Severity.MEDIUM
    service = "cloudtrail"
    cis_id = "3.2"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for trail in context.get_cloudtrail_trails():
            if trail.get("log_file_validation_enabled"):
                continue

            finding = self._create_finding(
                resource_id=trail.get("arn") or trail.get("name", ""),
                resource_type="CloudTrail Trail",
                risk=(
                    "Without log file validation, an attacker with access "
                    "to the log bucket could alter or delete log entries "
                    "to cover their tracks, and it would go unnoticed"
                ),
                evidence={"trail_name": trail.get("name"), "log_file_validation_enabled": False},
                remediation=(
                    "1. Enable log file validation on the trail\n"
                    "2. Periodically verify log integrity using the "
                    "CloudTrail validate-logs CLI command"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
                    "cloudtrail-log-file-validation-enabling.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Log file validation disabled: {trail.get('name')}")

        return findings
