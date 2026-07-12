"""
IAM-006: IAM credential unused for 90+ days

CIS AWS Foundations Benchmark 1.12: unused credentials should be removed
or deactivated -- they add standing attack surface without providing
any value.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule, days_since


class UnusedCredentialsRule(BaseRule):
    """Detects passwords/access keys unused for 90+ days."""

    id = "IAM-006"
    title = "IAM credential unused for 90+ days"
    description = (
        "IAM password or access key has not been used in over 90 days and "
        "should be removed or deactivated"
    )
    severity = Severity.MEDIUM
    service = "iam"
    cis_id = "1.12"

    MAX_UNUSED_DAYS = 90

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for row in context.get_credential_report_rows():
            if row.get("is_root"):
                continue

            user = row.get("user", "")
            arn = row.get("arn") or user

            if row.get("password_enabled"):
                age = days_since(row.get("password_last_used"))
                if age is not None and age > self.MAX_UNUSED_DAYS:
                    findings.append(self._create_finding(
                        resource_id=f"{arn}:password",
                        resource_type="IAM User Password",
                        risk=(
                            "An unused console password is a standing credential "
                            "that increases blast radius without providing value"
                        ),
                        evidence={"user": user, "credential_type": "password", "unused_days": age},
                        remediation=(
                            "1. Confirm the user no longer needs console access\n"
                            "2. Disable or remove the password/login profile"
                        ),
                        remediation_url=(
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                            "id_credentials_getting-report.html"
                        ),
                    ))
                    self.logger.warning(f"Unused password for {user}: {age} days")

            for key_num in (1, 2):
                if not row.get(f"access_key_{key_num}_active"):
                    continue

                # Prefer last-used date; fall back to rotation date for keys
                # that have never been used at all.
                reference = row.get(f"access_key_{key_num}_last_used") or \
                    row.get(f"access_key_{key_num}_last_rotated")
                age = days_since(reference)
                if age is not None and age > self.MAX_UNUSED_DAYS:
                    findings.append(self._create_finding(
                        resource_id=f"{arn}:access_key_{key_num}",
                        resource_type="IAM Access Key",
                        risk=(
                            "An unused access key is a standing credential that "
                            "increases blast radius without providing value"
                        ),
                        evidence={"user": user, "key_number": key_num, "unused_days": age},
                        remediation=(
                            "1. Confirm no automation depends on this key\n"
                            "2. Deactivate, then delete the unused access key"
                        ),
                        remediation_url=(
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                            "id_credentials_getting-report.html"
                        ),
                    ))
                    self.logger.warning(
                        f"Unused access key {key_num} for {user}: {age} days"
                    )

        return findings
