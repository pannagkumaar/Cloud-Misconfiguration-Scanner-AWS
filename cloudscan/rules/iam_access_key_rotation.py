"""
IAM-005: IAM access key not rotated in 90+ days

CIS AWS Foundations Benchmark 1.14: access keys should be rotated
regularly to limit the exposure window if a key is ever leaked.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule, days_since


class AccessKeyRotationRule(BaseRule):
    """Detects active access keys older than 90 days."""

    id = "IAM-005"
    title = "IAM access key has not been rotated in 90+ days"
    description = (
        "IAM access key is older than 90 days without rotation, increasing "
        "the exposure window if the key has been leaked"
    )
    severity = Severity.MEDIUM
    service = "iam"
    cis_id = "1.14"

    MAX_AGE_DAYS = 90

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for row in context.get_credential_report_rows():
            user = row.get("user", "")
            arn = row.get("arn") or user

            for key_num in (1, 2):
                if not row.get(f"access_key_{key_num}_active"):
                    continue

                age = days_since(row.get(f"access_key_{key_num}_last_rotated"))
                if age is not None and age > self.MAX_AGE_DAYS:
                    finding = self._create_finding(
                        resource_id=f"{arn}:access_key_{key_num}",
                        resource_type="IAM Access Key",
                        risk=(
                            "An access key that has never been rotated increases "
                            "the impact window if it is ever leaked -- the older "
                            "the key, the more likely it has been exposed in logs, "
                            "repos, or backups"
                        ),
                        evidence={"user": user, "key_number": key_num, "age_days": age},
                        remediation=(
                            "1. Create a new access key\n"
                            "2. Update applications/scripts to use the new key\n"
                            "3. Deactivate, then delete the old key\n"
                            "4. Automate rotation going forward"
                        ),
                        remediation_url=(
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                            "id_credentials_access-keys.html#Using_RotateAccessKey"
                        ),
                    )
                    findings.append(finding)
                    self.logger.warning(
                        f"Access key {key_num} for {user} is {age} days old"
                    )

        return findings
