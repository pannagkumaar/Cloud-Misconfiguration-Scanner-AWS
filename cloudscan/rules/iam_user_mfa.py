"""
IAM-004: IAM user has console access without MFA

CIS AWS Foundations Benchmark 1.10: users with a console password should
also have MFA enabled, so console sign-in isn't protected by password alone.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class UserMFADisabledRule(BaseRule):
    """Detects IAM users with a console password but no active MFA device."""

    id = "IAM-004"
    title = "IAM user has console access without MFA"
    description = (
        "IAM user has a console password enabled but no MFA device active, "
        "so console sign-in is protected by password alone"
    )
    severity = Severity.HIGH
    service = "iam"
    cis_id = "1.10"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for row in context.get_credential_report_rows():
            if row.get("is_root"):
                continue  # covered separately by IAM-002

            if row.get("password_enabled") and not row.get("mfa_active"):
                finding = self._create_finding(
                    resource_id=row.get("arn") or row.get("user", ""),
                    resource_type="IAM User",
                    risk=(
                        "Console sign-in relies on a single factor, enabling "
                        "account takeover from a leaked or brute-forced password"
                    ),
                    evidence={
                        "user": row.get("user"),
                        "password_enabled": True,
                        "mfa_active": False,
                    },
                    remediation=(
                        "1. Ask the user to enable a virtual or hardware MFA device\n"
                        "2. Enforce MFA account-wide via an IAM policy condition "
                        "(aws:MultiFactorAuthPresent)\n"
                        "3. Consider requiring MFA for all console users"
                    ),
                    remediation_url=(
                        "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                        "id_credentials_mfa_enable_virtual.html"
                    ),
                )
                findings.append(finding)
                self.logger.warning(
                    f"IAM user has console access without MFA: {row.get('user')}"
                )

        return findings
