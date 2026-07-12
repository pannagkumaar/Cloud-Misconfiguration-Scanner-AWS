"""
IAM-002: Root account MFA disabled

CIS AWS Foundations Benchmark 1.5: ensure MFA is enabled for the root
account. The root user cannot be restricted by IAM policy, so a leaked
root password alone is enough to compromise the entire account.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class RootMFADisabledRule(BaseRule):
    """Detects a root account without MFA enabled."""

    id = "IAM-002"
    title = "Root account does not have MFA enabled"
    description = (
        "The AWS account root user does not have multi-factor authentication "
        "enabled, leaving the most privileged identity in the account "
        "protected by only a single credential"
    )
    severity = Severity.CRITICAL
    service = "iam"
    cis_id = "1.5"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []
        root = context.get_root_credential_row()
        if root is None:
            # No credential report data available (e.g. offline scan of a
            # partial export) -- nothing to evaluate, not a "pass".
            return findings

        if not root.get("mfa_active", False):
            finding = self._create_finding(
                resource_id=root.get("arn") or "root",
                resource_type="AWS Account Root User",
                risk=(
                    "Root account compromise via a leaked or brute-forced "
                    "password alone would grant complete, unrestrictable "
                    "control of the AWS account"
                ),
                evidence={"mfa_active": False},
                remediation=(
                    "1. Sign in to the AWS Management Console as root\n"
                    "2. Enable a hardware or virtual MFA device on the root user\n"
                    "3. Store the MFA device securely, separate from root credentials\n"
                    "4. Avoid using the root account for day-to-day tasks"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                    "id_root-user.html#id_root-user_manage_mfa"
                ),
            )
            findings.append(finding)
            self.logger.warning("Root account does not have MFA enabled")

        return findings
