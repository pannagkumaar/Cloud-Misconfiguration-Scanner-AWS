"""
IAM-003: Root account has an active access key

CIS AWS Foundations Benchmark 1.4: the root user should never have
programmatic access keys. Root keys cannot be scoped by policy, so a
leaked root key is equivalent to a full account takeover.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class RootAccessKeyRule(BaseRule):
    """Detects an active access key on the root account."""

    id = "IAM-003"
    title = "Root account has an active access key"
    description = (
        "The AWS account root user has at least one active access key, "
        "which should never be used for programmatic access"
    )
    severity = Severity.CRITICAL
    service = "iam"
    cis_id = "1.4"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []
        root = context.get_root_credential_row()
        if root is None:
            return findings

        key1_active = root.get("access_key_1_active", False)
        key2_active = root.get("access_key_2_active", False)

        if key1_active or key2_active:
            finding = self._create_finding(
                resource_id=root.get("arn") or "root",
                resource_type="AWS Account Root User",
                risk=(
                    "An exposed root access key grants unrestricted, "
                    "unrecoverable-by-policy access to the entire account "
                    "and cannot be scoped down like an IAM user's permissions"
                ),
                evidence={
                    "access_key_1_active": key1_active,
                    "access_key_2_active": key2_active,
                },
                remediation=(
                    "1. Sign in to the AWS Management Console as root\n"
                    "2. Delete all root account access keys\n"
                    "3. Use IAM users or roles with least-privilege policies "
                    "for programmatic access instead"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                    "id_root-user.html#id_root-user_manage_add-key"
                ),
            )
            findings.append(finding)
            self.logger.warning("Root account has an active access key")

        return findings
