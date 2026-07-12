"""
IAM-007: Weak or missing account password policy

CIS AWS Foundations Benchmark 1.8/1.9: the account password policy should
require a strong minimum length, all character classes, and prevent
password reuse.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class WeakPasswordPolicyRule(BaseRule):
    """Detects a missing or weak account password policy."""

    id = "IAM-007"
    title = "Account password policy is weak or missing"
    description = (
        "The IAM account password policy does not meet minimum security "
        "requirements (or no custom policy is set at all)"
    )
    severity = Severity.MEDIUM
    service = "iam"
    cis_id = "1.8"

    MIN_LENGTH = 14
    MIN_REUSE_PREVENTION = 24

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []
        policy = context.get_password_policy()

        if not policy.get("exists"):
            findings.append(self._create_finding(
                resource_id="account-password-policy",
                resource_type="IAM Password Policy",
                risk=(
                    "Without a custom password policy, users can set short "
                    "or simple passwords, weakening console account security"
                ),
                evidence={"exists": False},
                remediation=(
                    "1. Set an account password policy (IAM > Account settings)\n"
                    f"2. Require minimum length >= {self.MIN_LENGTH}, all "
                    "character classes, and password reuse prevention "
                    f">= {self.MIN_REUSE_PREVENTION}"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                    "id_credentials_passwords_account-policy.html"
                ),
            ))
            self.logger.warning("No account password policy is set")
            return findings

        problems = self._find_problems(policy)
        if problems:
            findings.append(self._create_finding(
                resource_id="account-password-policy",
                resource_type="IAM Password Policy",
                risk=(
                    "A weak password policy makes console accounts easier "
                    "to compromise via brute-force or credential stuffing"
                ),
                evidence={"problems": problems},
                remediation=(
                    f"1. Update the account password policy to require length "
                    f">= {self.MIN_LENGTH}, all character classes, and reuse "
                    f"prevention >= {self.MIN_REUSE_PREVENTION}"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
                    "id_credentials_passwords_account-policy.html"
                ),
            ))
            self.logger.warning(f"Weak password policy: {problems}")

        return findings

    def _find_problems(self, policy: dict) -> List[str]:
        problems = []
        min_length = policy.get("minimum_password_length") or 0
        if min_length < self.MIN_LENGTH:
            problems.append(f"minimum length is {min_length} (should be >= {self.MIN_LENGTH})")
        if not policy.get("require_symbols"):
            problems.append("does not require symbols")
        if not policy.get("require_numbers"):
            problems.append("does not require numbers")
        if not policy.get("require_uppercase_characters"):
            problems.append("does not require uppercase characters")
        if not policy.get("require_lowercase_characters"):
            problems.append("does not require lowercase characters")
        reuse_prevention = policy.get("password_reuse_prevention") or 0
        if reuse_prevention < self.MIN_REUSE_PREVENTION:
            problems.append(
                f"reuse prevention is {reuse_prevention} "
                f"(should be >= {self.MIN_REUSE_PREVENTION})"
            )
        return problems
