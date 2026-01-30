"""
Base rule class - Abstract class for all security rules.

Each rule:
1. Defines metadata (ID, severity, CIS reference)
2. Evaluates a specific security configuration
3. Generates findings with evidence and remediation
"""

from abc import ABC, abstractmethod
from typing import List, Optional
import logging
from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity


class BaseRule(ABC):
    """Abstract base class for security rules."""

    # Override in subclass
    id: str = "RULE-000"                     # e.g., "S3-001", "CIS-1.1"
    title: str = "Undefined Rule"
    description: str = "Rule description"
    severity: Severity = Severity.INFO
    service: str = "unknown"                 # iam, s3, ec2, rds
    cis_id: Optional[str] = None            # CIS benchmark reference

    def __init__(self):
        """Initialize rule."""
        self.logger = logging.getLogger(f"cloudscan.rules.{self.id}")

    @abstractmethod
    def evaluate(self, context: ScanContext) -> List[Finding]:
        """
        Evaluate this rule against the scan context.

        Args:
            context: ScanContext with collected AWS data

        Returns:
            List of findings (empty if no issues found)
        """
        pass

    def _create_finding(
        self,
        resource_id: str,
        resource_type: str,
        risk: str,
        evidence: dict,
        remediation: str,
        remediation_url: str = "",
    ) -> Finding:
        """
        Create a finding from this rule.

        Args:
            resource_id: ID of the affected resource
            resource_type: Type of resource (bucket, security_group, etc.)
            risk: Description of the risk
            evidence: Dictionary with evidence data
            remediation: Remediation steps
            remediation_url: Optional AWS documentation link

        Returns:
            Finding instance
        """
        return Finding(
            rule_id=self.id,
            title=self.title,
            description=self.description,
            severity=self.severity,
            service=self.service,
            cis_id=self.cis_id,
            resource_id=resource_id,
            resource_type=resource_type,
            risk=risk,
            evidence=evidence,
            remediation=remediation,
            remediation_url=remediation_url,
        )

    def __repr__(self) -> str:
        return f"<Rule {self.id} ({self.severity.value})>"
