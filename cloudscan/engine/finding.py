"""
Finding data class - Represents a single security finding.

A finding is the output of a rule evaluation. It includes:
- What was found (resource, rule ID)
- Why it's a problem (risk, severity)
- Evidence (what was observed)
- How to fix it (remediation)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional
from datetime import datetime


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a single security finding."""

    # Identification
    rule_id: str                        # e.g., "S3-001", "CIS-1.1"
    title: str                          # Short description
    description: str                    # Longer explanation

    # Classification
    severity: Severity                  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    service: str                        # iam, s3, ec2, rds
    cis_id: Optional[str] = None       # CIS benchmark reference if applicable

    # Resource
    resource_id: str = ""               # The AWS resource that triggered the finding
    resource_type: str = ""             # Type of resource (bucket, security_group, etc.)

    # Risk
    risk: str = ""                      # What could happen if not fixed
    evidence: Dict[str, Any] = field(default_factory=dict)  # Data supporting the finding

    # Remediation
    remediation: str = ""               # How to fix this
    remediation_url: str = ""           # Link to AWS docs

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_id: Optional[str] = None       # ID of the scan that found this

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON output."""
        return {
            "id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "service": self.service,
            "cis_id": self.cis_id,
            "resource": {
                "id": self.resource_id,
                "type": self.resource_type,
            },
            "risk": self.risk,
            "evidence": self.evidence,
            "remediation": {
                "steps": self.remediation,
                "url": self.remediation_url,
            },
            "timestamp": self.timestamp,
        }

    def __repr__(self) -> str:
        return (
            f"<Finding {self.rule_id} {self.severity.value} "
            f"on {self.resource_id}>"
        )
