"""
Risk scoring - assigns a 0-100 numeric score to each finding.

The score exists to prioritize *within* a severity tier (two HIGH
findings aren't necessarily equally urgent), not to replace severity.
It's deliberately simple: a base score per severity, boosted for rules
that specifically indicate internet/public exposure -- an allowlist of
known rule ids rather than inferring exposure from each rule's evidence
dict, which would be fragile (evidence shapes differ per rule and
aren't a stable contract to pattern-match against).

The boost is capped so it can never let a lower severity tier outrank a
higher one (see test_scoring.py for the tier-ordering guarantee).
"""

from typing import Dict, Set

from cloudscan.engine.finding import Finding, Severity

SEVERITY_BASE_SCORE: Dict[Severity, int] = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 45,
    Severity.LOW: 20,
    Severity.INFO: 5,
}

# Rules whose entire purpose is flagging internet/public exposure --
# these findings are more urgent than a same-severity finding that isn't
# about exposure (e.g. a HIGH from a missing best-practice vs. a HIGH
# security group open to the world).
EXPOSURE_RULE_IDS: Set[str] = {
    "S3-001",    # public S3 bucket
    "SG-001",    # security group open to 0.0.0.0/0 on SSH/RDP
    "SG-002",    # security group open to 0.0.0.0/0 on another port
    "SG-003",    # security group open to ::/0 on SSH/RDP
    "EC2-001",   # instance with a public IP behind an open security group
    "RDS-001",   # RDS instance publicly accessible
    "CT-001",    # no audit trail at all -- account-wide exposure
}

EXPOSURE_MULTIPLIER = 1.15


def compute_score(finding: Finding) -> int:
    """Compute a 0-100 risk score for a single finding."""
    base = SEVERITY_BASE_SCORE.get(finding.severity, 10)
    if finding.rule_id in EXPOSURE_RULE_IDS:
        base = base * EXPOSURE_MULTIPLIER
    return min(100, round(base))


def score_findings(findings: list) -> list:
    """Set .score on every finding in place, and return them sorted by
    score descending (ties broken by rule_id for stable output)."""
    for finding in findings:
        finding.score = compute_score(finding)
    return sorted(findings, key=lambda f: (-f.score, f.rule_id))
