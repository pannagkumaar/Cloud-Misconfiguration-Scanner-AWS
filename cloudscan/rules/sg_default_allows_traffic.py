"""
SG-004: Default security group allows traffic

CIS AWS Foundations Benchmark 5.3: the default security group of every
VPC should restrict all traffic, since it's easy to accidentally attach
resources to it without realizing what it permits.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class DefaultSecurityGroupRule(BaseRule):
    """Detects a default security group with inbound or outbound rules."""

    id = "SG-004"
    title = "Default security group allows traffic"
    description = (
        "The VPC's default security group has inbound or outbound rules "
        "configured; it should be left with no rules so resources "
        "accidentally attached to it get no unintended access"
    )
    severity = Severity.LOW
    service = "ec2"
    cis_id = "5.3"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for sg in context.get_security_groups():
            if sg.get("name") != "default":
                continue

            inbound = sg.get("inbound_rules", [])
            outbound = sg.get("outbound_rules", [])
            if not inbound and not outbound:
                continue

            finding = self._create_finding(
                resource_id=sg["id"],
                resource_type="Security Group",
                risk=(
                    "Any resource launched without an explicit security "
                    "group falls back to the default group -- if it "
                    "permits traffic, that resource is unintentionally "
                    "exposed"
                ),
                evidence={
                    "security_group_id": sg["id"],
                    "vpc_id": sg.get("vpc_id"),
                    "inbound_rule_count": len(inbound),
                    "outbound_rule_count": len(outbound),
                },
                remediation=(
                    "1. Remove all inbound and outbound rules from the "
                    "default security group\n"
                    "2. Create purpose-specific security groups for each "
                    "workload instead\n"
                    "3. Audit existing resources attached to the default "
                    "group and move them to a dedicated group"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/vpc/latest/userguide/"
                    "VPC_SecurityGroups.html#DefaultSecurityGroup"
                ),
            )
            findings.append(finding)
            self.logger.warning(f"Default security group allows traffic: {sg['id']}")

        return findings
