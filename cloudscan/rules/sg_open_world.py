"""
SG-001: Open security group to 0.0.0.0/0

Detects security groups that allow unrestricted inbound access from
any IP on dangerous ports (SSH 22, RDP 3389).
"""

from typing import List
from cloudscan.rules.base import BaseRule
from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity


class SecurityGroupOpenRule(BaseRule):
    """Detects security groups open to 0.0.0.0/0 on dangerous ports."""

    id = "SG-001"
    title = "Security group allows unrestricted inbound access"
    description = (
        "Security group allows inbound access from 0.0.0.0/0 (anyone) "
        "on SSH (22) or RDP (3389), enabling direct remote access attempts"
    )
    severity = Severity.HIGH
    service = "ec2"

    DANGEROUS_PORTS = [22, 3389]  # SSH, RDP

    def evaluate(self, context: ScanContext) -> List[Finding]:
        """
        Evaluate security groups for unrestricted access on dangerous ports.

        Returns findings for any insecure rules.
        """
        findings = []

        for sg in context.get_security_groups():
            for rule in sg.get("inbound_rules", []):
                if self._is_dangerous_rule(rule):
                    finding = self._create_finding(
                        resource_id=sg["id"],
                        resource_type="Security Group",
                        risk=self._get_risk_for_rule(rule),
                        evidence=self._gather_evidence(sg, rule),
                        remediation=self._get_remediation_for_rule(rule),
                        remediation_url=(
                            "https://docs.aws.amazon.com/vpc/latest/userguide/"
                            "VPC_SecurityGroups.html"
                        ),
                    )
                    findings.append(finding)
                    port = rule.get("from_port", "all")
                    self.logger.warning(
                        f"Open security group {sg['id']} on port {port}"
                    )

        return findings

    def _is_dangerous_rule(self, rule: dict) -> bool:
        """Check if rule allows unrestricted access on a dangerous port."""
        # Must have 0.0.0.0/0 in IP ranges
        has_open_cidr = any(
            ip_range.get("cidr") == "0.0.0.0/0"
            for ip_range in rule.get("ip_ranges", [])
        )

        if not has_open_cidr:
            return False

        # Check if port is dangerous
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        protocol = rule.get("protocol", "-1")

        # Protocol -1 means all protocols
        if protocol == "-1":
            return True

        # Only interested in TCP
        if protocol != "tcp":
            return False

        # Check if port range includes dangerous ports
        if from_port is None or to_port is None:
            return False

        for port in self.DANGEROUS_PORTS:
            if from_port <= port <= to_port:
                return True

        return False

    def _get_risk_for_rule(self, rule: dict) -> str:
        """Get risk description for a rule."""
        port = rule.get("from_port", "unknown")
        if port == 22:
            return "SSH access from the internet enables brute-force attacks and unauthorized access"
        elif port == 3389:
            return "RDP access from the internet enables brute-force attacks and unauthorized access"
        else:
            return "Unrestricted access on port {}".format(port)

    def _get_remediation_for_rule(self, rule: dict) -> str:
        """Get remediation steps for a rule."""
        port = rule.get("from_port", "unknown")
        return (
            f"1. Remove or restrict the inbound rule allowing 0.0.0.0/0 on port {port}\n"
            f"2. Restrict SSH/RDP access to specific IPs (e.g., office VPN/bastion host)\n"
            f"3. Consider using AWS Systems Manager Session Manager for remote access\n"
            f"4. Implement a bastion host or VPN for secure remote access"
        )

    def _gather_evidence(self, sg: dict, rule: dict) -> dict:
        """Gather evidence data for the finding."""
        return {
            "security_group_id": sg["id"],
            "security_group_name": sg.get("name"),
            "vpc_id": sg.get("vpc_id"),
            "rule": {
                "protocol": rule.get("protocol"),
                "from_port": rule.get("from_port"),
                "to_port": rule.get("to_port"),
                "open_cidr": "0.0.0.0/0",
            },
            "description": rule.get("ip_ranges", [{}])[0].get("description", ""),
        }
