"""
SG-003: Security group allows unrestricted IPv6 inbound access

IPv6 counterpart to SG-001: many scanners and hand-written security
group rules only check IPv4 CIDR ranges, leaving an IPv6 ::/0 rule on
the same dangerous ports (SSH/RDP) unnoticed.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class SecurityGroupOpenIPv6Rule(BaseRule):
    """Detects security groups open to ::/0 on dangerous ports."""

    id = "SG-003"
    title = "Security group allows unrestricted IPv6 inbound access"
    description = (
        "Security group allows inbound access from ::/0 (any IPv6 address) "
        "on SSH (22) or RDP (3389), enabling direct remote access attempts"
    )
    severity = Severity.HIGH
    service = "ec2"

    DANGEROUS_PORTS = [22, 3389]

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for sg in context.get_security_groups():
            for rule in sg.get("inbound_rules", []):
                if not self._is_dangerous_rule(rule):
                    continue

                finding = self._create_finding(
                    resource_id=sg["id"],
                    resource_type="Security Group",
                    risk=(
                        "SSH/RDP access from any IPv6 address enables "
                        "brute-force attacks and unauthorized access, "
                        "just as an open IPv4 rule would"
                    ),
                    evidence={
                        "security_group_id": sg["id"],
                        "security_group_name": sg.get("name"),
                        "protocol": rule.get("protocol"),
                        "from_port": rule.get("from_port"),
                        "to_port": rule.get("to_port"),
                        "open_cidr": "::/0",
                    },
                    remediation=(
                        "1. Remove or restrict the inbound rule allowing "
                        "::/0 on this port\n"
                        "2. Restrict SSH/RDP access to specific IPv6 ranges "
                        "or disable IPv6 access entirely if unused\n"
                        "3. Consider AWS Systems Manager Session Manager "
                        "for remote access instead"
                    ),
                    remediation_url=(
                        "https://docs.aws.amazon.com/vpc/latest/userguide/"
                        "VPC_SecurityGroups.html"
                    ),
                )
                findings.append(finding)
                self.logger.warning(
                    f"Open IPv6 security group {sg['id']} on port "
                    f"{rule.get('from_port', 'all')}"
                )

        return findings

    def _is_dangerous_rule(self, rule: dict) -> bool:
        has_open_cidr = any(
            ip_range.get("cidr") == "::/0"
            for ip_range in rule.get("ipv6_ranges", [])
        )
        if not has_open_cidr:
            return False

        protocol = rule.get("protocol", "-1")
        if protocol == "-1":
            return True
        if protocol != "tcp":
            return False

        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        if from_port is None or to_port is None:
            return False

        return any(from_port <= p <= to_port for p in self.DANGEROUS_PORTS)
