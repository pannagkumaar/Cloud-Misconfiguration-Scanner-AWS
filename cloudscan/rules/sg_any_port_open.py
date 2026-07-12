"""
SG-002: Security group allows unrestricted inbound access on a
non-standard port

Broader companion to SG-001: flags any inbound rule open to
0.0.0.0/0 on a specific port range, at a lower severity than the
SSH/RDP-specific check. Ranges that include 22 or 3389 are excluded
here since SG-001 already reports those at HIGH; "all ports/protocols"
(-1) is also excluded since SG-001 already covers that case too.
"""

from typing import List

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class SecurityGroupAnyPortOpenRule(BaseRule):
    """Detects security groups open to 0.0.0.0/0 on non-dangerous ports."""

    id = "SG-002"
    title = "Security group allows unrestricted inbound access on a non-standard port"
    description = (
        "Security group allows inbound access from 0.0.0.0/0 (anyone) on "
        "a specific port that isn't SSH/RDP but is still exposed to the "
        "entire internet"
    )
    severity = Severity.MEDIUM
    service = "ec2"

    # Ports SG-001 already reports at HIGH severity; skip them here to
    # avoid flagging the exact same rule twice under two different IDs.
    EXCLUDED_PORTS = {22, 3389}

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []

        for sg in context.get_security_groups():
            for rule in sg.get("inbound_rules", []):
                if not self._is_broad_non_dangerous_rule(rule):
                    continue

                finding = self._create_finding(
                    resource_id=sg["id"],
                    resource_type="Security Group",
                    risk=(
                        "Unrestricted access on this port from the entire "
                        "internet exposes whatever service listens on it "
                        "to scanning and exploitation attempts"
                    ),
                    evidence={
                        "security_group_id": sg["id"],
                        "security_group_name": sg.get("name"),
                        "protocol": rule.get("protocol"),
                        "from_port": rule.get("from_port"),
                        "to_port": rule.get("to_port"),
                        "open_cidr": "0.0.0.0/0",
                    },
                    remediation=(
                        "1. Restrict the inbound rule to specific known IPs\n"
                        "2. Use a load balancer or bastion/VPN in front of "
                        "the service instead of exposing it directly\n"
                        "3. Confirm the port genuinely needs to be internet-facing"
                    ),
                    remediation_url=(
                        "https://docs.aws.amazon.com/vpc/latest/userguide/"
                        "VPC_SecurityGroups.html"
                    ),
                )
                findings.append(finding)
                self.logger.warning(
                    f"Broad open security group {sg['id']} on port "
                    f"{rule.get('from_port')}"
                )

        return findings

    def _is_broad_non_dangerous_rule(self, rule: dict) -> bool:
        has_open_cidr = any(
            ip_range.get("cidr") == "0.0.0.0/0"
            for ip_range in rule.get("ip_ranges", [])
        )
        if not has_open_cidr:
            return False

        protocol = rule.get("protocol", "-1")
        if protocol == "-1":
            return False  # SG-001 already covers "all protocols" as HIGH

        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        if from_port is None or to_port is None:
            return False

        # If this range touches a dangerous port, SG-001 already reports it.
        if any(from_port <= p <= to_port for p in self.EXCLUDED_PORTS):
            return False

        return True
