"""
EC2-001: EC2 instance with a public IP is attached to an internet-open
security group

Correlation check: a public IP alone isn't necessarily dangerous (the
attached security group might still lock it down), and an open security
group alone isn't necessarily dangerous (nothing might be using it with
a public IP). The combination of both is what actually creates an
internet-reachable host, and is a more actionable, higher-confidence
signal than either fact in isolation.
"""

from typing import List, Set

from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity
from cloudscan.rules.base import BaseRule


class InternetExposedInstanceRule(BaseRule):
    """Detects EC2 instances reachable from the internet."""

    id = "EC2-001"
    title = "EC2 instance is reachable from the internet"
    description = (
        "EC2 instance has a public IP address and is attached to a "
        "security group with an inbound rule open to the entire internet"
    )
    severity = Severity.HIGH
    service = "ec2"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []
        open_sg_ids = self._get_internet_open_security_group_ids(context)

        for instance in context.get_ec2_instances():
            if not instance.get("public_ip"):
                continue

            instance_sg_ids = {
                sg.get("id") for sg in instance.get("security_groups", [])
            }
            matched = instance_sg_ids & open_sg_ids
            if not matched:
                continue

            finding = self._create_finding(
                resource_id=instance["id"],
                resource_type="EC2 Instance",
                risk=(
                    "This instance is directly reachable from the internet "
                    "on at least one port, making it a target for scanning, "
                    "brute-forcing, and exploitation attempts"
                ),
                evidence={
                    "instance_id": instance["id"],
                    "public_ip": instance.get("public_ip"),
                    "internet_open_security_groups": sorted(matched),
                },
                remediation=(
                    "1. Remove the public IP if the instance doesn't need "
                    "to be internet-facing\n"
                    "2. Restrict the attached security group's inbound "
                    "rules to specific IPs\n"
                    "3. Place the instance behind a load balancer or "
                    "bastion/VPN instead of exposing it directly"
                ),
                remediation_url=(
                    "https://docs.aws.amazon.com/vpc/latest/userguide/"
                    "VPC_SecurityGroups.html"
                ),
            )
            findings.append(finding)
            self.logger.warning(
                f"Internet-exposed instance: {instance['id']} "
                f"({instance.get('public_ip')})"
            )

        return findings

    def _get_internet_open_security_group_ids(self, context: ScanContext) -> Set[str]:
        open_ids: Set[str] = set()
        for sg in context.get_security_groups():
            for rule in sg.get("inbound_rules", []):
                if self._is_open_to_internet(rule):
                    open_ids.add(sg["id"])
                    break
        return open_ids

    @staticmethod
    def _is_open_to_internet(rule: dict) -> bool:
        has_open_ipv4 = any(
            ip_range.get("cidr") == "0.0.0.0/0"
            for ip_range in rule.get("ip_ranges", [])
        )
        has_open_ipv6 = any(
            ip_range.get("cidr") == "::/0"
            for ip_range in rule.get("ipv6_ranges", [])
        )
        return has_open_ipv4 or has_open_ipv6
