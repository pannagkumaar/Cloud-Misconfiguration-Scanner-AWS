"""
EC2 Collector - Collects EC2 security configuration.

Gathers:
- Security groups and their rules
- EC2 instances and their security groups
- Public IPs
- VPC configuration
"""

from typing import Dict, Any, List
import logging
from botocore.exceptions import ClientError
from cloudscan.collectors.base import BaseCollector


class EC2Collector(BaseCollector):
    """Collects EC2 configuration from AWS account."""

    service_name = "ec2"

    def collect(self) -> Dict[str, Any]:
        """
        Collect EC2 configuration.

        Returns:
            Dictionary containing EC2 configuration
        """
        self.logger.info("Starting EC2 collection...")

        try:
            ec2_client = self.aws_client.get_client("ec2")

            result = {
                "service": "ec2",
                "security_groups": self._collect_security_groups(ec2_client),
                "instances": self._collect_instances(ec2_client),
            }

            self.logger.info(
                f"EC2 collection complete: {len(result['security_groups'])} SGs, "
                f"{len(result['instances'])} instances"
            )

            return result

        except ClientError as e:
            self.logger.error(f"EC2 collection failed: {e}")
            raise

    def _collect_security_groups(self, ec2_client) -> List[Dict[str, Any]]:
        """
        Collect security group configurations.

        Returns:
            List of security group configurations
        """
        security_groups = []
        try:
            paginator = ec2_client.get_paginator("describe_security_groups")

            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    sg_data = {
                        "id": sg["GroupId"],
                        "name": sg["GroupName"],
                        "description": sg.get("GroupDescription", ""),
                        "vpc_id": sg.get("VpcId"),
                        "owner_id": sg.get("OwnerId"),
                        "inbound_rules": [],
                        "outbound_rules": [],
                    }

                    # Parse inbound rules
                    for rule in sg.get("IpPermissions", []):
                        sg_data["inbound_rules"].append(
                            self._parse_rule(rule, direction="inbound")
                        )

                    # Parse outbound rules
                    for rule in sg.get("IpPermissionsEgress", []):
                        sg_data["outbound_rules"].append(
                            self._parse_rule(rule, direction="outbound")
                        )

                    security_groups.append(sg_data)

            self.logger.debug(f"Collected {len(security_groups)} security groups")
            return security_groups

        except Exception as e:
            self.logger.error(f"Error collecting security groups: {e}")
            return []

    def _collect_instances(self, ec2_client) -> List[Dict[str, Any]]:
        """
        Collect EC2 instance configurations.

        Returns:
            List of instance configurations
        """
        instances = []
        try:
            paginator = ec2_client.get_paginator("describe_instances")

            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        instance_data = {
                            "id": instance["InstanceId"],
                            "state": instance["State"]["Name"],
                            "type": instance.get("InstanceType"),
                            "vpc_id": instance.get("VpcId"),
                            "subnet_id": instance.get("SubnetId"),
                            "public_ip": instance.get("PublicIpAddress"),
                            "private_ip": instance.get("PrivateIpAddress"),
                            "security_groups": [
                                {
                                    "id": sg["GroupId"],
                                    "name": sg["GroupName"]
                                }
                                for sg in instance.get("SecurityGroups", [])
                            ],
                            "tags": {
                                tag["Key"]: tag["Value"]
                                for tag in instance.get("Tags", [])
                            },
                        }

                        instances.append(instance_data)

            self.logger.debug(f"Collected {len(instances)} EC2 instances")
            return instances

        except Exception as e:
            self.logger.error(f"Error collecting instances: {e}")
            return []

    @staticmethod
    def _parse_rule(rule: Dict[str, Any], direction: str) -> Dict[str, Any]:
        """
        Parse a security group rule.

        Args:
            rule: Rule dictionary from AWS API
            direction: "inbound" or "outbound"

        Returns:
            Parsed rule dictionary
        """
        parsed_rule = {
            "protocol": rule.get("IpProtocol", "-1"),
            "from_port": rule.get("FromPort"),
            "to_port": rule.get("ToPort"),
            "direction": direction,
            "ip_ranges": [],
            "ipv6_ranges": [],
            "user_id_group_pairs": [],
        }

        # IP v4 ranges
        for ip_range in rule.get("IpRanges", []):
            parsed_rule["ip_ranges"].append({
                "cidr": ip_range.get("CidrIp"),
                "description": ip_range.get("Description", ""),
            })

        # IP v6 ranges
        for ipv6_range in rule.get("Ipv6Ranges", []):
            parsed_rule["ipv6_ranges"].append({
                "cidr": ipv6_range.get("CidrIpv6"),
                "description": ipv6_range.get("Description", ""),
            })

        # User ID group pairs (security group references)
        for group_pair in rule.get("UserIdGroupPairs", []):
            parsed_rule["user_id_group_pairs"].append({
                "group_id": group_pair.get("GroupId"),
                "user_id": group_pair.get("UserId"),
                "description": group_pair.get("Description", ""),
            })

        return parsed_rule
