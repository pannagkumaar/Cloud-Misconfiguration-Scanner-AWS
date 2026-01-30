"""
IAM Collector - Collects IAM configuration.

Gathers:
- IAM users and their properties
- IAM roles and trust relationships
- IAM policies
- MFA configuration
- Access keys and their age
- Root account activity
"""

from typing import Dict, Any, List
import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError
from cloudscan.collectors.base import BaseCollector


class IAMCollector(BaseCollector):
    """Collects IAM configuration from AWS account."""

    service_name = "iam"

    def collect(self) -> Dict[str, Any]:
        """
        Collect IAM configuration.

        Returns:
            Dictionary containing IAM configuration
        """
        self.logger.info("Starting IAM collection...")

        try:
            iam_client = self.aws_client.get_client("iam")

            result = {
                "service": "iam",
                "users": self._collect_users(iam_client),
                "roles": self._collect_roles(iam_client),
                "policies": self._collect_policies(iam_client),
                "account_summary": self._collect_account_summary(iam_client),
                "credential_report": self._collect_credential_report(iam_client),
            }

            self.logger.info(f"IAM collection complete: {len(result['users'])} users, "
                           f"{len(result['roles'])} roles")

            return result

        except ClientError as e:
            self.logger.error(f"IAM collection failed: {e}")
            raise

    def _collect_users(self, iam_client) -> List[Dict[str, Any]]:
        """
        Collect IAM users.

        Returns:
            List of user configurations
        """
        users = []
        try:
            paginator = iam_client.get_paginator("list_users")

            for page in paginator.paginate():
                for user in page.get("Users", []):
                    user_data = {
                        "name": user["UserName"],
                        "arn": user["Arn"],
                        "created": user["CreateDate"].isoformat(),
                        "mfa_devices": [],
                        "access_keys": [],
                        "inline_policies": [],
                        "attached_policies": [],
                    }

                    # Get MFA devices
                    try:
                        mfa_response = iam_client.list_mfa_devices(
                            UserName=user["UserName"]
                        )
                        user_data["mfa_devices"] = [
                            {
                                "serial": device["SerialNumber"],
                                "enabled": device.get("Status") == "Active"
                            }
                            for device in mfa_response.get("MFADevices", [])
                        ]
                    except Exception as e:
                        self.logger.debug(f"Error getting MFA for {user['UserName']}: {e}")

                    # Get access keys
                    try:
                        keys_response = iam_client.list_access_keys(
                            UserName=user["UserName"]
                        )
                        user_data["access_keys"] = [
                            {
                                "key_id": key["AccessKeyId"],
                                "status": key["Status"],
                                "created": key["CreateDate"].isoformat(),
                            }
                            for key in keys_response.get("AccessKeyMetadata", [])
                        ]
                    except Exception as e:
                        self.logger.debug(f"Error getting access keys for {user['UserName']}: {e}")

                    # Get inline policies
                    try:
                        policies_response = iam_client.list_user_policies(
                            UserName=user["UserName"]
                        )
                        user_data["inline_policies"] = policies_response.get("PolicyNames", [])
                    except Exception as e:
                        self.logger.debug(f"Error getting inline policies for {user['UserName']}: {e}")

                    # Get attached policies
                    try:
                        attached_response = iam_client.list_attached_user_policies(
                            UserName=user["UserName"]
                        )
                        user_data["attached_policies"] = [
                            {
                                "name": policy["PolicyName"],
                                "arn": policy["PolicyArn"]
                            }
                            for policy in attached_response.get("AttachedPolicies", [])
                        ]
                    except Exception as e:
                        self.logger.debug(f"Error getting attached policies for {user['UserName']}: {e}")

                    users.append(user_data)

            self.logger.debug(f"Collected {len(users)} IAM users")
            return users

        except Exception as e:
            self.logger.error(f"Error collecting users: {e}")
            return []

    def _collect_roles(self, iam_client) -> List[Dict[str, Any]]:
        """
        Collect IAM roles.

        Returns:
            List of role configurations
        """
        roles = []
        try:
            paginator = iam_client.get_paginator("list_roles")

            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_data = {
                        "name": role["RoleName"],
                        "arn": role["Arn"],
                        "created": role["CreateDate"].isoformat(),
                        "assume_role_policy": role.get("AssumeRolePolicyDocument", {}),
                        "inline_policies": [],
                        "attached_policies": [],
                    }

                    # Get inline policies
                    try:
                        policies_response = iam_client.list_role_policies(
                            RoleName=role["RoleName"]
                        )
                        role_data["inline_policies"] = policies_response.get("PolicyNames", [])
                    except Exception as e:
                        self.logger.debug(f"Error getting inline policies for {role['RoleName']}: {e}")

                    # Get attached policies
                    try:
                        attached_response = iam_client.list_attached_role_policies(
                            RoleName=role["RoleName"]
                        )
                        role_data["attached_policies"] = [
                            {
                                "name": policy["PolicyName"],
                                "arn": policy["PolicyArn"]
                            }
                            for policy in attached_response.get("AttachedPolicies", [])
                        ]
                    except Exception as e:
                        self.logger.debug(f"Error getting attached policies for {role['RoleName']}: {e}")

                    roles.append(role_data)

            self.logger.debug(f"Collected {len(roles)} IAM roles")
            return roles

        except Exception as e:
            self.logger.error(f"Error collecting roles: {e}")
            return []

    def _collect_policies(self, iam_client) -> List[Dict[str, Any]]:
        """
        Collect customer-managed IAM policies.

        Returns:
            List of policy configurations
        """
        policies = []
        try:
            paginator = iam_client.get_paginator("list_policies")

            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_data = {
                        "name": policy["PolicyName"],
                        "arn": policy["Arn"],
                        "created": policy["CreateDate"].isoformat(),
                        "update_date": policy.get("UpdateDate", policy["CreateDate"]).isoformat(),
                        "default_version": policy.get("DefaultVersionId"),
                    }

                    # Get policy document
                    try:
                        version_response = iam_client.get_policy_version(
                            PolicyArn=policy["Arn"],
                            VersionId=policy.get("DefaultVersionId")
                        )
                        policy_data["document"] = version_response.get("PolicyVersion", {}).get("Document", {})
                    except Exception as e:
                        self.logger.debug(f"Error getting policy document for {policy['Arn']}: {e}")

                    policies.append(policy_data)

            self.logger.debug(f"Collected {len(policies)} customer-managed policies")
            return policies

        except Exception as e:
            self.logger.error(f"Error collecting policies: {e}")
            return []

    def _collect_account_summary(self, iam_client) -> Dict[str, Any]:
        """
        Collect account-level IAM summary.

        Returns:
            Account summary dictionary
        """
        try:
            response = iam_client.get_account_summary()
            summary = response.get("SummaryMap", {})

            return {
                "users": summary.get("Users", 0),
                "roles": summary.get("Roles", 0),
                "policies": summary.get("Policies", 0),
                "groups": summary.get("Groups", 0),
                "mfa_devices": summary.get("MFADevices", 0),
            }

        except Exception as e:
            self.logger.error(f"Error collecting account summary: {e}")
            return {}

    def _collect_credential_report(self, iam_client) -> Dict[str, Any]:
        """
        Collect IAM credential report (for root account MFA check).

        Returns:
            Credential report data
        """
        try:
            # Request credential report
            iam_client.generate_credential_report()

            # Get the report
            response = iam_client.get_credential_report()
            # Report is in CSV format, we'll just note it was collected
            return {
                "available": True,
                "generated": response.get("GeneratedTime", datetime.now(timezone.utc)).isoformat(),
            }

        except Exception as e:
            self.logger.error(f"Error collecting credential report: {e}")
            return {"available": False, "error": str(e)}
