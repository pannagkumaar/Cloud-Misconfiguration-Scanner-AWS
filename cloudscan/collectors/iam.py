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

import csv
import io
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

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
                "password_policy": self._collect_password_policy(iam_client),
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
                        "inline_policy_documents": [],
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

                    # Get inline policies (names + actual documents)
                    try:
                        policies_response = iam_client.list_user_policies(
                            UserName=user["UserName"]
                        )
                        policy_names = policies_response.get("PolicyNames", [])
                        user_data["inline_policies"] = policy_names

                        for policy_name in policy_names:
                            try:
                                doc_response = iam_client.get_user_policy(
                                    UserName=user["UserName"], PolicyName=policy_name
                                )
                                user_data["inline_policy_documents"].append({
                                    "name": policy_name,
                                    "document": doc_response.get("PolicyDocument", {}),
                                })
                            except Exception as e:
                                self.logger.debug(
                                    f"Error getting inline policy document "
                                    f"{policy_name} for {user['UserName']}: {e}"
                                )
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
                        "inline_policy_documents": [],
                        "attached_policies": [],
                    }

                    # Get inline policies (names + actual documents)
                    try:
                        policies_response = iam_client.list_role_policies(
                            RoleName=role["RoleName"]
                        )
                        policy_names = policies_response.get("PolicyNames", [])
                        role_data["inline_policies"] = policy_names

                        for policy_name in policy_names:
                            try:
                                doc_response = iam_client.get_role_policy(
                                    RoleName=role["RoleName"], PolicyName=policy_name
                                )
                                role_data["inline_policy_documents"].append({
                                    "name": policy_name,
                                    "document": doc_response.get("PolicyDocument", {}),
                                })
                            except Exception as e:
                                self.logger.debug(
                                    f"Error getting inline policy document "
                                    f"{policy_name} for {role['RoleName']}: {e}"
                                )
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
        Collect and parse the IAM credential report.

        This unlocks account-level checks that need per-credential state
        AWS doesn't expose any other way: root account MFA/access keys,
        per-user MFA status, and access key age/last-used, all in one CSV.

        Returns:
            Credential report data, including parsed per-user/root rows
        """
        try:
            report_bytes = self._generate_and_fetch_report(iam_client)
            rows = self._parse_credential_report(report_bytes)

            return {
                "available": True,
                "generated": datetime.now(timezone.utc).isoformat(),
                "rows": rows,
            }

        except Exception as e:
            self.logger.error(f"Error collecting credential report: {e}")
            return {"available": False, "error": str(e), "rows": []}

    def _generate_and_fetch_report(self, iam_client, max_attempts: int = 5) -> bytes:
        """
        Request credential report generation and poll until it's ready.

        AWS generates the report asynchronously: generate_credential_report()
        returns a State of STARTED/INPROGRESS immediately, and callers must
        poll (typically via repeated generate_credential_report() calls)
        until State is COMPLETE before get_credential_report() succeeds.
        """
        for attempt in range(max_attempts):
            state = iam_client.generate_credential_report().get("State")
            if state == "COMPLETE":
                break
            time.sleep(0.5 * (attempt + 1))

        response = iam_client.get_credential_report()
        return response["Content"]

    def _parse_credential_report(self, report_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Parse the credential report CSV into structured rows.

        CSV columns (per AWS docs): user, arn, user_creation_time,
        password_enabled, password_last_used, password_last_changed,
        password_next_rotation, mfa_active, access_key_1_active,
        access_key_1_last_rotated, access_key_1_last_used_date, ...,
        access_key_2_active, access_key_2_last_rotated,
        access_key_2_last_used_date, ...
        """
        content = report_bytes.decode("utf-8") if isinstance(report_bytes, bytes) else report_bytes
        reader = csv.DictReader(io.StringIO(content))

        rows = []
        for row in reader:
            user = row.get("user", "")
            rows.append({
                "user": user,
                "arn": row.get("arn", ""),
                "is_root": user == "<root_account>",
                "mfa_active": self._csv_bool(row.get("mfa_active")),
                "password_enabled": self._csv_bool(row.get("password_enabled")),
                "password_last_used": self._csv_optional(row.get("password_last_used")),
                "access_key_1_active": self._csv_bool(row.get("access_key_1_active")),
                "access_key_1_last_rotated": self._csv_optional(row.get("access_key_1_last_rotated")),
                "access_key_1_last_used": self._csv_optional(row.get("access_key_1_last_used_date")),
                "access_key_2_active": self._csv_bool(row.get("access_key_2_active")),
                "access_key_2_last_rotated": self._csv_optional(row.get("access_key_2_last_rotated")),
                "access_key_2_last_used": self._csv_optional(row.get("access_key_2_last_used_date")),
            })

        return rows

    @staticmethod
    def _csv_bool(value: Any) -> bool:
        return str(value).strip().lower() == "true"

    @staticmethod
    def _csv_optional(value: Any):
        v = str(value).strip() if value is not None else ""
        return None if v in ("", "N/A", "not_supported") else v

    def _collect_password_policy(self, iam_client) -> Dict[str, Any]:
        """
        Collect the account password policy.

        Returns:
            Password policy dictionary, or {"exists": False} if the
            account has no custom password policy set (AWS default applies)
        """
        try:
            response = iam_client.get_account_password_policy()
            policy = response.get("PasswordPolicy", {})
            return {
                "exists": True,
                "minimum_password_length": policy.get("MinimumPasswordLength"),
                "require_symbols": policy.get("RequireSymbols"),
                "require_numbers": policy.get("RequireNumbers"),
                "require_uppercase_characters": policy.get("RequireUppercaseCharacters"),
                "require_lowercase_characters": policy.get("RequireLowercaseCharacters"),
                "max_password_age": policy.get("MaxPasswordAge"),
                "password_reuse_prevention": policy.get("PasswordReusePrevention"),
            }
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "NoSuchEntity":
                return {"exists": False}
            self.logger.error(f"Error collecting password policy: {e}")
            return {"exists": False}
        except Exception as e:
            self.logger.error(f"Error collecting password policy: {e}")
            return {"exists": False}
