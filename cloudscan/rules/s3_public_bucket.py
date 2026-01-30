"""
S3-001: Public S3 bucket detection

Detects S3 buckets that are publicly accessible through:
1. Bucket policies allowing public access
2. ACLs allowing public access
3. Missing or incomplete public access blocks
"""

from typing import List
import json
from cloudscan.rules.base import BaseRule
from cloudscan.engine.context import ScanContext
from cloudscan.engine.finding import Finding, Severity


class S3PublicBucketRule(BaseRule):
    """Detects publicly accessible S3 buckets."""

    id = "S3-001"
    title = "S3 bucket is publicly accessible"
    description = (
        "S3 bucket allows public access through policy, ACL, or missing "
        "public access blocks, allowing anyone on the internet to read objects"
    )
    severity = Severity.HIGH
    service = "s3"
    cis_id = "2.1.5.1"

    def evaluate(self, context: ScanContext) -> List[Finding]:
        """
        Evaluate S3 buckets for public accessibility.

        Returns findings for any publicly accessible buckets.
        """
        findings = []

        for bucket in context.get_s3_buckets():
            if self._is_publicly_accessible(bucket):
                finding = self._create_finding(
                    resource_id=bucket["name"],
                    resource_type="S3 Bucket",
                    risk="Publicly accessible bucket allows anyone on the internet "
                         "to read and potentially exfiltrate data",
                    evidence=self._gather_evidence(bucket),
                    remediation=(
                        "1. Enable 'Block Public Access' for the bucket\n"
                        "2. Review and restrict bucket policy to known principals\n"
                        "3. Set bucket ACL to 'Private'\n"
                        "4. Enable logging to track access"
                    ),
                    remediation_url=(
                        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
                        "access-control-block-public-access.html"
                    ),
                )
                findings.append(finding)
                self.logger.warning(f"Public S3 bucket found: {bucket['name']}")

        return findings

    def _is_publicly_accessible(self, bucket: dict) -> bool:
        """Check if bucket is publicly accessible."""
        # Check public access block
        pub_block = bucket.get("public_access_block", {})
        if not (pub_block.get("block_public_acls") and 
                pub_block.get("block_public_policy")):
            # Not fully blocked, check policy and ACL
            if self._has_public_policy(bucket) or self._has_public_acl(bucket):
                return True

        return False

    def _has_public_policy(self, bucket: dict) -> bool:
        """Check if bucket policy allows public access."""
        policy = bucket.get("policy")
        if not policy:
            return False

        statements = policy.get("Statement", [])
        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue

            principal = statement.get("Principal", {})
            # Check for wildcard principal
            if principal == "*" or principal.get("AWS") == "*":
                return True

            # Check for explicit public access
            if isinstance(principal, str) and principal == "*":
                return True

        return False

    def _has_public_acl(self, bucket: dict) -> bool:
        """Check if bucket ACL allows public access."""
        acl = bucket.get("acl", {})
        grants = acl.get("grants", [])

        for grant in grants:
            grantee = grant.get("Grantee", {})
            # Check for AllUsers or AuthenticatedUsers groups
            if grantee.get("Type") == "Group":
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    return True

        return False

    def _gather_evidence(self, bucket: dict) -> dict:
        """Gather evidence data for the finding."""
        evidence = {
            "bucket_name": bucket["name"],
            "region": bucket["region"],
            "public_block_status": bucket.get("public_access_block", {}),
        }

        # Add policy if it allows public access
        if self._has_public_policy(bucket):
            evidence["public_policy"] = True
            policy = bucket.get("policy", {})
            statements = policy.get("Statement", [])
            for stmt in statements:
                if stmt.get("Effect") == "Allow":
                    principal = stmt.get("Principal")
                    if principal == "*" or principal.get("AWS") == "*":
                        evidence["principal"] = "* (wildcard)"
                        evidence["actions"] = stmt.get("Action", [])
                        break

        # Add ACL if public
        if self._has_public_acl(bucket):
            evidence["public_acl"] = True

        return evidence
