"""Shared pytest fixtures and helpers for the CloudScan test suite."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from cloudscan.engine.context import ScanContext

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def make_collected_data(**services: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a minimal collected_data structure for the given services.

    Example: make_collected_data(s3={"service": "s3", "buckets": [...]})
    """
    return {"services": list(services.keys()), "data": services}


def make_context(**services: Dict[str, Any]) -> ScanContext:
    """Build a ScanContext directly from normalized per-service data."""
    return ScanContext("123456789012", "us-east-1", make_collected_data(**services))


def load_fixture(name: str) -> Dict[str, Any]:
    """Load a JSON fixture file from tests/fixtures/."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


# --------------------------------------------------------------------------
# S3 bucket builders
# --------------------------------------------------------------------------

def make_bucket(
    name: str = "test-bucket",
    region: str = "us-east-1",
    policy: Optional[Dict[str, Any]] = None,
    acl: Optional[Dict[str, Any]] = None,
    public_access_block: Optional[Dict[str, Any]] = None,
    versioning: Optional[Dict[str, Any]] = None,
    logging: Optional[Dict[str, Any]] = None,
    encryption: Optional[Dict[str, Any]] = None,
    tags: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "created": "2024-01-01T00:00:00Z",
        "region": region,
        "policy": policy,
        "acl": acl,
        "public_access_block": public_access_block or {
            "block_public_acls": True,
            "ignore_public_acls": True,
            "block_public_policy": True,
            "restrict_public_buckets": True,
        },
        "versioning": versioning,
        "logging": logging,
        "encryption": encryption,
        "tags": tags,
    }


def public_policy_statement(bucket_name: str) -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket_name}/*",
        }],
    }


# --------------------------------------------------------------------------
# Security group builders
# --------------------------------------------------------------------------

def make_security_group(
    sg_id: str = "sg-test",
    name: str = "test-sg",
    inbound_rules: Optional[List[Dict[str, Any]]] = None,
    vpc_id: str = "vpc-test",
) -> Dict[str, Any]:
    return {
        "id": sg_id,
        "name": name,
        "description": "test sg",
        "vpc_id": vpc_id,
        "owner_id": "123456789012",
        "inbound_rules": inbound_rules or [],
        "outbound_rules": [],
    }


def make_inbound_rule(
    protocol: str = "tcp",
    from_port: Optional[int] = 22,
    to_port: Optional[int] = 22,
    cidr: str = "0.0.0.0/0",
) -> Dict[str, Any]:
    return {
        "protocol": protocol,
        "from_port": from_port,
        "to_port": to_port,
        "direction": "inbound",
        "ip_ranges": [{"cidr": cidr, "description": ""}] if cidr else [],
        "ipv6_ranges": [],
        "user_id_group_pairs": [],
    }


# --------------------------------------------------------------------------
# RDS builders
# --------------------------------------------------------------------------

def make_rds_instance(
    instance_id: str = "test-db",
    publicly_accessible: bool = False,
    storage_encrypted: bool = True,
    engine: str = "mysql",
    backup_retention_period: int = 7,
    deletion_protection: bool = True,
    multi_az: bool = True,
) -> Dict[str, Any]:
    return {
        "id": instance_id,
        "engine": engine,
        "engine_version": "8.0",
        "status": "available",
        "allocated_storage": 20,
        "instance_class": "db.t3.micro",
        "publicly_accessible": publicly_accessible,
        "multi_az": multi_az,
        "encryption": {"storage_encrypted": storage_encrypted, "kms_key_id": None},
        "backup": {
            "backup_retention_period": backup_retention_period,
            "backup_window": "03:00-04:00",
            "copy_tags_to_snapshot": True,
            "deletion_protection": deletion_protection,
        },
        "network": {"vpc_id": "vpc-test", "vpc_security_groups": [], "db_subnet_group": "default"},
        "auto_minor_version_upgrade": True,
        "tags": {},
    }


# --------------------------------------------------------------------------
# IAM builders
# --------------------------------------------------------------------------

WILDCARD_STATEMENT = {"Effect": "Allow", "Action": "*", "Resource": "*"}
SCOPED_STATEMENT = {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::my-bucket/*"]}


def make_iam_user(
    name: str = "test-user",
    inline_policy_documents: Optional[List[Dict[str, Any]]] = None,
    attached_policies: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "arn": f"arn:aws:iam::123456789012:user/{name}",
        "created": "2024-01-01T00:00:00Z",
        "mfa_devices": [],
        "access_keys": [],
        "inline_policies": [d["name"] for d in (inline_policy_documents or [])],
        "inline_policy_documents": inline_policy_documents or [],
        "attached_policies": attached_policies or [],
    }


def make_iam_role(
    name: str = "test-role",
    inline_policy_documents: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "arn": f"arn:aws:iam::123456789012:role/{name}",
        "created": "2024-01-01T00:00:00Z",
        "assume_role_policy": {},
        "inline_policies": [d["name"] for d in (inline_policy_documents or [])],
        "inline_policy_documents": inline_policy_documents or [],
        "attached_policies": [],
    }


def make_managed_policy(
    name: str = "test-policy",
    statements: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    return {
        "name": name,
        "arn": f"arn:aws:iam::123456789012:policy/{name}",
        "created": "2024-01-01T00:00:00Z",
        "update_date": "2024-01-01T00:00:00Z",
        "default_version": "v1",
        "document": {"Version": "2012-10-17", "Statement": statements or [SCOPED_STATEMENT]},
    }


@pytest.fixture
def s3_service():
    def _build(buckets):
        return {"service": "s3", "buckets": buckets}
    return _build


@pytest.fixture
def ec2_service():
    def _build(security_groups=None, instances=None):
        return {"service": "ec2", "security_groups": security_groups or [], "instances": instances or []}
    return _build


@pytest.fixture
def rds_service():
    def _build(instances=None):
        return {"service": "rds", "instances": instances or []}
    return _build


@pytest.fixture
def iam_service():
    def _build(users=None, roles=None, policies=None):
        return {
            "service": "iam",
            "users": users or [],
            "roles": roles or [],
            "policies": policies or [],
            "account_summary": {},
            "credential_report": {"available": False, "rows": []},
            "password_policy": {"exists": False},
        }
    return _build
