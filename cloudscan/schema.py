"""
Normalized data contract for Cloud Misconfiguration Scanner.

This module is the single source of truth for the shape of data that flows
from loaders into rules. Both data sources (live AWS collectors and the
offline file loader) MUST produce data matching this shape before it reaches
ScanContext / rules. Rules NEVER see raw AWS API response keys (PascalCase
like "Buckets", "SecurityGroups", "IpPermissions") -- only this normalized,
snake_case shape.

Top-level collected_data structure (what loaders return):

    {
        "services": ["iam", "s3", "ec2", "rds", "cloudtrail"],
        "data": {
            "iam": {...},           # see IAM_SHAPE below
            "s3": {...},            # see S3_SHAPE below
            "ec2": {...},           # see EC2_SHAPE below
            "rds": {...},           # see RDS_SHAPE below
            "cloudtrail": {...},    # see CLOUDTRAIL_SHAPE below
        }
    }

Each service entry may instead be `{"error": "<message>", "service": "<name>"}`
if collection failed for that service; ScanContext.get_service_data() treats
that as empty data.

--------------------------------------------------------------------------
IAM
--------------------------------------------------------------------------
{
    "service": "iam",
    "users": [
        {
            "name": str,
            "arn": str,
            "created": str (ISO8601),
            "mfa_devices": [{"serial": str, "enabled": bool}],
            "access_keys": [{"key_id": str, "status": "Active"|"Inactive", "created": str}],
            "inline_policies": [str],            # policy names (legacy/back-compat)
            "inline_policy_documents": [         # NEW: actual documents
                {"name": str, "document": {...policy JSON...}}
            ],
            "attached_policies": [{"name": str, "arn": str}],
        },
        ...
    ],
    "roles": [
        {
            "name": str,
            "arn": str,
            "created": str,
            "assume_role_policy": {...},
            "inline_policies": [str],
            "inline_policy_documents": [{"name": str, "document": {...}}],
            "attached_policies": [{"name": str, "arn": str}],
        },
        ...
    ],
    "policies": [   # customer-managed policies
        {
            "name": str,
            "arn": str,
            "created": str,
            "update_date": str,
            "default_version": str,
            "document": {...policy JSON...},
        },
        ...
    ],
    "account_summary": {
        "users": int, "roles": int, "policies": int,
        "groups": int, "mfa_devices": int,
    },
    "credential_report": {
        "available": bool,
        "generated": str,
        "rows": [   # NEW: parsed CSV rows, one per IAM user + "<root_account>"
            {
                "user": str,
                "arn": str,
                "is_root": bool,
                "mfa_active": bool,
                "password_enabled": bool,
                "password_last_used": Optional[str],
                "access_key_1_active": bool,
                "access_key_1_last_rotated": Optional[str],
                "access_key_1_last_used": Optional[str],
                "access_key_2_active": bool,
                "access_key_2_last_rotated": Optional[str],
                "access_key_2_last_used": Optional[str],
            },
            ...
        ],
    },
    "password_policy": {   # NEW
        "exists": bool,
        "minimum_password_length": Optional[int],
        "require_symbols": Optional[bool],
        "require_numbers": Optional[bool],
        "require_uppercase_characters": Optional[bool],
        "require_lowercase_characters": Optional[bool],
        "max_password_age": Optional[int],
        "password_reuse_prevention": Optional[int],
    },
}

--------------------------------------------------------------------------
S3
--------------------------------------------------------------------------
{
    "service": "s3",
    "buckets": [
        {
            "name": str,
            "created": str,
            "region": str,
            "policy": Optional[{...bucket policy JSON...}],
            "acl": Optional[{"owner": {...}, "grants": [{"Grantee": {...}, "Permission": str}]}],
            "public_access_block": {
                "block_public_acls": bool, "ignore_public_acls": bool,
                "block_public_policy": bool, "restrict_public_buckets": bool,
            },
            "versioning": Optional[{"status": str, "mfa_delete": str}],
            "logging": Optional[dict],
            "encryption": Optional[dict],   # ServerSideEncryptionConfiguration
            "tags": Optional[dict],
        },
        ...
    ],
}

--------------------------------------------------------------------------
EC2
--------------------------------------------------------------------------
{
    "service": "ec2",
    "security_groups": [
        {
            "id": str, "name": str, "description": str,
            "vpc_id": Optional[str], "owner_id": Optional[str],
            "inbound_rules": [
                {
                    "protocol": str, "from_port": Optional[int], "to_port": Optional[int],
                    "direction": "inbound",
                    "ip_ranges": [{"cidr": str, "description": str}],
                    "ipv6_ranges": [{"cidr": str, "description": str}],
                    "user_id_group_pairs": [{"group_id": str, "user_id": str, "description": str}],
                },
                ...
            ],
            "outbound_rules": [...same shape...],
        },
        ...
    ],
    "instances": [
        {
            "id": str, "state": str, "type": str,
            "vpc_id": Optional[str], "subnet_id": Optional[str],
            "public_ip": Optional[str], "private_ip": Optional[str],
            "security_groups": [{"id": str, "name": str}],
            "metadata_options": {"http_tokens": "required"|"optional"},  # NEW (IMDSv2)
            "tags": dict,
        },
        ...
    ],
}

--------------------------------------------------------------------------
RDS
--------------------------------------------------------------------------
{
    "service": "rds",
    "instances": [
        {
            "id": str, "engine": str, "engine_version": str, "status": str,
            "allocated_storage": Optional[int], "instance_class": Optional[str],
            "publicly_accessible": bool, "multi_az": bool,
            "encryption": {"storage_encrypted": bool, "kms_key_id": Optional[str]},
            "backup": {
                "backup_retention_period": Optional[int], "backup_window": Optional[str],
                "copy_tags_to_snapshot": bool, "deletion_protection": bool,
            },
            "network": {"vpc_id": Optional[str], "vpc_security_groups": [...], "db_subnet_group": Optional[str]},
            "auto_minor_version_upgrade": Optional[bool],   # NEW
            "tags": dict,
        },
        ...
    ],
}

--------------------------------------------------------------------------
CloudTrail (NEW)
--------------------------------------------------------------------------
{
    "service": "cloudtrail",
    "trails": [
        {
            "name": str, "arn": str,
            "is_multi_region_trail": bool,
            "log_file_validation_enabled": bool,
            "kms_key_id": Optional[str],
            "is_logging": bool,
            "s3_bucket_name": Optional[str],
            "include_global_service_events": bool,
        },
        ...
    ],
}
"""

from typing import Any, Dict, List

# Canonical top-level keys expected under data["data"][<service>]
IAM_SHAPE = {
    "users", "roles", "policies", "account_summary",
    "credential_report", "password_policy",
}
S3_SHAPE = {"buckets"}
EC2_SHAPE = {"security_groups", "instances"}
RDS_SHAPE = {"instances"}
CLOUDTRAIL_SHAPE = {"trails"}

SERVICE_SHAPES = {
    "iam": IAM_SHAPE,
    "s3": S3_SHAPE,
    "ec2": EC2_SHAPE,
    "rds": RDS_SHAPE,
    "cloudtrail": CLOUDTRAIL_SHAPE,
}


def empty_service_data(service: str) -> Dict[str, Any]:
    """Return an empty-but-valid normalized payload for a service."""
    if service == "iam":
        return {
            "service": "iam",
            "users": [],
            "roles": [],
            "policies": [],
            "account_summary": {},
            "credential_report": {"available": False, "rows": []},
            "password_policy": {"exists": False},
        }
    if service == "s3":
        return {"service": "s3", "buckets": []}
    if service == "ec2":
        return {"service": "ec2", "security_groups": [], "instances": []}
    if service == "rds":
        return {"service": "rds", "instances": []}
    if service == "cloudtrail":
        return {"service": "cloudtrail", "trails": []}
    return {"service": service}


# Top-level keys per service that hold a *list* of resources once normalized.
# Raw AWS API responses wrap the same resources in a dict envelope instead
# (e.g. {"buckets": {"Buckets": [...]}} vs normalized {"buckets": [...]}),
# so checking the runtime type of these keys is a reliable normalization
# signal -- unlike checking key *names*, which can coincidentally collide
# between raw export scripts and the normalized shape.
_LIST_KEYS = {
    "iam": {"users", "roles", "policies"},
    "s3": {"buckets"},
    "ec2": {"security_groups", "instances"},
    "rds": {"instances"},
    "cloudtrail": {"trails"},
}


def is_normalized(service: str, payload: Dict[str, Any]) -> bool:
    """
    Best-effort check: does this payload already match the normalized shape
    for `service`, as opposed to a raw AWS API response?

    This is a diagnostic helper (used by `validate()`); the file loader does
    NOT gate normalization on this, since normalize_* functions are
    idempotent and safe to run on already-normalized data.
    """
    if not isinstance(payload, dict):
        return False

    list_keys = _LIST_KEYS.get(service)
    if list_keys is None:
        return True  # unknown service, assume caller knows what they're doing

    for key in list_keys:
        if key in payload and not isinstance(payload[key], list):
            return False

    return True


def validate(collected_data: Dict[str, Any]) -> List[str]:
    """
    Validate collected_data against the normalized contract.

    Returns a list of human-readable problems (empty list = valid).
    This is intentionally permissive -- it flags obvious structural issues
    without being a full JSON-Schema validator.
    """
    problems: List[str] = []

    if not isinstance(collected_data, dict):
        return ["collected_data must be a dict"]

    if "services" not in collected_data or "data" not in collected_data:
        return ["collected_data must have 'services' and 'data' keys"]

    if not isinstance(collected_data["services"], list):
        problems.append("'services' must be a list")

    data = collected_data.get("data", {})
    if not isinstance(data, dict):
        return problems + ["'data' must be a dict"]

    for service, payload in data.items():
        if not isinstance(payload, dict):
            problems.append(f"{service}: payload must be a dict")
            continue
        if "error" in payload:
            continue  # collection failure is a valid (if degraded) state
        if service in SERVICE_SHAPES and not is_normalized(service, payload):
            problems.append(
                f"{service}: payload does not look normalized "
                f"(found keys {sorted(payload.keys())})"
            )

    return problems
