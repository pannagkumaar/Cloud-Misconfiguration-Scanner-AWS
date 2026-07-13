"""
Raw AWS API -> normalized schema adapter.

Exported configuration (via `aws` CLI / `scripts/export_aws_config.*`) comes
back in raw AWS API shape: PascalCase keys, nested response envelopes
("Buckets", "SecurityGroups", "IpPermissions", "DBInstances", "CidrIp", ...).

Rules and ScanContext only understand the normalized shape documented in
cloudscan/schema.py (snake_case, collector-produced). This module bridges
the two so `--from-file` works identically whether the file was produced by
our export scripts (raw AWS shape) or is already normalized (e.g. dumped
from a previous live scan).

Each normalize_* function is defensive: missing keys become empty
lists/dicts rather than raising, since exports may be partial (e.g. a
service the caller didn't have permission to enumerate).
"""

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def _parse_json_maybe(value: Any) -> Dict[str, Any]:
    """Return value as a dict, parsing it from a JSON string if needed."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            logger.debug("Could not parse JSON string policy document")
            return {}
    return {}


def _iso(value: Any) -> str:
    """Best-effort stringification of a date-ish value."""
    if value is None:
        return ""
    return str(value)


# --------------------------------------------------------------------------
# IAM
# --------------------------------------------------------------------------

def normalize_iam(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw IAM export into the schema.py IAM shape."""
    if not isinstance(raw, dict):
        raw = {}

    users_raw = raw.get("users", raw.get("Users", {}))
    users_list = users_raw.get("Users", users_raw) if isinstance(users_raw, dict) else users_raw
    users = []
    for u in users_list or []:
        if not isinstance(u, dict):
            continue
        users.append({
            "name": u.get("UserName") or u.get("name", ""),
            "arn": u.get("Arn") or u.get("arn", ""),
            "created": _iso(u.get("CreateDate") or u.get("created")),
            "mfa_devices": u.get("mfa_devices", []),
            "access_keys": u.get("access_keys", []),
            "inline_policies": u.get("inline_policies", []),
            "inline_policy_documents": [
                {"name": p.get("PolicyName") or p.get("name", ""),
                 "document": _parse_json_maybe(p.get("PolicyDocument") or p.get("document"))}
                for p in (u.get("InlinePolicies") or u.get("inline_policy_documents") or [])
                if isinstance(p, dict)
            ],
            "attached_policies": [
                {"name": p.get("PolicyName") or p.get("name", ""),
                 "arn": p.get("PolicyArn") or p.get("arn", "")}
                for p in (u.get("AttachedPolicies") or u.get("attached_policies") or [])
                if isinstance(p, dict)
            ],
        })

    roles_raw = raw.get("roles", raw.get("Roles", {}))
    roles_list = roles_raw.get("Roles", roles_raw) if isinstance(roles_raw, dict) else roles_raw
    roles = []
    for r in roles_list or []:
        if not isinstance(r, dict):
            continue
        roles.append({
            "name": r.get("RoleName") or r.get("name", ""),
            "arn": r.get("Arn") or r.get("arn", ""),
            "created": _iso(r.get("CreateDate") or r.get("created")),
            "assume_role_policy": _parse_json_maybe(
                r.get("AssumeRolePolicyDocument") or r.get("assume_role_policy")
            ),
            "inline_policies": r.get("inline_policies", []),
            "inline_policy_documents": [
                {"name": p.get("PolicyName") or p.get("name", ""),
                 "document": _parse_json_maybe(p.get("PolicyDocument") or p.get("document"))}
                for p in (r.get("InlinePolicies") or r.get("inline_policy_documents") or [])
                if isinstance(p, dict)
            ],
            "attached_policies": [
                {"name": p.get("PolicyName") or p.get("name", ""),
                 "arn": p.get("PolicyArn") or p.get("arn", "")}
                for p in (r.get("AttachedPolicies") or r.get("attached_policies") or [])
                if isinstance(p, dict)
            ],
        })

    policies_raw = raw.get("policies", raw.get("Policies", {}))
    policies_list = policies_raw.get("Policies", policies_raw) if isinstance(policies_raw, dict) else policies_raw
    policies = []
    for p in policies_list or []:
        if not isinstance(p, dict):
            continue
        document = (
            p.get("document")
            or p.get("Document")
            or (p.get("PolicyVersion") or {}).get("Document")
        )
        policies.append({
            "name": p.get("PolicyName") or p.get("name", ""),
            "arn": p.get("Arn") or p.get("arn", ""),
            "created": _iso(p.get("CreateDate") or p.get("created")),
            "update_date": _iso(p.get("UpdateDate") or p.get("update_date") or p.get("CreateDate")),
            "default_version": p.get("DefaultVersionId") or p.get("default_version", ""),
            "document": _parse_json_maybe(document),
        })

    credential_report = raw.get("credential_report", {"available": False, "rows": []})
    if "rows" not in credential_report:
        credential_report["rows"] = []

    password_policy = raw.get("password_policy", {"exists": False})

    return {
        "service": "iam",
        "users": users,
        "roles": roles,
        "policies": policies,
        "account_summary": raw.get("account_summary", {}),
        "credential_report": credential_report,
        "password_policy": password_policy,
    }


# --------------------------------------------------------------------------
# S3
# --------------------------------------------------------------------------

def _normalize_public_access_block(raw_bucket: Dict[str, Any]) -> Dict[str, Optional[bool]]:
    pab = (
        raw_bucket.get("public_access_block")
        or raw_bucket.get("PublicAccessBlockConfiguration")
        or {}
    )
    if not pab:
        return {
            "block_public_acls": False,
            "ignore_public_acls": False,
            "block_public_policy": False,
            "restrict_public_buckets": False,
        }
    return {
        "block_public_acls": pab.get("block_public_acls", pab.get("BlockPublicAcls", False)),
        "ignore_public_acls": pab.get("ignore_public_acls", pab.get("IgnorePublicAcls", False)),
        "block_public_policy": pab.get("block_public_policy", pab.get("BlockPublicPolicy", False)),
        "restrict_public_buckets": pab.get("restrict_public_buckets", pab.get("RestrictPublicBuckets", False)),
    }


def _normalize_acl(raw_bucket: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    acl = raw_bucket.get("acl")
    if acl:
        return acl
    grants = raw_bucket.get("Grants")
    if grants is None:
        return None
    return {"owner": raw_bucket.get("Owner", {}), "grants": grants}


def normalize_s3(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw S3 export into the schema.py S3 shape."""
    if not isinstance(raw, dict):
        raw = {}

    buckets_raw = raw.get("buckets", raw.get("Buckets", {}))
    buckets_list = buckets_raw.get("Buckets", buckets_raw) if isinstance(buckets_raw, dict) else buckets_raw

    buckets = []
    for b in buckets_list or []:
        if not isinstance(b, dict):
            continue

        # Already-normalized bucket (has lowercase "name")
        if "name" in b:
            buckets.append({
                "name": b.get("name"),
                "created": _iso(b.get("created")),
                "region": b.get("region", "unknown"),
                "policy": b.get("policy"),
                "acl": b.get("acl"),
                "public_access_block": _normalize_public_access_block(b),
                "versioning": b.get("versioning"),
                "logging": b.get("logging"),
                "encryption": b.get("encryption"),
                "tags": b.get("tags"),
            })
            continue

        policy = _parse_json_maybe(b.get("Policy")) or None
        versioning_raw = b.get("VersioningConfiguration")
        versioning = None
        if versioning_raw:
            versioning = {
                "status": versioning_raw.get("Status"),
                "mfa_delete": versioning_raw.get("MFADelete"),
            }

        buckets.append({
            "name": b.get("Name", ""),
            "created": _iso(b.get("CreationDate")),
            "region": b.get("Region", "unknown"),
            "policy": policy,
            "acl": _normalize_acl(b),
            "public_access_block": _normalize_public_access_block(b),
            "versioning": versioning,
            "logging": b.get("LoggingEnabled"),
            "encryption": b.get("ServerSideEncryptionConfiguration"),
            "tags": {t["Key"]: t["Value"] for t in b.get("TagSet", [])} if b.get("TagSet") else None,
        })

    return {"service": "s3", "buckets": buckets}


# --------------------------------------------------------------------------
# EC2
# --------------------------------------------------------------------------

def _normalize_sg_rule(rule: Dict[str, Any], direction: str) -> Dict[str, Any]:
    # Already-normalized rule
    if "ip_ranges" in rule:
        return rule

    return {
        "protocol": rule.get("IpProtocol", "-1"),
        "from_port": rule.get("FromPort"),
        "to_port": rule.get("ToPort"),
        "direction": direction,
        "ip_ranges": [
            {"cidr": r.get("CidrIp"), "description": r.get("Description", "")}
            for r in rule.get("IpRanges", [])
        ],
        "ipv6_ranges": [
            {"cidr": r.get("CidrIpv6"), "description": r.get("Description", "")}
            for r in rule.get("Ipv6Ranges", [])
        ],
        "user_id_group_pairs": [
            {"group_id": r.get("GroupId"), "user_id": r.get("UserId"), "description": r.get("Description", "")}
            for r in rule.get("UserIdGroupPairs", [])
        ],
    }


def normalize_ec2(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw EC2 export into the schema.py EC2 shape."""
    if not isinstance(raw, dict):
        raw = {}

    sg_raw = raw.get("security_groups", raw.get("SecurityGroups", {}))
    sg_list = sg_raw.get("SecurityGroups", sg_raw) if isinstance(sg_raw, dict) else sg_raw

    security_groups = []
    for sg in sg_list or []:
        if not isinstance(sg, dict):
            continue
        if "id" in sg and "inbound_rules" in sg:
            security_groups.append(sg)
            continue

        security_groups.append({
            "id": sg.get("GroupId", ""),
            "name": sg.get("GroupName", ""),
            "description": sg.get("GroupDescription", sg.get("Description", "")),
            "vpc_id": sg.get("VpcId"),
            "owner_id": sg.get("OwnerId"),
            "inbound_rules": [
                _normalize_sg_rule(r, "inbound") for r in sg.get("IpPermissions", [])
            ],
            "outbound_rules": [
                _normalize_sg_rule(r, "outbound") for r in sg.get("IpPermissionsEgress", [])
            ],
        })

    instances_raw = raw.get("instances", raw.get("Reservations", {}))
    if isinstance(instances_raw, dict) and "Reservations" in instances_raw:
        reservations = instances_raw["Reservations"]
    elif isinstance(instances_raw, list) and instances_raw and isinstance(instances_raw[0], dict) and "id" in instances_raw[0]:
        # already-normalized instance list
        reservations = None
    else:
        reservations = instances_raw if isinstance(instances_raw, list) else []

    instances = []
    if reservations is None:
        instances = instances_raw
    else:
        for reservation in reservations or []:
            for inst in reservation.get("Instances", []):
                metadata_opts = inst.get("MetadataOptions", {})
                instances.append({
                    "id": inst.get("InstanceId", ""),
                    "state": inst.get("State", {}).get("Name", ""),
                    "type": inst.get("InstanceType"),
                    "vpc_id": inst.get("VpcId"),
                    "subnet_id": inst.get("SubnetId"),
                    "public_ip": inst.get("PublicIpAddress"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "security_groups": [
                        {"id": sg.get("GroupId"), "name": sg.get("GroupName")}
                        for sg in inst.get("SecurityGroups", [])
                    ],
                    "metadata_options": {
                        "http_tokens": metadata_opts.get("HttpTokens", "optional"),
                    },
                    "tags": {t["Key"]: t["Value"] for t in inst.get("Tags", [])},
                })

    return {"service": "ec2", "security_groups": security_groups, "instances": instances}


# --------------------------------------------------------------------------
# RDS
# --------------------------------------------------------------------------

def normalize_rds(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw RDS export into the schema.py RDS shape."""
    if not isinstance(raw, dict):
        raw = {}

    instances_raw = raw.get("instances", raw.get("db_instances", raw.get("DBInstances", {})))
    instances_list = (
        instances_raw.get("DBInstances", instances_raw)
        if isinstance(instances_raw, dict) else instances_raw
    )

    instances = []
    for inst in instances_list or []:
        if not isinstance(inst, dict):
            continue
        if "id" in inst and "encryption" in inst:
            instances.append(inst)
            continue

        subnet_group = inst.get("DBSubnetGroup", {}) or {}
        instances.append({
            "id": inst.get("DBInstanceIdentifier", ""),
            "engine": inst.get("Engine"),
            "engine_version": inst.get("EngineVersion"),
            "status": inst.get("DBInstanceStatus"),
            "allocated_storage": inst.get("AllocatedStorage"),
            "instance_class": inst.get("DBInstanceClass"),
            "publicly_accessible": inst.get("PubliclyAccessible", False),
            "multi_az": inst.get("MultiAZ", False),
            "encryption": {
                "storage_encrypted": inst.get("StorageEncrypted", False),
                "kms_key_id": inst.get("KmsKeyId"),
            },
            "backup": {
                "backup_retention_period": inst.get("BackupRetentionPeriod"),
                "backup_window": inst.get("PreferredBackupWindow"),
                "copy_tags_to_snapshot": inst.get("CopyTagsToSnapshot", False),
                "deletion_protection": inst.get("DeletionProtection", False),
            },
            "network": {
                "vpc_id": subnet_group.get("VpcId"),
                "vpc_security_groups": [
                    {"id": sg.get("VpcSecurityGroupId"), "status": sg.get("Status")}
                    for sg in inst.get("VpcSecurityGroups", [])
                ],
                "db_subnet_group": subnet_group.get("DBSubnetGroupName"),
            },
            "auto_minor_version_upgrade": inst.get("AutoMinorVersionUpgrade"),
            "tags": {t["Key"]: t["Value"] for t in inst.get("TagList", [])} if inst.get("TagList") else {},
        })

    return {"service": "rds", "instances": instances}


# --------------------------------------------------------------------------
# CloudTrail
# --------------------------------------------------------------------------

def normalize_cloudtrail(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a raw CloudTrail export into the schema.py CloudTrail shape."""
    if not isinstance(raw, dict):
        raw = {}

    trails_raw = raw.get("trails", raw.get("trailList", raw.get("Trails", {})))
    trails_list = (
        trails_raw.get("trailList", trails_raw)
        if isinstance(trails_raw, dict) else trails_raw
    )

    trails = []
    for t in trails_list or []:
        if not isinstance(t, dict):
            continue
        if "name" in t and "is_multi_region_trail" in t:
            trails.append(t)
            continue

        trails.append({
            "name": t.get("Name", ""),
            "arn": t.get("TrailARN", t.get("Arn", "")),
            "is_multi_region_trail": t.get("IsMultiRegionTrail", False),
            "log_file_validation_enabled": t.get("LogFileValidationEnabled", False),
            "kms_key_id": t.get("KmsKeyId"),
            "is_logging": t.get("IsLogging", t.get("is_logging", False)),
            "s3_bucket_name": t.get("S3BucketName"),
            "include_global_service_events": t.get("IncludeGlobalServiceEvents", False),
        })

    return {"service": "cloudtrail", "trails": trails}


NORMALIZERS = {
    "iam": normalize_iam,
    "s3": normalize_s3,
    "ec2": normalize_ec2,
    "rds": normalize_rds,
    "cloudtrail": normalize_cloudtrail,
}


def normalize_service_data(service: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a single service's payload into the schema.py shape.

    Each normalize_* function is internally idempotent: it recognizes both
    raw AWS API envelopes (PascalCase, nested under "Buckets"/"Users"/...)
    and already-normalized items (which it passes through unchanged), so we
    always run the normalizer rather than trying to pre-detect the input
    shape. Pre-detection based on top-level key names is unreliable because
    export scripts may choose lowercase container keys (e.g. "buckets") that
    coincidentally match the normalized shape while still wrapping raw AWS
    envelopes underneath.

    If the service is unknown, the payload is returned unchanged.
    """
    if not isinstance(payload, dict) or "error" in payload:
        return payload

    normalizer = NORMALIZERS.get(service)
    if normalizer is None:
        return payload

    return normalizer(payload)


def normalize_collected_data(collected_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize every service payload in a full collected_data structure.

    Safe to call on already-normalized data (no-op per service).
    """
    data = collected_data.get("data", {})
    normalized = {
        service: normalize_service_data(service, payload)
        for service, payload in data.items()
    }
    return {**collected_data, "data": normalized}
