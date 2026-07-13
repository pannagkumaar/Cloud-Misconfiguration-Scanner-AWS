"""Tests for cloudscan.loaders.normalize -- the raw AWS -> normalized adapter."""

from cloudscan.loaders.normalize import (
    normalize_cloudtrail,
    normalize_collected_data,
    normalize_ec2,
    normalize_iam,
    normalize_rds,
    normalize_s3,
)


class TestNormalizeS3:
    def test_raw_aws_shape(self):
        raw = {
            "buckets": {
                "Buckets": [
                    {
                        "Name": "my-bucket",
                        "CreationDate": "2024-01-01T00:00:00Z",
                        "Policy": {"Version": "2012-10-17", "Statement": []},
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": False, "IgnorePublicAcls": False,
                            "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
                        },
                    }
                ]
            }
        }
        result = normalize_s3(raw)
        assert result["service"] == "s3"
        assert len(result["buckets"]) == 1
        bucket = result["buckets"][0]
        assert bucket["name"] == "my-bucket"
        assert bucket["policy"] == {"Version": "2012-10-17", "Statement": []}
        assert bucket["public_access_block"]["block_public_acls"] is False

    def test_raw_policy_as_json_string(self):
        """get-bucket-policy via aws-cli returns Policy as a JSON string."""
        raw = {"buckets": {"Buckets": [{
            "Name": "b1", "CreationDate": "x",
            "Policy": '{"Version": "2012-10-17", "Statement": []}',
        }]}}
        result = normalize_s3(raw)
        assert result["buckets"][0]["policy"] == {"Version": "2012-10-17", "Statement": []}

    def test_missing_public_access_block_defaults_to_unblocked(self):
        raw = {"buckets": {"Buckets": [{"Name": "b1", "CreationDate": "x"}]}}
        result = normalize_s3(raw)
        pab = result["buckets"][0]["public_access_block"]
        assert pab == {
            "block_public_acls": False, "ignore_public_acls": False,
            "block_public_policy": False, "restrict_public_buckets": False,
        }

    def test_already_normalized_passthrough(self):
        already = {"buckets": [{
            "name": "b1", "created": "x", "region": "us-east-1",
            "policy": None, "acl": None,
            "public_access_block": {"block_public_acls": True, "ignore_public_acls": True,
                                     "block_public_policy": True, "restrict_public_buckets": True},
            "versioning": None, "logging": None, "encryption": None, "tags": None,
        }]}
        result = normalize_s3(already)
        assert result["buckets"] == already["buckets"]

    def test_empty_input(self):
        result = normalize_s3({})
        assert result == {"service": "s3", "buckets": []}


class TestNormalizeEC2:
    def test_raw_security_groups(self):
        raw = {"security_groups": {"SecurityGroups": [{
            "GroupId": "sg-123", "GroupName": "web", "GroupDescription": "web tier",
            "VpcId": "vpc-1",
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "ssh"}],
            }],
            "IpPermissionsEgress": [],
        }]}}
        result = normalize_ec2(raw)
        sg = result["security_groups"][0]
        assert sg["id"] == "sg-123"
        assert sg["inbound_rules"][0]["ip_ranges"][0]["cidr"] == "0.0.0.0/0"
        assert sg["inbound_rules"][0]["from_port"] == 22

    def test_raw_instances_via_reservations(self):
        raw = {"instances": {"Reservations": [{"Instances": [{
            "InstanceId": "i-1", "State": {"Name": "running"},
            "InstanceType": "t3.micro", "PublicIpAddress": "1.2.3.4",
            "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web"}],
            "Tags": [{"Key": "Name", "Value": "web1"}],
        }]}]}}
        result = normalize_ec2(raw)
        inst = result["instances"][0]
        assert inst["id"] == "i-1"
        assert inst["public_ip"] == "1.2.3.4"
        assert inst["tags"] == {"Name": "web1"}
        assert inst["metadata_options"]["http_tokens"] == "optional"

    def test_already_normalized_passthrough(self):
        already = {
            "security_groups": [{"id": "sg-1", "name": "x", "description": "", "vpc_id": None,
                                  "owner_id": None, "inbound_rules": [], "outbound_rules": []}],
            "instances": [{"id": "i-1", "state": "running", "type": "t3.micro", "vpc_id": None,
                           "subnet_id": None, "public_ip": None, "private_ip": None,
                           "security_groups": [], "metadata_options": {"http_tokens": "required"},
                           "tags": {}}],
        }
        result = normalize_ec2(already)
        assert result["security_groups"] == already["security_groups"]
        assert result["instances"] == already["instances"]

    def test_empty_instances_list_passthrough(self):
        result = normalize_ec2({"instances": []})
        assert result["instances"] == []


class TestNormalizeRDS:
    def test_raw_db_instances_key(self):
        raw = {"db_instances": {"DBInstances": [{
            "DBInstanceIdentifier": "prod-db", "Engine": "mysql",
            "PubliclyAccessible": True, "StorageEncrypted": False,
            "BackupRetentionPeriod": 5, "DeletionProtection": False,
        }]}}
        result = normalize_rds(raw)
        inst = result["instances"][0]
        assert inst["id"] == "prod-db"
        assert inst["publicly_accessible"] is True
        assert inst["encryption"]["storage_encrypted"] is False
        assert inst["backup"]["backup_retention_period"] == 5

    def test_already_normalized_passthrough(self):
        already = {"instances": [{
            "id": "x", "engine": "mysql", "engine_version": "8.0", "status": "available",
            "allocated_storage": 20, "instance_class": "db.t3.micro",
            "publicly_accessible": False, "multi_az": False,
            "encryption": {"storage_encrypted": True, "kms_key_id": None},
            "backup": {"backup_retention_period": 7, "backup_window": None,
                       "copy_tags_to_snapshot": False, "deletion_protection": True},
            "network": {"vpc_id": None, "vpc_security_groups": [], "db_subnet_group": None},
            "auto_minor_version_upgrade": True, "tags": {},
        }]}
        result = normalize_rds(already)
        assert result["instances"] == already["instances"]


class TestNormalizeIAM:
    def test_raw_policies_with_document(self):
        raw = {"policies": {"Policies": [{
            "PolicyName": "admin", "Arn": "arn:aws:iam::123:policy/admin",
            "DefaultVersionId": "v1", "CreateDate": "x",
            "Document": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
        }]}}
        result = normalize_iam(raw)
        policy = result["policies"][0]
        assert policy["name"] == "admin"
        assert policy["document"]["Statement"][0]["Action"] == "*"

    def test_raw_policy_via_policy_version_wrapper(self):
        raw = {"policies": {"Policies": [{
            "PolicyName": "admin", "Arn": "arn:x", "DefaultVersionId": "v1", "CreateDate": "x",
            "PolicyVersion": {"Document": {"Version": "2012-10-17", "Statement": []}},
        }]}}
        result = normalize_iam(raw)
        assert result["policies"][0]["document"] == {"Version": "2012-10-17", "Statement": []}

    def test_raw_users_and_roles(self):
        raw = {
            "users": {"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::123:user/alice", "CreateDate": "x"}]},
            "roles": {"Roles": [{
                "RoleName": "lambda-role", "Arn": "arn:aws:iam::123:role/lambda-role", "CreateDate": "x",
                "AssumeRolePolicyDocument": '{"Version": "2012-10-17", "Statement": []}',
            }]},
        }
        result = normalize_iam(raw)
        assert result["users"][0]["name"] == "alice"
        assert result["roles"][0]["name"] == "lambda-role"
        assert result["roles"][0]["assume_role_policy"] == {"Version": "2012-10-17", "Statement": []}

    def test_inline_policy_documents_from_raw(self):
        raw = {"users": {"Users": [{
            "UserName": "bob", "Arn": "arn:aws:iam::123:user/bob", "CreateDate": "x",
            "InlinePolicies": [{
                "PolicyName": "AdminAccess",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            }],
        }]}}
        result = normalize_iam(raw)
        docs = result["users"][0]["inline_policy_documents"]
        assert len(docs) == 1
        assert docs[0]["name"] == "AdminAccess"
        assert docs[0]["document"]["Statement"][0]["Action"] == "*"

    def test_empty_input(self):
        result = normalize_iam({})
        assert result["users"] == []
        assert result["roles"] == []
        assert result["policies"] == []
        assert result["credential_report"] == {"available": False, "rows": []}


class TestNormalizeCloudTrail:
    def test_raw_trail_list(self):
        raw = {"trails": {"trailList": [{
            "Name": "org-trail", "TrailARN": "arn:aws:cloudtrail:us-east-1:123:trail/org-trail",
            "IsMultiRegionTrail": True, "LogFileValidationEnabled": True,
            "KmsKeyId": "arn:aws:kms:...", "IncludeGlobalServiceEvents": True,
        }]}}
        result = normalize_cloudtrail(raw)
        trail = result["trails"][0]
        assert trail["name"] == "org-trail"
        assert trail["is_multi_region_trail"] is True
        assert trail["log_file_validation_enabled"] is True

    def test_empty_input(self):
        assert normalize_cloudtrail({}) == {"service": "cloudtrail", "trails": []}


class TestNormalizeCollectedData:
    def test_normalizes_every_service(self):
        collected = {
            "services": ["s3", "ec2"],
            "data": {
                "s3": {"buckets": {"Buckets": [{"Name": "b1", "CreationDate": "x"}]}},
                "ec2": {"error": "AccessDenied", "service": "ec2"},
            },
        }
        result = normalize_collected_data(collected)
        assert result["data"]["s3"]["buckets"][0]["name"] == "b1"
        assert result["data"]["ec2"] == {"error": "AccessDenied", "service": "ec2"}
