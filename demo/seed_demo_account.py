"""
Seed a moto-simulated "vulnerable" AWS account and run a full CloudScan
scan against it -- no real AWS account, credentials, or cost required.

This is the primary "try it yourself" path for the project: it proves the
whole pipeline (boto3 collectors -> normalized context -> rule engine ->
formatter) against real boto3 API responses, not just hand-built fixtures.

Usage:
    python demo/seed_demo_account.py
    python demo/seed_demo_account.py --output json
    python demo/seed_demo_account.py --output html --output-file report.html
"""

import argparse
import json
import os
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from moto import mock_aws

from cloudscan.aws_client import AWSClient
from cloudscan.collectors.manager import CollectorManager
from cloudscan.engine.context import ScanContext
from cloudscan.engine.rule_engine import RuleEngine
from cloudscan.output.console import ConsoleOutputFormatter
from cloudscan.output.json import JSONLOutputFormatter, JSONOutputFormatter

REGION = "us-east-1"
ACCOUNT_ID = "123456789012"

PUBLIC_BUCKET = "cloudscan-demo-public-bucket"
SECURE_BUCKET = "cloudscan-demo-secure-bucket"
OPEN_SG_NAME = "cloudscan-demo-open-ssh"
RESTRICTED_SG_NAME = "cloudscan-demo-restricted"
DEMO_USER = "cloudscan-demo-user"
DEMO_POLICY = "cloudscan-demo-admin-policy"
PUBLIC_DB = "cloudscan-demo-public-db"
SECURE_DB = "cloudscan-demo-secure-db"

ADMIN_DOCUMENT = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
})


def seed_vulnerable_account(aws_client: AWSClient) -> None:
    """
    Populate the (moto-mocked) account with intentionally misconfigured
    resources side by side with equivalent secure ones, so a scan
    demonstrates both true positives and the absence of false positives.
    """
    _seed_s3(aws_client)
    _seed_ec2(aws_client)
    _seed_iam(aws_client)
    _seed_rds(aws_client)


def _seed_s3(aws_client: AWSClient) -> None:
    s3 = aws_client.get_client("s3")

    s3.create_bucket(Bucket=PUBLIC_BUCKET)
    s3.put_bucket_policy(Bucket=PUBLIC_BUCKET, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{PUBLIC_BUCKET}/*",
        }],
    }))
    s3.put_public_access_block(Bucket=PUBLIC_BUCKET, PublicAccessBlockConfiguration={
        "BlockPublicAcls": False, "IgnorePublicAcls": False,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
    })

    s3.create_bucket(Bucket=SECURE_BUCKET)
    s3.put_public_access_block(Bucket=SECURE_BUCKET, PublicAccessBlockConfiguration={
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    })
    s3.put_bucket_encryption(Bucket=SECURE_BUCKET, ServerSideEncryptionConfiguration={
        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
    })
    s3.put_bucket_versioning(Bucket=SECURE_BUCKET, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_policy(Bucket=SECURE_BUCKET, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{SECURE_BUCKET}", f"arn:aws:s3:::{SECURE_BUCKET}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }],
    }))


def _seed_ec2(aws_client: AWSClient) -> None:
    ec2 = aws_client.get_client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

    open_sg = ec2.create_security_group(
        GroupName=OPEN_SG_NAME, Description="Open to the world (demo)", VpcId=vpc_id
    )
    ec2.authorize_security_group_ingress(
        GroupId=open_sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "any"}],
        }],
    )

    restricted_sg = ec2.create_security_group(
        GroupName=RESTRICTED_SG_NAME, Description="Internal only (demo)", VpcId=vpc_id
    )
    ec2.authorize_security_group_ingress(
        GroupId=restricted_sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8", "Description": "internal only"}],
        }],
    )


def _seed_iam(aws_client: AWSClient) -> None:
    iam = aws_client.get_client("iam")

    iam.create_user(UserName=DEMO_USER)
    iam.put_user_policy(
        UserName=DEMO_USER, PolicyName="AdminAccess", PolicyDocument=ADMIN_DOCUMENT
    )

    iam.create_policy(PolicyName=DEMO_POLICY, PolicyDocument=ADMIN_DOCUMENT)


def _seed_rds(aws_client: AWSClient) -> None:
    rds = aws_client.get_client("rds")

    rds.create_db_instance(
        DBInstanceIdentifier=PUBLIC_DB,
        Engine="mysql", DBInstanceClass="db.t3.micro",
        MasterUsername="admin", MasterUserPassword="SuperSecret123!",
        AllocatedStorage=20, PubliclyAccessible=True, StorageEncrypted=False,
    )
    rds.create_db_instance(
        DBInstanceIdentifier=SECURE_DB,
        Engine="postgres", DBInstanceClass="db.t3.micro",
        MasterUsername="admin", MasterUserPassword="SuperSecret123!",
        AllocatedStorage=20, PubliclyAccessible=False, StorageEncrypted=True,
        BackupRetentionPeriod=7, DeletionProtection=True, MultiAZ=True,
        AutoMinorVersionUpgrade=True,
    )


def _set_dummy_credentials() -> None:
    """moto intercepts AWS calls before they reach the network, but boto3
    still wants credential-shaped strings to build a session."""
    for key, value in [
        ("AWS_ACCESS_KEY_ID", "testing"),
        ("AWS_SECRET_ACCESS_KEY", "testing"),
        ("AWS_SECURITY_TOKEN", "testing"),
        ("AWS_SESSION_TOKEN", "testing"),
        ("AWS_DEFAULT_REGION", REGION),
    ]:
        os.environ.setdefault(key, value)


def run_scan(output: str = "console", output_file: str = None):
    """Seed the demo account and run a full scan, returning the findings."""
    _set_dummy_credentials()

    with mock_aws():
        aws_client = AWSClient(region=REGION)
        seed_vulnerable_account(aws_client)

        manager = CollectorManager(aws_client)
        collected = manager.collect_all()

        context = ScanContext(ACCOUNT_ID, REGION, collected)
        engine = RuleEngine()
        engine.load_rules()
        findings = engine.evaluate(context)

    formatter = _build_formatter(output, output_file)
    formatted = formatter.format(findings)
    formatter.write(formatted)

    return findings


def _build_formatter(output: str, output_file: str):
    if output == "json":
        return JSONOutputFormatter(output_file=output_file)
    if output == "jsonl":
        return JSONLOutputFormatter(output_file=output_file)
    if output == "html":
        # Imported lazily so `console`/`json` output doesn't require the
        # HTML formatter module to exist.
        from cloudscan.output.html import HTMLOutputFormatter
        return HTMLOutputFormatter(output_file=output_file)
    return ConsoleOutputFormatter(output_file=output_file)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run CloudScan against a simulated vulnerable AWS account "
            "(moto-mocked, no real AWS account or cost)."
        )
    )
    parser.add_argument(
        "--output", choices=["console", "json", "jsonl", "html"], default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--output-file", default=None, help="Write findings to file instead of stdout"
    )
    args = parser.parse_args()
    run_scan(output=args.output, output_file=args.output_file)


if __name__ == "__main__":
    main()
