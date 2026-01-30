"""
AWS authentication and client management.

Handles AWS credential configuration and boto3 client creation.
"""

import logging
from typing import Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


logger = logging.getLogger(__name__)


class AWSClient:
    """Manages AWS authentication and client creation."""

    def __init__(
        self,
        region: str = "us-east-1",
        profile: Optional[str] = None,
        assume_role: Optional[str] = None
    ):
        """
        Initialize AWS client manager.

        Args:
            region: AWS region to connect to
            profile: AWS profile to use from credentials
            assume_role: Optional IAM role ARN to assume

        Raises:
            NoCredentialsError: If AWS credentials are not configured
        """
        self.region = region
        self.profile = profile
        self.assume_role = assume_role

        # Create session
        session_kwargs = {}
        if profile:
            session_kwargs["profile_name"] = profile

        try:
            self.session = boto3.Session(**session_kwargs)
        except NoCredentialsError as e:
            logger.error(
                "AWS credentials not found. Configure via ~/.aws/credentials or env vars"
            )
            raise

        # If assuming role, do that now
        if assume_role:
            self._assume_role(assume_role)

        self._clients: Dict[str, Any] = {}
        logger.info(f"AWS client initialized (region={region}, profile={profile})")

    def _assume_role(self, role_arn: str) -> None:
        """
        Assume an IAM role for additional permissions.

        Args:
            role_arn: ARN of role to assume
        """
        sts = self.session.client("sts", region_name=self.region)

        try:
            assumed_role = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="cloudscan-session"
            )

            credentials = assumed_role["Credentials"]
            self.session = boto3.Session(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
                region_name=self.region
            )

            logger.info(f"Successfully assumed role: {role_arn}")

        except ClientError as e:
            logger.error(f"Failed to assume role {role_arn}: {e}")
            raise

    def get_client(self, service_name: str) -> Any:
        """
        Get or create a boto3 client for a service.

        Args:
            service_name: AWS service name (iam, s3, ec2, rds, etc.)

        Returns:
            boto3 service client

        Raises:
            ClientError: If client creation fails
        """
        if service_name not in self._clients:
            try:
                self._clients[service_name] = self.session.client(
                    service_name,
                    region_name=self.region
                )
                logger.debug(f"Created {service_name} client")

            except ClientError as e:
                logger.error(f"Failed to create {service_name} client: {e}")
                raise

        return self._clients[service_name]

    def get_account_id(self) -> str:
        """
        Get AWS account ID.

        Returns:
            AWS account ID as string

        Raises:
            ClientError: If STS call fails
        """
        try:
            sts = self.get_client("sts")
            response = sts.get_caller_identity()
            account_id = response["Account"]
            logger.debug(f"Account ID: {account_id}")
            return account_id

        except ClientError as e:
            logger.error(f"Failed to get account ID: {e}")
            raise

    def validate_credentials(self) -> bool:
        """
        Validate AWS credentials are working.

        Returns:
            True if credentials are valid
        """
        try:
            self.get_account_id()
            logger.info("AWS credentials validated successfully")
            return True

        except Exception as e:
            logger.error(f"Credentials validation failed: {e}")
            return False
