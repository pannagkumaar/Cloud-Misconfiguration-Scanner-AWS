"""
CLI entry point for Cloud Misconfiguration Scanner.

Implements the main command-line interface using Click.
"""

import click
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from cloudscan.config import ScannerConfig
from cloudscan.logger import setup_logging, get_logger
from cloudscan.aws_client import AWSClient

logger = get_logger("cli")


@click.group()
@click.version_option(version="0.1.0", prog_name="cloudscan")
def cli():
    """Cloud Misconfiguration Scanner for AWS.

    Detect security misconfigurations with clear risk, evidence, and remediation.
    """
    pass


@cli.command()
@click.option(
    "--config",
    type=click.Path(exists=True),
    default=None,
    help="Path to config.yaml"
)
@click.option(
    "--profile",
    default="default",
    help="AWS profile to use (default: default)"
)
@click.option(
    "--region",
    default="us-east-1",
    help="AWS region to scan (default: us-east-1)"
)
@click.option(
    "--services",
    multiple=True,
    type=click.Choice(["iam", "s3", "ec2", "rds"]),
    help="Services to scan (default: all)"
)
@click.option(
    "--severity",
    multiple=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
    help="Severity levels to include (default: all)"
)
@click.option(
    "--output",
    type=click.Choice(["console", "json", "sarif"]),
    default="console",
    help="Output format (default: console)"
)
@click.option(
    "--output-file",
    type=click.Path(),
    default=None,
    help="Write findings to file instead of stdout"
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
    default="INFO",
    help="Logging level (default: INFO)"
)
@click.option(
    "--fail-on",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]),
    default=None,
    help="Exit with code 1 if findings at this severity or higher are found"
)
def scan(
    config,
    profile,
    region,
    services,
    severity,
    output,
    output_file,
    log_level,
    fail_on
):
    """Scan AWS account for security misconfigurations.

    Example:

        \b
        # Basic scan
        cloudscan scan

        \b
        # Scan specific services
        cloudscan scan --services s3 ec2

        \b
        # Filter by severity
        cloudscan scan --severity CRITICAL HIGH

        \b
        # Output to JSON
        cloudscan scan --output json --output-file findings.json

        \b
        # Fail on CRITICAL findings
        cloudscan scan --fail-on CRITICAL
    """
    # Setup logging
    setup_logging(log_level=log_level)
    logger.info("Starting scan...")

    try:
        # Load configuration
        config_obj = ScannerConfig(config)
        logger.debug(f"Configuration loaded from {config_obj.config_path}")

        # AWS authentication
        logger.info("Authenticating to AWS...")
        aws_client = AWSClient(
            region=region,
            profile=profile,
            assume_role=config_obj.get("aws.assume_role")
        )

        # Validate credentials
        if not aws_client.validate_credentials():
            logger.error("AWS credentials validation failed")
            sys.exit(1)

        account_id = aws_client.get_account_id()
        logger.info(f"Connected to AWS account: {account_id}")

        # TODO: Implement actual scanning in Phase 2-3
        click.echo("\n" + "=" * 70)
        click.echo("Cloud Misconfiguration Scanner")
        click.echo("=" * 70)
        click.echo(f"Account ID: {account_id}")
        click.echo(f"Region: {region}")
        click.echo(f"Services: {', '.join(services) if services else 'all'}")
        click.echo(f"Severity: {', '.join(severity) if severity else 'all'}")
        click.echo("=" * 70)
        click.echo("\n[INFO] Phase 1 complete. Scanner infrastructure ready.")
        click.echo("\nNext phases:")
        click.echo("  Phase 2: Service collectors (IAM, S3, EC2, RDS)")
        click.echo("  Phase 3: Rule engine and security rules")
        click.echo("  Phase 4: Output formatting")
        click.echo("")

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
def validate():
    """Validate AWS credentials and configuration.

    Useful for testing your setup before running full scans.
    """
    setup_logging(log_level="INFO")
    logger.info("Validating AWS credentials...")

    try:
        aws_client = AWSClient()

        if aws_client.validate_credentials():
            account_id = aws_client.get_account_id()
            click.secho("✓ AWS credentials are valid", fg="green")
            click.echo(f"  Account ID: {account_id}")
            click.echo(f"  Region: {aws_client.region}")
        else:
            click.secho("✗ AWS credentials validation failed", fg="red")
            sys.exit(1)

    except Exception as e:
        click.secho(f"✗ Validation failed: {e}", fg="red")
        logger.error(f"Validation error: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
def version():
    """Show version information."""
    click.echo("Cloud Misconfiguration Scanner v0.1.0")
    click.echo("Phase 1: Core Architecture (Complete)")
    click.echo("Next: Phase 2 - Service Collectors")


if __name__ == "__main__":
    cli()
