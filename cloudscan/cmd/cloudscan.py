"""
CLI entry point for Cloud Misconfiguration Scanner.

Implements the main command-line interface using Click.
"""

import click
import logging
import sys
import json
from pathlib import Path

# Add grandparent directory to path for imports (so cloudscan can be imported)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from cloudscan.config import ScannerConfig
from cloudscan.logger import setup_logging, get_logger
from cloudscan.aws_client import AWSClient
from cloudscan.loaders.aws_live import AWSLiveLoader
from cloudscan.loaders.file_loader import FileLoader
from cloudscan.engine.context import ScanContext
from cloudscan.engine.rule_engine import RuleEngine
from cloudscan.engine.finding import Severity
from cloudscan.output.console import ConsoleOutputFormatter
from cloudscan.output.json import JSONOutputFormatter, JSONLOutputFormatter
from cloudscan.website.scanner import WebsiteScanner
from cloudscan.website.output import WebsiteOutputFormatter

logger = get_logger("cli")


@click.group()
@click.version_option(version="0.1.0", prog_name="cloudscan")
def cli():
    """Cloud Misconfiguration Scanner for AWS.

    Detect security misconfigurations with clear risk, evidence, and remediation.
    """
    pass


@cli.command(name="aws-scan")
@click.option(
    "--config",
    type=click.Path(exists=True),
    default=None,
    help="Path to config.yaml"
)
@click.option(
    "--from-file",
    type=click.Path(exists=True),
    default=None,
    help="Load configuration from JSON/YAML file (offline mode, no AWS credentials needed)"
)
@click.option(
    "--profile",
    default="default",
    help="AWS profile to use (default: default, only used without --from-file)"
)
@click.option(
    "--region",
    default="us-east-1",
    help="AWS region to scan (default: us-east-1, only used without --from-file)"
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
def aws_scan(
    config,
    from_file,
    profile,
    region,
    services,
    severity,
    output,
    output_file,
    log_level,
    fail_on
):
    """Scan for security misconfigurations.

    Supports two modes:
    1. LIVE MODE (requires AWS credentials):
       cloudscan scan --profile myprofile --region us-east-1

    2. OFFLINE MODE (no credentials needed):
       cloudscan scan --from-file exported-config.json

    Perfect for pentesting - analyze exported configs offline!

    Example:

        \b
        # Live scan from AWS
        cloudscan scan

        \b
        # Scan exported configuration (no AWS access needed!)
        cloudscan scan --from-file /path/to/aws-config.json

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
        # Determine data source
        if from_file:
            logger.info(f"Loading configuration from file: {from_file}")
            loader = FileLoader(from_file)
            account_id = "unknown"
            region = "unknown"
        else:
            # Live AWS mode
            logger.info("Loading configuration from AWS APIs")
            
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

            # Create loader for live AWS
            services_to_collect = list(services) if services else ["iam", "s3", "ec2", "rds"]
            loader = AWSLiveLoader(aws_client, services=services_to_collect)

        # Load configuration data
        collected_data = loader.load()

        # PHASE 3: Run security rules
        logger.info("Running security rules...")
        context = ScanContext(account_id, region, collected_data)

        rule_engine = RuleEngine()
        rule_engine.load_rules()
        findings = rule_engine.evaluate(context)

        # Filter by severity if specified
        if severity:
            severity_filter = [Severity[s] for s in severity]
            findings = [f for f in findings if f.severity in severity_filter]

        # PHASE 4: Format output
        logger.info(f"Formatting output ({output} format)...")

        if output == "json":
            formatter = JSONOutputFormatter(output_file=output_file)
        elif output == "jsonl":
            formatter = JSONLOutputFormatter(output_file=output_file)
        else:  # console
            formatter = ConsoleOutputFormatter(output_file=output_file)

        formatted_output = formatter.format(findings)
        formatter.write(formatted_output)

        # Determine exit code
        if fail_on:
            fail_on_severity = Severity[fail_on]
            severity_order = {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
            }

            for finding in findings:
                if severity_order.get(finding.severity, 99) <= severity_order.get(fail_on_severity, 99):
                    logger.warning(f"Found {fail_on} severity finding, exiting with code 1")
                    sys.exit(1)

        logger.info("Scan complete")

    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.argument("url")
@click.option(
    "--output",
    type=click.Choice(["console", "json"]),
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
def website_scan(url, output, output_file, log_level):
    """Scan website for AWS misconfigurations (Stage 1 of pentesting).

    Performs passive reconnaissance to identify AWS infrastructure and
    security misconfigurations exposed on the website.

    Example:

        \b
        # Scan a website
        cloudscan website-scan https://example.com

        \b
        # Save findings to file
        cloudscan website-scan https://example.com --output-file findings.txt

        \b
        # Output as JSON
        cloudscan website-scan https://example.com --output json

        \b
        # If AWS detected, proceed to deep scan
        cloudscan aws-scan --from-file aws-config.json
    """
    setup_logging(log_level=log_level)
    logger.info(f"Starting website scan for: {url}")

    try:
        # Stage 1: Website reconnaissance
        scanner = WebsiteScanner(url)
        indicators = scanner.scan()
        aws_services = scanner.get_aws_services()

        # Format output
        formatter = WebsiteOutputFormatter(output_file=output_file, output_format=output)
        formatted_output = formatter.format(url, indicators, aws_services)
        formatter.write(formatted_output)

        # If AWS detected, suggest next steps
        if aws_services:
            logger.info(f"AWS infrastructure detected: {', '.join(aws_services)}")
            logger.info("Next: Export AWS config and run 'cloudscan aws-scan --from-file config.json'")

    except Exception as e:
        logger.error(f"Website scan failed: {e}", exc_info=True)
        click.secho(f"Error: {e}", fg="red")
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
            click.secho("OK - AWS credentials are valid", fg="green")
            click.echo(f"  Account ID: {account_id}")
            click.echo(f"  Region: {aws_client.region}")
        else:
            click.secho("FAIL - AWS credentials validation failed", fg="red")
            sys.exit(1)

    except Exception as e:
        click.secho(f"FAIL - Validation error: {e}", fg="red")
        logger.error(f"Validation error: {e}", exc_info=True)
        sys.exit(1)


# Alias for backward compatibility
@cli.command(name="scan")
@click.option("--config", type=click.Path(exists=True), default=None)
@click.option("--from-file", type=click.Path(exists=True), default=None)
@click.option("--profile", default="default")
@click.option("--region", default="us-east-1")
@click.option("--services", multiple=True, type=click.Choice(["iam", "s3", "ec2", "rds"]))
@click.option("--severity", multiple=True, type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]))
@click.option("--output", type=click.Choice(["console", "json", "sarif"]), default="console")
@click.option("--output-file", type=click.Path(), default=None)
@click.option("--log-level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]), default="INFO")
@click.option("--fail-on", type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"]), default=None)
def scan(config, from_file, profile, region, services, severity, output, output_file, log_level, fail_on):
    """Scan for misconfigurations (alias for aws-scan for backward compatibility)."""
    # Delegate to aws_scan
    return aws_scan.callback(config, from_file, profile, region, services, severity, output, output_file, log_level, fail_on)


@cli.command()
def version():
    """Show version information."""
    click.echo("Cloud Misconfiguration Scanner v0.1.0")
    click.echo("")
    click.echo("Available Commands:")
    click.echo("  website-scan  - Stage 1: Scan website for AWS misconfigurations")
    click.echo("  aws-scan      - Stage 2: Deep analysis of AWS configurations")
    click.echo("  validate      - Test AWS credentials")
    click.echo("  version       - Show this help")
    click.echo("")
    click.echo("Typical Pentesting Flow:")
    click.echo("  1. cloudscan website-scan https://example.com")
    click.echo("  2. If AWS detected, export config")
    click.echo("  3. cloudscan aws-scan --from-file aws-config.json")


if __name__ == "__main__":
    cli()
