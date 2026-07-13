# CloudScan

[![CI](https://github.com/pannagkumaar/Cloud-Misconfiguration-Scanner-AWS/actions/workflows/ci.yml/badge.svg)](https://github.com/pannagkumaar/Cloud-Misconfiguration-Scanner-AWS/actions/workflows/ci.yml)

Python / boto3 / Click / SARIF / CIS Benchmark / moto / pytest

An agentless AWS Cloud Security Posture Management (CSPM) CLI. CloudScan reads AWS
resource configuration (live, via read-only IAM, or offline from an exported JSON
snapshot) and evaluates it against 31 security rules spanning IAM, S3, EC2/VPC, RDS,
and CloudTrail. Each finding comes with evidence, a remediation, and (where
applicable) a CIS AWS Foundations Benchmark control reference.

## Why this exists

Most "misconfiguration scanner" toy projects hardcode four rules and call it done.
CloudScan is built the way a real CSPM tool is structured, with a normalized data
contract between collection and evaluation, rules that are independently unit
tested against that contract, moto-backed integration tests that catch real
boto3 API bugs (not just logic bugs), CI that runs the full suite plus a
self-seeded demo account, and output formats that integrate with actual
tooling, including SARIF for GitHub Code Scanning and a self-contained HTML
report for sharing with people who don't want a JSON blob.

## Quick start

### Install

```bash
git clone https://github.com/pannagkumaar/Cloud-Misconfiguration-Scanner-AWS.git
cd Cloud-Misconfiguration-Scanner-AWS
python -m venv .venv
source .venv/bin/activate   # on Windows use .venv\Scripts\activate

pip install -e .            # installs the `cloudscan` command
pip install -e ".[dev]"     # + pytest, ruff, moto, pre-commit (for development)
```

### Try it without an AWS account

CloudScan ships a demo that seeds an in-memory mock AWS account (via
[moto](https://github.com/getmoto/moto), no network calls, no real credentials)
with a deliberately vulnerable mix of resources, then scans it.

```bash
make demo              # console output
make demo-html         # writes report.html, open it in a browser
```

Or run it directly.

```bash
python demo/seed_demo_account.py --output html --output-file report.html
```

### Scan a real account (read-only)

```bash
cloudscan aws-scan --profile myprofile --region us-east-1
```

This only calls read (`Describe*`/`Get*`/`List*`) APIs. See
[Required IAM policy](#required-iam-policy) below for the exact permission set.

### Scan an offline export (no AWS access needed)

```bash
cloudscan aws-scan --from-file examples/sample-aws-config.json
```

Useful for pentest engagements or reviewing a config someone handed you, without
ever touching their credentials.

## What it checks

31 rules across 5 services. Every rule has a stable ID, a severity, and (where
one exists) a CIS AWS Foundations Benchmark v1.4/1.5 control reference.

### IAM (9 rules)

| ID | Severity | Check | CIS |
|----|----------|-------|-----|
| IAM-001 | CRITICAL | Policy grants full administrative access (wildcard action and resource) | 1.18 |
| IAM-002 | CRITICAL | Root account has no MFA | 1.5 |
| IAM-003 | CRITICAL | Root account has an active access key | 1.4 |
| IAM-004 | HIGH | IAM user has console access without MFA | 1.10 |
| IAM-005 | MEDIUM | Access key not rotated in 90+ days | 1.14 |
| IAM-006 | MEDIUM | Credential unused for 90+ days | 1.12 |
| IAM-007 | MEDIUM | Account password policy is weak or missing | 1.8 |
| IAM-008 | MEDIUM | Policy grants overly broad permissions | n/a |
| IAM-009 | LOW | Policy attached directly to a user (not a group/role) | 1.15 |

### S3 (6 rules)

| ID | Severity | Check | CIS |
|----|----------|-------|-----|
| S3-001 | HIGH | Bucket is publicly accessible | 2.1.5.1 |
| S3-002 | MEDIUM | Default encryption not enabled | 2.1.1 |
| S3-003 | LOW | Versioning disabled | n/a |
| S3-004 | LOW | Access logging disabled | n/a |
| S3-005 | MEDIUM | Block Public Access not fully enabled | 2.1.5.1 |
| S3-006 | MEDIUM | Bucket policy does not enforce TLS | n/a |

### EC2 / VPC (6 rules)

| ID | Severity | Check | CIS |
|----|----------|-------|-----|
| SG-001 | HIGH | Security group open to 0.0.0.0/0 on SSH/RDP | n/a |
| SG-002 | MEDIUM | Security group open to 0.0.0.0/0 on another port | n/a |
| SG-003 | HIGH | Security group open to the IPv6 equivalent of 0.0.0.0/0 on SSH/RDP | n/a |
| SG-004 | LOW | Default security group allows traffic | 5.3 |
| EC2-001 | HIGH | Instance has a public IP behind an open security group | n/a |
| EC2-002 | MEDIUM | Instance does not enforce IMDSv2 | n/a |

### RDS (5 rules)

| ID | Severity | Check | CIS |
|----|----------|-------|-----|
| RDS-001 | CRITICAL | Publicly accessible AND unencrypted | n/a |
| RDS-004 | MEDIUM | Backup retention period too short | n/a |
| RDS-005 | MEDIUM | Deletion protection not enabled | n/a |
| RDS-006 | LOW | Not configured for Multi-AZ | n/a |
| RDS-007 | LOW | Auto minor version upgrade disabled | n/a |

### CloudTrail (5 rules)

| ID | Severity | Check | CIS |
|----|----------|-------|-----|
| CT-001 | CRITICAL | No CloudTrail trail exists in the account | 3.1 |
| CT-002 | HIGH | No trail is multi-region | 3.1 |
| CT-003 | MEDIUM | Log file validation disabled | 3.2 |
| CT-004 | MEDIUM | Trail not encrypted with KMS | 3.7 |
| CT-005 | HIGH | Trail exists but is not actively logging | n/a |

Filter to just the CIS-mapped subset and get a coverage summary.

```bash
cloudscan aws-scan --from-file examples/sample-aws-config.json --framework cis
```

## Risk scoring

Every finding gets a 0-100 score (`--output json`/`jsonl` includes it, console
and HTML use it to order results). The score exists to prioritize *within* a
severity tier, since two HIGH findings aren't equally urgent, not to replace
severity. A base score per tier is boosted for rules that specifically
indicate internet/public exposure (e.g. a public S3 bucket or a security group
open to the world), capped so a boosted lower tier can never outrank an
unboosted higher tier. See `cloudscan/engine/scoring.py`.

## Output formats

```bash
cloudscan aws-scan --from-file examples/sample-aws-config.json --output console   # default, human-readable
cloudscan aws-scan --from-file examples/sample-aws-config.json --output json      # single JSON document
cloudscan aws-scan --from-file examples/sample-aws-config.json --output jsonl     # one finding per line, for streaming/CI
cloudscan aws-scan --from-file examples/sample-aws-config.json --output sarif     # SARIF 2.1.0, for GitHub Code Scanning
cloudscan aws-scan --from-file examples/sample-aws-config.json --output html --output-file report.html   # self-contained report
```

The CI workflow (`.github/workflows/ci.yml`) runs the demo account through
`--output sarif` and uploads it via `github/codeql-action/upload-sarif`, so
findings from the seeded demo account show up in this repo's Security tab.
It's a working example of wiring CSPM output into GitHub's native tooling.

## CLI reference

```
$ cloudscan --help
Usage: cloudscan [OPTIONS] COMMAND [ARGS]...

  Cloud Misconfiguration Scanner for AWS.

  Detect security misconfigurations with clear risk, evidence, and
  remediation.

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  aws-scan      Scan for security misconfigurations.
  validate      Validate AWS credentials and configuration.
  version       Show version information.
  website-scan  Scan website for AWS misconfigurations (Stage 1 of...
```

```
$ cloudscan aws-scan --help
Usage: cloudscan aws-scan [OPTIONS]

  Scan for security misconfigurations.

  Supports two modes:
  1. LIVE MODE (requires AWS credentials):
       cloudscan aws-scan --profile myprofile --region us-east-1
  2. OFFLINE MODE (no credentials needed):
       cloudscan aws-scan --from-file exported-config.json

Options:
  --config PATH                    Path to config.yaml
  --from-file PATH                 Load configuration from JSON/YAML file
                                    (offline mode, no AWS credentials needed)
  --profile TEXT                   AWS profile to use (default: default, only
                                    used without --from-file)
  --region TEXT                    AWS region to scan (default: us-east-1,
                                    only used without --from-file)
  --services [iam|s3|ec2|rds|cloudtrail]
                                    Services to scan (default: all)
  --severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]
                                    Severity levels to include (default: all)
  --output [console|json|jsonl|sarif|html]
                                    Output format (default: console)
  --output-file PATH                Write findings to file instead of stdout
  --log-level [DEBUG|INFO|WARNING|ERROR]
                                    Logging level (default: INFO)
  --fail-on [CRITICAL|HIGH|MEDIUM|LOW]
                                    Exit with code 1 if findings at this
                                    severity or higher are found
  --framework [cis]                Filter findings to a compliance framework
                                    and print a coverage summary
  --help                            Show this message and exit.
```

There's also `cloudscan website-scan <url>`, a lightweight, unauthenticated
recon module that checks a public website's headers/TLS/error pages for
signs of AWS infrastructure. It's a secondary, opportunistic module (useful
as a first step when you don't have AWS credentials yet); the actual security
analysis is `aws-scan`. See [WEBSITE_SCANNER.md](WEBSITE_SCANNER.md).

## Offline mode, exporting a config to scan

Offline mode reads either a raw AWS API export (e.g. from
`aws iam list-users`-style calls, envelope-wrapped) or a pre-normalized
snapshot matching the contract in `cloudscan/schema.py`. See
`examples/sample-aws-config.json` for a worked example, and
`cloudscan/loaders/normalize.py` for the adapter that converts a raw export
into the normalized shape rules actually evaluate against.

To produce a real export from an account you have (or temporarily had)
credentials for, `scripts/export_aws_config.sh` / `.ps1` call the AWS CLI
across iam/s3/ec2/rds/cloudtrail and write a raw export in the shape
`normalize.py` expects.

```bash
./scripts/export_aws_config.sh aws-config.json us-east-1 myprofile
cloudscan aws-scan --from-file aws-config.json
```

## Required IAM policy

Read-only. `iam:GenerateCredentialReport` has no write concerns despite
the name. It's an async report-generation call that doesn't modify
account state.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "iam:GenerateCredentialReport",
        "s3:Get*",
        "s3:List*",
        "ec2:Describe*",
        "rds:Describe*",
        "cloudtrail:Describe*",
        "cloudtrail:Get*",
        "cloudtrail:List*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Architecture

```
Collectors (boto3, live) ──┐
                            ├──> normalize.py ──> ScanContext ──> RuleEngine ──> scoring ──> OutputFormatter
FileLoader (offline JSON) ─┘         (schema.py contract)      (31 rules)     (0-100)     (console/json/jsonl/sarif/html)
```

Collectors and the file loader both funnel through the same normalization
step (`cloudscan/loaders/normalize.py`), so every rule evaluates against one
documented data contract (`cloudscan/schema.py`) regardless of whether the
data came from a live API call or an offline export. Full details in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Development

```bash
make dev              # install with dev extras
make test             # pytest with coverage (261 tests)
make lint             # ruff check
```

Tests are organized by layer. Unit tests for each rule (`tests/test_rules_*.py`)
run against hand-built fixtures, collector tests run against `moto`-mocked AWS
(`tests/test_collectors_*.py`), formatter tests validate real output
(SARIF against the official OASIS JSON schema, HTML for balanced tags), and
an end-to-end integration test (`tests/test_integration_moto.py`) seeds
a mock account and asserts on the findings that come out the other end.

## Project layout

```
cloudscan/
├── cmd/cloudscan.py         # Click CLI entry point
├── collectors/               # boto3 collectors for iam, s3, ec2, rds, cloudtrail
├── loaders/                  # file_loader (offline JSON) + normalize (schema adapter)
├── engine/                   # ScanContext, RuleEngine, Finding, scoring
├── rules/                    # 31 rule classes, one file each
├── compliance/                # CIS control mapping + coverage reporting
├── output/                   # console, json, sarif, html formatters
├── website/                   # secondary website-recon module
└── schema.py                  # normalized data contract (the thing everything agrees on)

demo/seed_demo_account.py     # moto-seeded vulnerable account + scan runner
examples/sample-aws-config.json
tests/                        # 261 tests
```
