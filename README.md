# Cloud Misconfiguration Scanner for AWS 

:: Python / AWS / Boto3 / Requests / Click / JSON / YAML / CLI / Security / Regex / REST APIs ::

A production-style security scanner that detects real AWS misconfigurations with clear risk, evidence, and remediation guidance.

## Quick Start

### Prerequisites
- Python 3.8+
- AWS account with read-only IAM role (optional - see offline mode below)
- AWS credentials configured (via `~/.aws/credentials` or environment variables) - ONLY needed for live scanning

### Installation

```bash
# Clone the repo
git clone <repo-url>
cd Cloud-Misconfiguration-Scanner-AWS

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Architecture Overview

```
AWS Account (read-only IAM)
    ↓
CLI Entry Point (Click)
    ↓
Configuration Loader (config.yaml)
    ↓
Service Collectors (boto3)
    ├─ IAM Collector
    ├─ S3 Collector
    ├─ EC2 Collector
    └─ RDS Collector
    ↓
Rule Engine
    ├─ CIS Benchmark Rules
    ├─ Security Best Practices
    └─ Compliance Rules
    ↓
Finding Generator
    ├─ Resource ID
    ├─ Risk Description
    ├─ Evidence
    └─ Remediation
    ↓
Output Formatter
    ├─ Console (Pretty Terminal)
    ├─ JSON (CI/CD)
    └─ SARIF (GitHub)
```

## Design Principles

**Separation of Concerns**
- Collectors gather raw AWS data independently
- Rules implement security logic separately  
- Engine orchestrates the flow
- Formatters handle output generation

**Extensibility**
- Add new AWS services without modifying rules
- Add new rules without modifying collectors
- Multiple output formats (Console, JSON, SARIF)

**Security First**
- Read-only IAM role (no modifications)
- No credential storage
- Uses boto3 credential chain
- Output sanitization for logs



## Example Output

### Console Output (Human-Friendly)

```
[CRITICAL] CIS-1.1 - Root account MFA disabled
           Resource: AWS Account (123456789)
           Risk: Root account compromise enables account takeover
           Evidence: Root user has no MFA virtual device attached
           Remediation: Enable MFA on root account
                        https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html

[HIGH] S3-001 - Public bucket detected
       Resource: prod-logs-bucket
       Risk: Public data exposure and exfiltration
       Evidence: Bucket policy allows Principal: * with s3:GetObject
       Remediation: Enable Block Public Access and use bucket policies to restrict access

[HIGH] SG-001 - Security group open to 0.0.0.0/0 on SSH (22)
       Resource: sg-12345678 (web-tier)
       Risk: Unauthorized SSH access from internet
       Evidence: Inbound rule allows 22/tcp from 0.0.0.0/0
       Remediation: Restrict SSH access to specific IPs or use Systems Manager Session Manager

Summary:
  Critical: 1
  High: 2
  Medium: 0
  Low: 0
  Total: 3
```

### JSON Output (Machine-Friendly)

```json
{
  "scan_id": "scan-20260130-001",
  "timestamp": "2026-01-30T10:45:22Z",
  "account_id": "123456789",
  "region": "us-east-1",
  "findings": [
    {
      "id": "CIS-1.1",
      "severity": "CRITICAL",
      "service": "iam",
      "resource": "AWS Account",
      "risk": "Root account compromise enables account takeover",
      "evidence": {
        "user": "root",
        "mfa_devices": []
      },
      "remediation": "Enable MFA on root account via AWS Management Console"
    }
  ],
  "summary": {
    "total": 3,
    "critical": 1,
    "high": 2,
    "medium": 0,
    "low": 0
  }
}
```

## Security Rules

### CIS AWS Foundations Benchmark

- **CIS 1.1** - Root account MFA enabled
- **CIS 2.1.1** - CloudTrail enabled
- **CIS 2.1.5** - CloudTrail log validation

### S3 Security

- **S3-001** - Public bucket detection
- **S3-002** - Bucket encryption (default)
- **S3-003** - Bucket versioning disabled

### EC2 Security

- **SG-001** - Open security group (0.0.0.0/0)
- **SG-002** - Unrestricted RDP (3389)
- **EC2-001** - Instance public IP exposure

### IAM Security

- **IAM-001** - Wildcard policy (*:*)
- **IAM-002** - Unused access keys (90+ days)
- **IAM-003** - Root account usage in last 30 days

### RDS Security

- **RDS-001** - Public instance without encryption
- **RDS-002** - Backup retention < 7 days
- **RDS-003** - No deletion protection

## Configuration

Edit [config.yaml](config.yaml):

```yaml
aws:
  region: us-east-1
  profile: default
  
scanner:
  services: [iam, s3, ec2, rds]
  severity_levels: [CRITICAL, HIGH, MEDIUM]
  
output:
  format: console  # console, json, sarif
  file: findings.json
```

## Usage

### Website Scanning

```bash
# Scan a website for AWS misconfigurations
python cloudscan/cmd/cloudscan.py website-scan https://example.com

# Save findings to file
python cloudscan/cmd/cloudscan.py website-scan https://example.com --output-file findings.txt

# JSON output
python cloudscan/cmd/cloudscan.py website-scan https://example.com --output json
```

**Checks:**
- Security headers (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS certificate validity
- AWS infrastructure detection (S3, CloudFront, RDS, etc.)
- Error page information disclosure
- Exposed credentials (AWS keys, tokens)
- Subdomain enumeration

### AWS Scanning

```bash
# Scan with default credentials
python cloudscan/cmd/cloudscan.py aws-scan

# Specify AWS profile
python cloudscan/cmd/cloudscan.py aws-scan --profile prod

# Filter by severity
python cloudscan/cmd/cloudscan.py aws-scan --severity HIGH CRITICAL

# Scan specific services
python cloudscan/cmd/cloudscan.py aws-scan --services iam s3

# Output to JSON
python cloudscan/cmd/cloudscan.py aws-scan --output json > findings.json
```

### Offline Scanning

```bash
# Export AWS config from account with access
./scripts/export_aws_config.sh > aws-export.json

# Scan it offline
python cloudscan/cmd/cloudscan.py aws-scan --from-file aws-export.json

# JSON output
python cloudscan/cmd/cloudscan.py aws-scan --from-file aws-export.json --output json
```

### Advanced Options

```bash
# Fail if any CRITICAL findings (for CI/CD)
python cloudscan/cmd/cloudscan.py aws-scan --fail-on CRITICAL

# Set log level for debugging
python cloudscan/cmd/cloudscan.py aws-scan --log-level DEBUG

# Combine options
python cloudscan/cmd/cloudscan.py aws-scan --from-file config.json --severity HIGH CRITICAL --output json --output-file findings.json
```

## Design

**Separation of Concerns**
Collectors gather raw AWS data independently, rules implement security logic separately. This mirrors production tools like AWS Security Hub.

**Read-Only Design**
The scanner performs read-only assessment. No modifications or auto-fixes are applied, ensuring safe and auditable scanning.

**CLI-Based**
Command-line interface integrates with CI/CD pipelines and automation workflows. JSON output enables programmatic integration.

## Testing

```bash
pytest tests/
```


## Security Considerations

### Credential Management
- ✅ Uses boto3 credential chain (no hardcoded credentials)
- ✅ Supports AWS STS temporary credentials
- ✅ Read-only IAM role recommended

### Data Handling
- ✅ No credential storage in findings
- ✅ Output sanitization for logs
- ✅ No PII in console output by default

### Required IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:Get*",
        "iam:List*",
        "s3:Get*",
        "s3:List*",
        "ec2:Describe*",
        "rds:Describe*",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```



