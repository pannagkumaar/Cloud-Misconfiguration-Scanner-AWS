# Cloud Misconfiguration Scanner for AWS 🛡️

A production-style security scanner that detects real AWS misconfigurations with clear risk, evidence, and remediation guidance.

**Perfect for interviews** — demonstrates security thinking, clean architecture, and production-ready code.

## Quick Start

### Prerequisites
- Python 3.8+
- AWS account with read-only IAM role
- AWS credentials configured (via `~/.aws/credentials` or environment variables)

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

### First Scan

```bash
python cloudscan/cmd/cloudscan.py --profile default --severity HIGH CRITICAL
```

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| **0** | Project definition & scope | ✅ Complete |
| **1** | Core architecture & CLI setup | ⏳ In Progress |
| **2** | Service collectors (IAM, S3, EC2, RDS) | 🔲 Not Started |
| **3** | Rule engine & security rules | 🔲 Not Started |
| **4** | Output formatting (JSON, Console, SARIF) | 🔲 Not Started |
| **5** | Validation with real misconfigs | 🔲 Not Started |
| **6** | Advanced features (auto-fix, CI/CD) | 🔲 Not Started |
| **7** | Documentation & presentation | 🔲 Not Started |

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

### ✅ What Makes This Production-Ready

1. **Separation of Concerns**
   - Collectors only gather raw AWS data
   - Rules only implement security logic
   - Engine orchestrates the flow
   - Output handles formatting

2. **Extensibility**
   - Add new AWS services without modifying rules
   - Add new rules without modifying collectors
   - Multiple output formats supported

3. **Security First**
   - Read-only IAM role (no modifications)
   - No credential storage
   - Uses boto3 credential chain
   - Output sanitization for logs

4. **Interview Defensible**
   - Clear architectural decisions
   - Mirrors enterprise tools (CloudTrail, Security Hub)
   - Thoughtful scope (know what NOT to build)
   - Production patterns


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

## Security Rules (Phase 3+)

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

### Basic Scan

```bash
# Scan with default config
python cloudscan/cmd/cloudscan.py

# Specify AWS profile
python cloudscan/cmd/cloudscan.py --profile prod

# Filter by severity
python cloudscan/cmd/cloudscan.py --severity HIGH CRITICAL

# Scan specific services
python cloudscan/cmd/cloudscan.py --services iam s3

# Output to JSON
python cloudscan/cmd/cloudscan.py --output json > findings.json
```

### CI/CD Integration

```bash
# Fail if any CRITICAL findings
python cloudscan/cmd/cloudscan.py --fail-on CRITICAL

# GitHub Action (coming Phase 6)
- uses: security/cloudscan@v1
  with:
    aws-role: arn:aws:iam::123456789:role/ScannerRole
    fail-on: CRITICAL
```

## Architecture Decisions

### Separation of Concerns

**Q: Why separate collectors and rules?**

A: In production scanners, you want independent testing. Collectors can be tested with mocked AWS responses. Rules can be tested with sample configurations. This separation also mirrors how tools like AWS Security Hub work — they collect config, then evaluate it against rules.

### Why Read-Only?

**Q: Could the scanner auto-fix issues?**

A: Not safely. Auto-fix requires:
1. Human review (we're in Phase 6)
2. Change management (not in scope)
3. Rollback capability (risky)

Read-only scanning eliminates these concerns and earns customer trust.

### Why AWS-Only?

**Q: Why AWS-only in Phase 1?**

A: 80/20 rule. 80% of security work is cloud-provider-specific. By focusing on AWS first, we can:
1. Deeply integrate with AWS services (CloudTrail, Config, Security Hub)
2. Understand CIS AWS Benchmark thoroughly
3. Build connectors for other clouds later without rearchitecting

### Why CLI?

**Q: Wouldn't a dashboard be more useful?**

A: CLI is better for Phase 1 because:
1. Simpler to test (no web framework complexity)
2. Better for CI/CD integration
3. Easier to version and distribute
4. Dashboard can layer on top of JSON output later

## Testing

### Unit Tests (Phase 2+)

```bash
pytest tests/test_collectors.py
pytest tests/test_rules.py
pytest tests/test_engine.py
```

### Integration Tests

```bash
./scripts/create_test_lab.sh
python cloudscan/cmd/cloudscan.py > /tmp/findings.json
./scripts/validate_findings.sh /tmp/findings.json
```

## Roadmap

### Phase 1: Core Architecture (Next)
- CLI with Click framework
- Configuration management
- AWS authentication
- Logging setup

### Phase 2: Asset Collection
- IAM collector
- S3 collector
- EC2 collector
- RDS collector

### Phase 3: Rule Engine
- Rule base class
- First rule set (CIS + high-value)
- Finding data class
- Rule evaluation loop

### Phase 4: Output Formatting
- Console formatter (colors, tables)
- JSON formatter
- SARIF formatter (GitHub integration)

### Phase 5: Real-World Validation
- Create vulnerable AWS lab
- Run scanner
- Validate findings
- Capture screenshots

### Phase 6: Advanced Features
- Auto-fix (opt-in only)
- CI/CD mode (--fail-on flag)
- Risk grouping
- GitHub Action

### Phase 7: Documentation
- Blog post
- Interview talking points
- Performance benchmarks
- False positive analysis

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



