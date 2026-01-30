# Cloud Misconfiguration Scanner - Architecture

## High-Level Flow

```
AWS Account (with read-only IAM role)
   ↓
Scanner CLI Entry Point
   ↓
Configuration Loader
   ↓
Service Collectors (IAM, S3, EC2, RDS)
   ↓
Rule Engine
   ↓
Finding Generator
   ↓
Output Formatter (JSON, Console, SARIF)
```

## Project Structure

```
cloudscan/
├── cmd/
│   └── cloudscan.py                    # CLI entry point
├── collectors/
│   ├── __init__.py
│   ├── base.py                         # Base collector class
│   ├── iam.py                          # IAM collector
│   ├── s3.py                           # S3 bucket collector
│   ├── ec2.py                          # EC2 security groups collector
│   └── rds.py                          # RDS instance collector
├── rules/
│   ├── __init__.py
│   ├── base.py                         # Base rule class
│   ├── cis_1_1_root_mfa.py            # CIS 1.1 - Root account MFA
│   ├── s3_public_access.py            # S3-001 - Public bucket detection
│   ├── sg_open_world.py               # SG-001 - Open security groups
│   ├── rds_public_unencrypted.py      # RDS-001 - Public + unencrypted
│   └── iam_wildcard_policy.py         # IAM-001 - Wildcard policies
├── engine/
│   ├── __init__.py
│   ├── context.py                      # Scan context object
│   ├── rule_engine.py                  # Rule executor
│   └── finding.py                      # Finding data class
├── output/
│   ├── __init__.py
│   ├── base.py                         # Base output formatter
│   ├── console.py                      # Terminal output
│   ├── json.py                         # JSON output
│   └── sarif.py                        # SARIF format (future)
├── __init__.py
└── config.py                           # Configuration management

tests/
├── __init__.py
├── test_collectors.py
├── test_rules.py
└── test_engine.py

config.yaml                             # Configuration file
requirements.txt                        # Python dependencies
.gitignore
README.md
ARCHITECTURE.md
```

## Design Principles

### 1. Separation of Concerns
- **Collectors**: Gather raw AWS configuration (no security logic)
- **Rules**: Implement security checks (no AWS API calls)
- **Engine**: Orchestrate collection and rule execution
- **Output**: Format findings for human/machine consumption

### 2. Extensibility
- New collectors can be added without modifying rule engine
- New rules can be added without touching collectors
- Multiple output formats supported

### 3. Interview-Ready
- Clear, testable components
- Security best practices (read-only IAM role)
- Production patterns (config management, logging, error handling)
- Mirrors enterprise tools (CloudTrail, Config, Security Hub)

## Why This Architecture?

✅ **Scalability**: Easy to add new AWS services
✅ **Testability**: Collectors and rules can be unit tested independently
✅ **Maintainability**: Bug in one rule won't affect others
✅ **Auditability**: Clear evidence trail for each finding
✅ **Interview Discussion**: Shows understanding of security architecture patterns

## Data Flow

### 1. Collection Phase
```
boto3 AWS API
   ↓
Collector.collect() → raw config dict
   ↓
Context object populated
```

### 2. Evaluation Phase
```
For each Rule:
  Rule.evaluate(context) → Finding or None
```

### 3. Reporting Phase
```
[Finding] → Output formatter
   ↓
Console/JSON/SARIF
```

## Security Considerations

- **Read-only IAM role**: Scanner has no write permissions
- **Temporary credentials**: Support AWS STS credentials
- **No credential storage**: Uses boto3 credential chain
- **Output sanitization**: Remove sensitive data from logs

## Future Enhancements

Phase 6 additions:
- Auto-fix (opt-in only)
- CI/CD integration (GitHub Actions)
- Risk grouping (exposure + no encryption = CRITICAL)
- Database for historical findings
- Compliance reporting (CIS, PCI-DSS)
