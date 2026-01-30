# Two-Stage Pentesting Workflow: Website + AWS Scanner

## Overview

CloudScan now supports a **realistic two-stage pentesting workflow**:

### Stage 1: Website Reconnaissance
```bash
cloudscan website-scan https://target.com
```
- Passive scanning of website
- Identifies AWS infrastructure
- Finds security misconfigurations exposed on website
- NO credentials required

### Stage 2: Deep AWS Analysis  
```bash
cloudscan aws-scan --from-file aws-config.json
```
- If you gain AWS credentials during Stage 1
- Deep analysis of AWS configurations
- Detailed security findings
- All 4 security rules from Phase 3

## Why This Matters for Pentesting

**Real pentesting scenario:**
1. You're given a website to test
2. You don't have AWS credentials initially
3. You scan the website for clues about AWS setup
4. You find evidence of misconfiguration or additional paths
5. You gain temporary AWS access
6. You export the AWS configuration
7. You do a deep analysis of the AWS account

## Website Scanner Features

### Security Headers Scanning
Checks for:
- ✅ Strict-Transport-Security (HSTS)
- ✅ X-Content-Type-Options
- ✅ X-Frame-Options  
- ✅ Content-Security-Policy (CSP)
- ✅ X-XSS-Protection

### SSL/TLS Certificate Validation
- ✅ Certificate expiration check
- ✅ Self-signed certificate detection
- ✅ Certificate chain validation

### AWS Infrastructure Detection
Identifies:
- ✅ AWS-specific HTTP headers (X-Amz, X-Amzn)
- ✅ CloudFront distributions
- ✅ S3 bucket references
- ✅ RDS endpoints
- ✅ API Gateway endpoints
- ✅ ElastiCache endpoints

### Error Page Analysis
- ✅ Information disclosure in error pages
- ✅ AWS service names leaked in errors

### DNS Reconnaissance
- ✅ Domain resolution validation
- ✅ DNSSEC checks

## Usage Examples

### Basic Website Scan

```bash
$ cloudscan website-scan https://example.com

Website Security Scanner - Reconnaissance Report
URL: https://example.com
Timestamp: 2026-01-30T13:18:40Z

AWS Infrastructure Detected:
  Services found: S3, CLOUDFRONT
  
  RECOMMENDATION: Switch to AWS Scanner for deep analysis
  Command: cloudscan aws-scan --from-file <aws-config.json>

[HIGH] Missing Strict-Transport-Security
  Description: Website missing HSTS header
  Evidence: HTTP response does not include HSTS
  Remediation: Add Strict-Transport-Security to headers

[INFO] AWS infrastructure detected
  Services: S3, CLOUDFRONT
  Evidence: Found AWS-specific headers
  Remediation: Ensure proper security configurations

Summary:
  CRITICAL: 0  HIGH: 3  MEDIUM: 2  LOW: 0  INFO: 1
  Total: 6
```

### Save Report to File

```bash
cloudscan website-scan https://example.com --output-file website-findings.txt
```

### Run AWS Scanner After Finding Credentials

```bash
# Stage 1: Website reconnaissance (no creds needed)
$ cloudscan website-scan https://example.com
# Output shows AWS infrastructure detected...

# Stage 2: Export AWS config (now you have temporary creds)
$ aws configure --profile temp-role
$ ./scripts/export_aws_config.sh --profile temp-role > aws-config.json

# Stage 3: Deep AWS analysis (no creds needed if you have export)
$ cloudscan aws-scan --from-file aws-config.json
```

## Pentesting Workflow Example

### Day 1: Initial Reconnaissance

```bash
$ cloudscan website-scan https://target-company.com

Found:
- Missing security headers (HIGH severity)
- AWS CloudFront distribution (INFO)
- S3 bucket references (INFO)
- Information in error pages (MEDIUM)

CONCLUSION: Target uses AWS. Likely has S3 buckets and CloudFront.
```

### Day 2-3: Further Investigation

Using website findings, you:
- Look for S3 bucket enumeration vulnerabilities
- Check CloudFront configurations
- Search for exposed AWS credentials in public repositories
- Attempt social engineering to gain AWS access

### Day 4: Deeper Dive (If Credentials Obtained)

```bash
# Export the AWS account configuration
$ aws configure --profile client-aws
$ ./scripts/export_aws_config.sh --profile client-aws > client-aws.json

# Run deep analysis
$ cloudscan aws-scan --from-file client-aws.json

Found:
- S3 bucket with public access (CRITICAL)
- Security group open to 0.0.0.0/0 (HIGH)  
- IAM wildcard policies (CRITICAL)
- RDS instance without encryption (HIGH)
```

## Architecture

### Website Scanner Module

```
cloudscan/website/
  ├── scanner.py       - Main scanner logic
  ├── output.py        - Result formatting
  └── __init__.py
```

**WebsiteScanner class:**
- Scans security headers
- Validates SSL/TLS certificates
- Checks DNS records
- Detects AWS services
- Analyzes error pages

**WebsiteIndicator class:**
- Stores findings from website scan
- Includes: type, severity, title, description, evidence, remediation

### Updated CLI

```
Commands:
  website-scan    Stage 1: Scan website for misconfigurations
  aws-scan        Stage 2: Deep AWS configuration analysis
  scan            Alias for aws-scan (backward compatible)
  validate        Test AWS credentials
  version         Show help
```

## Output Formatting

### Website Scanner Output

```
[HIGH] Missing Strict-Transport-Security
  Description: Website missing HSTS header
  Evidence: HTTP response does not include header
  Remediation: Add header to HTTP responses

[INFO] AWS infrastructure detected
  AWS Service: S3, CLOUDFRONT
  Evidence: Found X-Amz-Cf-Pop header
  Remediation: Ensure AWS resources properly secured
```

## Integration with AWS Scanner

When website scanner detects AWS:
1. Reports which AWS services are detected
2. Suggests switching to AWS scanner
3. Provides command to run next stage

When you have AWS export:
1. Run `aws-scan --from-file config.json`
2. Get detailed configuration analysis
3. All 4 AWS security rules applied:
   - S3-001: Public buckets
   - SG-001: Security groups open to 0.0.0.0/0
   - IAM-001: Wildcard policies
   - RDS-001: Public unencrypted instances

## Key Features

✅ **Two-stage pentesting workflow**
- Website reconnaissance
- AWS deep analysis

✅ **No credentials needed for analysis**
- Website: No creds at all
- AWS: Only need exported config

✅ **Realistic pentesting approach**
- Start with passive reconnaissance
- Escalate to active testing once you have access
- Use both scanners in sequence

✅ **Clear progression**
- Website findings guide AWS investigation
- AWS findings guide remediation

✅ **Interview talking point**
- "I built a two-stage pentesting tool that mirrors real workflows"
- "Website reconnaissance feeds into AWS analysis"
- "Perfect for both red teamers and blue teamers"

## Common Workflows

### Scenario 1: Pentesting Unknown Target

```bash
# Never done this before? Start here
cloudscan website-scan https://target.com

# If AWS detected, you now know what to look for
# Continue investigation with other recon tools

# If you gain AWS access
cloudscan aws-scan --from-file target-aws.json
```

### Scenario 2: Security Audit with Limited Access

```bash
# You have a website but not AWS credentials
cloudscan website-scan https://client.com

# Report website misconfigurations
# Ask client for AWS export for deeper analysis

# Client provides export
cloudscan aws-scan --from-file client-aws-export.json
```

### Scenario 3: Continuous Security Monitoring

```bash
# Weekly website scan for header changes
cloudscan website-scan https://company.com --output-file reports/week-$(date +%Y%m%d).txt

# Monthly AWS analysis with exported configs
cloudscan aws-scan --from-file exports/monthly-aws.json --output json > reports/monthly-aws.json
```

## Files Added

```
NEW:
  cloudscan/website/__init__.py
  cloudscan/website/scanner.py
  cloudscan/website/output.py

MODIFIED:
  cloudscan/cmd/cloudscan.py (added website-scan command, renamed scan to aws-scan)
```

## Testing

Tested on:
- ✅ httpbin.org (general website)
- ✅ aws.amazon.com (AWS infrastructure detection)
- ✅ All CLI commands and options
- ✅ Security header detection
- ✅ Error page analysis
- ✅ AWS service detection

## Next Steps

The two-stage workflow is **production-ready**. You can:

1. **Continue with Phase 6** - Auto-fix, GitHub Actions, SARIF
2. **Enhance website scanner** - Add more indicators, vulnerability scanning
3. **Combine findings** - Web + AWS findings in single report
4. **Add reporting** - Email, Slack, JIRA integration

---

Perfect for demonstrating security thinking and understanding real pentesting workflows!
