# PHASE 2 - Asset Collection Layer

## Completed: AWS Service Collectors

### Components Built

#### 1. Base Collector (`cloudscan/collectors/base.py`)
- Abstract base class for all collectors
- Common pagination handling
- Error handling and logging
- Type hints for extensibility

#### 2. IAM Collector (`cloudscan/collectors/iam.py`)
- **Collects:**
  - IAM users with properties
  - IAM roles and trust relationships
  - Customer-managed IAM policies
  - MFA device configuration
  - Access keys and metadata
  - Account-level IAM summary
  - Credential report availability

- **Security-relevant data:**
  - MFA device list (for MFA checks)
  - Access key creation dates (for key rotation)
  - Policy documents (for privilege analysis)
  - Root account access (from credential report)

#### 3. S3 Collector (`cloudscan/collectors/s3.py`)
- **Collects:**
  - S3 bucket list and metadata
  - Bucket policies
  - Bucket ACLs
  - Public Access Block configuration
  - Versioning settings
  - Server access logging
  - Default encryption settings
  - Bucket tags

- **Security-relevant data:**
  - Public Access Block (for public access detection)
  - Bucket policy statements (for privilege analysis)
  - Encryption configuration (for encryption checks)
  - Logging enablement (for audit trail)

#### 4. EC2 Collector (`cloudscan/collectors/ec2.py`)
- **Collects:**
  - Security groups and their rules
  - EC2 instances and metadata
  - Network configuration
  - Public IP addresses
  - Security group associations
  - Instance tags

- **Security-relevant data:**
  - Inbound/outbound rules (for exposure detection)
  - CIDR ranges including 0.0.0.0/0 (for open rules)
  - Public IPs (for internet accessibility)
  - Port ranges (for dangerous ports like 22, 3389)

#### 5. RDS Collector (`cloudscan/collectors/rds.py`)
- **Collects:**
  - RDS instances and configuration
  - RDS clusters and configuration
  - Encryption settings
  - Backup configuration
  - Deletion protection
  - Public accessibility flag
  - Database security groups
  - Backup retention periods

- **Security-relevant data:**
  - Storage encryption flag (for encryption checks)
  - Public accessibility (for exposure detection)
  - Backup retention (for backup/disaster recovery)
  - Deletion protection (for accidental deletion protection)

#### 6. Collector Manager (`cloudscan/collectors/manager.py`)
- Coordinates all collectors
- Parallel-ready architecture
- Error isolation (one collector failure doesn't block others)
- Service filtering
- Aggregated results

### Key Design Decisions

#### ✅ Separation: Collection vs. Analysis
- Collectors return RAW data
- NO security logic in collectors
- All security rules will go in Phase 3

This means:
- Collectors can be tested independently
- Rules can be updated without touching collectors
- Easy to add new collectors without affecting rules

#### ✅ Error Handling
- Errors in one collector don't block others
- Graceful degradation if a service is unavailable
- Clear error messages logged
- Returns partial results when possible

#### ✅ Pagination Support
- All collectors handle paginated API responses
- Works with large numbers of resources
- Transparent to caller

### Data Structure Example

```python
{
    "services": ["iam", "s3", "ec2", "rds"],
    "data": {
        "iam": {
            "service": "iam",
            "users": [...],
            "roles": [...],
            "policies": [...],
            "account_summary": {...},
            "credential_report": {...}
        },
        "s3": {
            "service": "s3",
            "buckets": [
                {
                    "name": "prod-logs",
                    "region": "us-east-1",
                    "policy": {...},
                    "public_access_block": {...},
                    "encryption": {...},
                    ...
                }
            ]
        },
        "ec2": {
            "service": "ec2",
            "security_groups": [...],
            "instances": [...]
        },
        "rds": {
            "service": "rds",
            "instances": [...],
            "clusters": [...]
        }
    }
}
```

### Interview Talking Points

**Q: "Why don't collectors do security checks?"**
- A: Separation of concerns. Collectors are about data gathering, rules are about interpretation. If we mix them:
  - Can't reuse collectors for different rule sets
  - Hard to test (can't mock AWS responses without security logic)
  - Coupling makes it hard to change rules

**Q: "What about performance with many resources?"**
- A: Current design is ready for optimization:
  - Collectors could run in parallel (Phase 6)
  - Pagination is built in
  - Can add caching/filtering later
  - Manager provides orchestration point

**Q: "How do you handle API limits?"**
- A: Currently we let boto3 handle backoff/retries. For Phase 6:
  - Could add request rate limiting
  - Could implement caching
  - Could add batch/filtered API calls

### What's Next: Phase 3

Rules engine will:
1. Receive collector output
2. Evaluate security policies
3. Generate findings with:
   - Resource ID
   - Risk description
   - Evidence from collected data
   - Remediation steps
4. Filter by severity

## File Inventory

```
cloudscan/collectors/
├── __init__.py
├── base.py              # Base collector class
├── iam.py              # IAM collector
├── s3.py               # S3 collector
├── ec2.py              # EC2 collector
├── rds.py              # RDS collector
└── manager.py          # Collector orchestration
```

## Summary

✅ **Phase 2 Complete** - Production-grade data collectors
- 4 AWS services (IAM, S3, EC2, RDS)
- Comprehensive attribute collection
- Error isolation and logging
- Pagination support
- Extensible architecture

**Code Quality:**
- Type hints on all functions
- Comprehensive docstrings
- Error handling with logging
- Clean separation of concerns
- Interview-defensible design

**Ready for Phase 3:** Rule engine and security rules
