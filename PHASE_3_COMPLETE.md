# PHASE 3 - Rule Engine (THE HEART)

## Completed: Security Rule Framework

### Core Components

#### 1. Finding Class (`cloudscan/engine/finding.py`)
Represents a single security finding with:
- **Rule metadata**: ID, title, severity, CIS reference
- **Resource info**: ID and type of affected resource
- **Evidence**: Data supporting the finding
- **Remediation**: Steps to fix and AWS documentation link
- **Timestamp**: When finding was generated

Supports both dictionary conversion (for JSON) and pretty printing.

#### 2. Scan Context (`cloudscan/engine/context.py`)
Provides rule engines with AWS data through convenience methods:
```python
context.get_iam_users()           # All IAM users
context.get_s3_buckets()          # All S3 buckets  
context.get_security_groups()     # All EC2 security groups
context.get_rds_instances()       # All RDS instances
```

#### 3. Base Rule (`cloudscan/rules/base.py`)
Abstract base class that all rules inherit from:
```python
class MyRule(BaseRule):
    id = "SERVICE-001"
    title = "Rule Title"
    severity = Severity.HIGH
    service = "s3"  # or iam, ec2, rds
    
    def evaluate(self, context: ScanContext) -> List[Finding]:
        findings = []
        # Evaluate resources
        # Create findings
        return findings
```

#### 4. Rule Engine (`cloudscan/engine/rule_engine.py`)
Orchestrates rule execution:
- Dynamically loads all rule classes
- Evaluates each rule against scan context
- Aggregates findings
- Sorts by severity
- Handles errors gracefully

### First Rule Set (High-Value Security Checks)

#### S3-001: Public Bucket Detection
- **Severity**: HIGH
- **Checks for**:
  - Bucket policies allowing public access (Principal: *)
  - Public ACLs (AllUsers group)
  - Missing public access blocks
- **Evidence**: Policy statements, ACL grants, block configuration
- **Remediation**: Enable block public access, restrict policy, update ACL

#### SG-001: Open Security Groups (0.0.0.0/0)
- **Severity**: HIGH
- **Checks for**:
  - Inbound rules from 0.0.0.0/0 on SSH (port 22)
  - Inbound rules from 0.0.0.0/0 on RDP (port 3389)
- **Evidence**: Port number, CIDR range, description
- **Remediation**: Restrict to specific IPs, use bastion/Session Manager

#### IAM-001: Wildcard Policies (*:*)
- **Severity**: CRITICAL (highest priority)
- **Checks for**:
  - Statements with Action: * and Resource: *
  - Inline policies on users and roles
  - Customer-managed policies with wildcards
- **Evidence**: Policy statement, affected principal
- **Remediation**: Replace with least-privilege permissions, use managed policies

#### RDS-001: Public + Unencrypted
- **Severity**: CRITICAL (when both conditions met)
- **Checks for**:
  - RDS publicly accessible + no encryption (CRITICAL)
  - RDS publicly accessible alone (HIGH)
  - RDS unencrypted alone (HIGH)
- **Evidence**: Encryption flag, public accessibility, engine type
- **Remediation**: Disable public access, enable encryption, use security groups

### Rule Design Pattern

Every rule follows this pattern:

```python
def evaluate(self, context: ScanContext) -> List[Finding]:
    findings = []
    
    # Iterate through resources
    for resource in context.get_resources():
        
        # Check condition
        if self._has_problem(resource):
            
            # Create finding with full context
            finding = self._create_finding(
                resource_id=resource["id"],
                resource_type="...",
                risk="Why is this bad?",
                evidence={"key": "value"},  # Supporting data
                remediation="How to fix it",
                remediation_url="AWS docs link"
            )
            findings.append(finding)
    
    return findings
```

### Evidence Gathering

Each finding includes evidence to justify the finding:
- For S3 buckets: policy statements, ACL grants
- For security groups: port ranges, CIDR blocks
- For IAM: policy documents, principal info
- For RDS: encryption flags, public access setting

This evidence:
- Supports the finding claim
- Can be used for audits
- Helps teams understand the issue
- Enables automation (e.g., auto-fix based on evidence)

### Key Design Decisions

#### ✅ Separation: Rules vs. Collection
- Collectors: AWS API calls only
- Rules: Analysis and finding generation only
- Benefit: Can write rules without AWS access, test with mocked data

#### ✅ Extensibility
- To add a new rule: Create a class, inherit from BaseRule, implement evaluate()
- New rules automatically loaded by RuleEngine
- No modification to engine or other rules needed

#### ✅ Severity Matters
- Findings sorted by CRITICAL → HIGH → MEDIUM → LOW → INFO
- Enables --fail-on CRITICAL for CI/CD
- Clearer reporting priorities

#### ✅ Evidence-Based Findings
- Each finding can explain itself
- No "magic" scoring
- Auditable for compliance

### Interview Talking Points

**Q: "How would you add more rules?"**
- A: Create new file in rules/ directory inheriting from BaseRule, implement evaluate() method. Engine auto-loads it.

**Q: "What if a rule has a false positive?"**
- A: Add exception list in config or modify rule logic. Evidence allows easy debugging.

**Q: "How do you handle mutually exclusive findings?"**
- A: Each rule operates independently. Can add grouping in Phase 4 output formatter.

**Q: "Why separate evidence from remediation?"**
- A: Evidence is objective (what was found), remediation is prescriptive (what to do). Different audiences care about each.

### Next: Phase 4

Output formatting will:
1. Take findings list
2. Format for different outputs (console, JSON, SARIF)
3. Apply filtering (severity, service)
4. Add statistics and summaries
5. Pretty-print for humans or machines

## File Inventory

```
cloudscan/engine/
├── __init__.py
├── finding.py             # Finding data class
├── context.py            # ScanContext for rules
└── rule_engine.py        # Rule orchestrator

cloudscan/rules/
├── __init__.py
├── base.py               # BaseRule abstract class
├── s3_public_bucket.py   # S3-001
├── sg_open_world.py      # SG-001
├── iam_wildcard_policy.py # IAM-001
└── rds_public_unencrypted.py # RDS-001
```

## Summary

✅ **Phase 3 Complete** - Security rule framework
- Finding data class with evidence + remediation
- ScanContext for convenient data access
- BaseRule pattern for consistent rule implementation
- 4 high-value security rules (CRITICAL and HIGH severity)
- Rule engine with dynamic loading and error handling

**Code Quality:**
- Type hints throughout
- Clear inheritance pattern
- Comprehensive evidence gathering
- Production-ready error handling
- Interview-friendly design decisions

**Rules Implemented:**
- S3-001: Public bucket detection
- SG-001: Open security groups on dangerous ports
- IAM-001: Wildcard policies (CRITICAL)
- RDS-001: Public + unencrypted (CRITICAL)

**Ready for Phase 4:** Output formatting
