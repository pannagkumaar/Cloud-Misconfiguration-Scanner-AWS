# PHASE 1 - Core Architecture

## Completed: CLI Framework & AWS Authentication

### Components Built

#### 1. Configuration Management (`cloudscan/config.py`)
- YAML-based configuration loading
- Environment variable overrides
- Hierarchical config access (e.g., `config.get("aws.region")`)
- Support for AWS role assumption

#### 2. Logging System (`cloudscan/logger.py`)
- Centralized logging setup
- Console + file logging
- Configurable log levels
- Structured logging for debugging

#### 3. AWS Client (`cloudscan/aws_client.py`)
- boto3 session management
- Credential validation
- Multi-service client caching
- Account ID retrieval
- Role assumption support
- Error handling with clear messaging

#### 4. CLI Entry Point (`cloudscan/cmd/cloudscan.py`)
- Click-based CLI framework
- Three commands: `scan`, `validate`, `version`
- Comprehensive option parsing
- AWS authentication flow
- Production-ready error handling

### Features

**`cloudscan scan` command:**
```bash
# Basic scan (all services, all severity)
cloudscan scan

# Specific services
cloudscan scan --services iam s3

# Filter severity
cloudscan scan --severity CRITICAL HIGH

# Output formats
cloudscan scan --output json --output-file findings.json

# Fail on severity
cloudscan scan --fail-on CRITICAL
```

**`cloudscan validate` command:**
```bash
# Verify AWS credentials are working
cloudscan validate
```

### Architecture

```
CLI Entry (Click)
    ↓
Config Loading (YAML + env)
    ↓
AWS Authentication (boto3)
    ↓
Credential Validation (STS)
    ↓
Ready for collectors/rules (Phase 2-3)
```

### Key Design Decisions

#### ✅ Separation of Concerns
- Configuration is independent of AWS authentication
- Logging is centralized but doesn't couple to business logic
- CLI handles only interface, not scanning logic

#### ✅ Production Patterns
- Error handling with logging
- Credential validation before scanning
- Configurable via both files and environment
- Support for role assumption (for cross-account scanning)

#### ✅ Interview Talking Points
- **Q: "Why a separate config module?"**
  - A: Makes testing easier (mock config, no files). Mirrors enterprise tools like Terraform.

- **Q: "Why validate credentials upfront?"**
  - A: Fail fast with clear error messages. Better UX than discovering errors mid-scan.

- **Q: "Why support role assumption?"**
  - A: Scales to multi-account setups. Phase 6 enhancement.

### What's NOT Included (Intentionally)

- ❌ Actual security scanning (Phase 2-3)
- ❌ Output formatting (Phase 4)
- ❌ Rule engine (Phase 3)
- ❌ Database persistence (Phase 6+)

### How to Test Phase 1

```bash
# Activate venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Validate AWS credentials
python cloudscan/cmd/cloudscan.py validate

# Run scan (will show infrastructure is ready)
python cloudscan/cmd/cloudscan.py scan

# Check help
python cloudscan/cmd/cloudscan.py scan --help
```

### Next: Phase 2

Build service collectors:
- `IAMCollector` - users, roles, policies
- `S3Collector` - buckets, policies, access blocks
- `EC2Collector` - security groups, instances
- `RDSCollector` - instances, encryption, public access

Each collector will:
1. Inherit from `BaseCollector`
2. Implement `collect()` method
3. Return structured AWS data (no security logic)
4. Handle pagination and errors gracefully

## File Inventory

```
cloudscan/
├── __init__.py
├── config.py              # Configuration management
├── logger.py              # Logging setup
├── aws_client.py          # AWS authentication
├── cmd/
│   ├── __init__.py
│   └── cloudscan.py       # CLI entry point
├── collectors/
│   ├── __init__.py
│   ├── base.py            # To be created Phase 2
│   ├── iam.py             # To be created Phase 2
│   ├── s3.py              # To be created Phase 2
│   ├── ec2.py             # To be created Phase 2
│   └── rds.py             # To be created Phase 2
├── rules/
│   ├── __init__.py
│   ├── base.py            # To be created Phase 3
│   └── (rule files)       # To be created Phase 3
├── engine/
│   ├── __init__.py
│   ├── context.py         # To be created Phase 3
│   ├── rule_engine.py     # To be created Phase 3
│   └── finding.py         # To be created Phase 3
└── output/
    ├── __init__.py
    ├── base.py            # To be created Phase 4
    ├── console.py         # To be created Phase 4
    └── json.py            # To be created Phase 4
```

## Summary

✅ **Phase 1 Complete** - Production-grade CLI infrastructure
- Config management (YAML + env)
- AWS authentication (boto3)
- CLI framework (Click)
- Credential validation
- Error handling
- Logging system

**Code Quality:**
- Type hints on all functions
- Comprehensive docstrings
- Error handling with logging
- Clean separation of concerns
- Interview-defensible design

**Ready for Phase 2:** Service collectors
