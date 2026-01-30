# PHASE 0 - Project Scope & Definition

## What We're Building

A **production-style CLI scanner** that detects real AWS security misconfigurations with:
- ✅ Clear risk descriptions
- ✅ Evidence from actual AWS resources
- ✅ Actionable remediation steps
- ✅ Clean JSON + terminal output
- ✅ Interview-grade code quality

## Scope (Sharp & Intentional)

### In Scope
- **Cloud**: AWS only (for now)
- **Access**: Read-only IAM role (no modifications)
- **Mode**: CLI tool with click framework
- **Output**: JSON + pretty terminal formatting
- **Rules**: CIS Benchmark 1.5.0 + common misconfigs
- **Services**: IAM, S3, EC2, RDS (Phase 1)
- **Finding Format**: Resource + Risk + Evidence + Remediation

### Out of Scope (Intentionally)
- ❌ Dashboard/Web UI
- ❌ AI/ML scoring algorithms
- ❌ Fake "risk scores" with no methodology
- ❌ Auto-fix without human review
- ❌ Multiple cloud providers (AWS only)
- ❌ Real-time event processing
- ❌ Agent-based scanning (API only)

## Why These Decisions Matter for Interviews

**Scope clarity shows:**
1. Product thinking (understand constraints)
2. Security mindset (read-only is safer)
3. Realistic timeline (don't over-promise)
4. Maintainability (keep it simple)

**When an interviewer asks "Why only AWS?":**
> "Focusing on one cloud provider allows deeper integration and reliability. This pattern scales to multi-cloud in Phase 2 without rearchitecting the core engine."

## Success Criteria

After all phases:
- ✅ Scanner detects real misconfigurations in test AWS account
- ✅ Findings include evidence (not just "bad")
- ✅ Clean JSON output for CI/CD integration
- ✅ Pretty console output for human review
- ✅ Code is interview-defensible (not over-engineered)
- ✅ Git history shows thoughtful progression

## Assumptions

1. User has AWS account with read-only IAM role configured
2. boto3 credentials are available via credential chain
3. Python 3.8+
4. No external security APIs (all AWS-native)

## Timeline

- Phase 0: 1 day ✅ (today)
- Phase 1: 2–3 days
- Phase 2: 3–4 days
- Phase 3: 4–5 days
- Phase 4: 2 days
- Phase 5: 2–3 days
- Phase 6: Optional (1–2 days)
- Phase 7: 1–2 days

**Total: ~14-18 days** to production-ready scanner
