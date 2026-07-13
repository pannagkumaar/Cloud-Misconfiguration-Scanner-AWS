# CloudScan — Architecture

## High-level flow

```
AWS Account (read-only IAM)  ──┐
                                ├──> normalize.py ──> ScanContext ──> RuleEngine ──> scoring ──> OutputFormatter
Offline JSON export ───────────┘      (schema.py)                    (31 rules)     (0-100)    (console/json/jsonl/sarif/html)
```

Both data sources — live boto3 collectors and an offline JSON/YAML export —
converge on the same normalization step before anything evaluates them. This
is the one piece of the design worth calling out: early versions of this
scanner had rules read the collectors' raw shape directly, and offline mode
(which loads a differently-shaped raw AWS export) silently produced zero
findings because rules were checking for keys the offline path never
populated. `cloudscan/schema.py` documents the normalized contract each
service's data must satisfy; `cloudscan/loaders/normalize.py` is the adapter
that gets both live and offline data into that shape. Rules only ever see
normalized data.

## Project structure

```
cloudscan/
├── cmd/
│   └── cloudscan.py            # Click CLI: aws-scan, website-scan, validate, version
├── collectors/
│   ├── base.py                 # BaseCollector
│   ├── manager.py               # CollectorManager — registers/runs all collectors
│   ├── iam.py                   # users, roles, policies, inline docs, credential report, password policy
│   ├── s3.py                    # buckets, ACLs, policies, encryption, versioning, logging, PAB
│   ├── ec2.py                   # instances, security groups
│   ├── rds.py                   # DB instances
│   └── cloudtrail.py            # trails + trail status
├── loaders/
│   ├── base.py                  # BaseLoader
│   ├── aws_live.py               # drives collectors for live-mode scans
│   ├── file_loader.py            # loads + normalizes an offline JSON/YAML export
│   └── normalize.py              # raw AWS shape -> schema.py normalized shape
├── engine/
│   ├── context.py                 # ScanContext — typed accessors rules query against
│   ├── rule_engine.py             # dynamic rule loading + evaluation + scoring + sort
│   ├── finding.py                  # Finding dataclass, Severity enum
│   └── scoring.py                  # 0-100 risk score, severity-tier-ordering guarantee
├── rules/
│   ├── base.py                     # BaseRule, _create_finding() helper
│   └── *.py                        # 31 rule files, one class per file (iam_*, s3_*, sg_*, ec2_*, rds_*, cloudtrail_*)
├── compliance/
│   └── mappings.py                 # CIS control -> rule id mapping, coverage summary, --framework filter
├── output/
│   ├── base.py                     # BaseOutputFormatter
│   ├── console.py                   # human-readable terminal output
│   ├── json.py                      # single JSON document (+ jsonl variant)
│   ├── sarif.py                     # SARIF 2.1.0 for GitHub Code Scanning
│   └── html.py                      # self-contained HTML report
├── website/                          # secondary module: unauthenticated website recon
│   ├── scanner.py
│   └── output.py
├── config.py                          # config.yaml loading + env var overrides
└── schema.py                          # the normalized data contract everything agrees on

demo/
└── seed_demo_account.py               # moto-seeded vulnerable account + scan runner (make demo)

examples/
└── sample-aws-config.json             # worked example of an offline export

tests/                                  # 261 tests: rules, collectors (moto), engine, formatters, integration
```

## Design principles

### 1. One normalized contract, two data sources
Collectors (live boto3) and the file loader (offline export) are the only two
places that know about AWS's actual response shapes. Everything downstream —
rules, the engine, output formatters — only ever sees the normalized shape
defined in `schema.py`. This is what makes offline mode a first-class citizen
rather than a best-effort fallback: the same rule, the same test fixtures, and
the same evaluation path run whether the data came from a live account or a
JSON file someone handed you.

### 2. Rules are pure functions over ScanContext
A rule (`cloudscan/rules/base.py` subclass) takes a `ScanContext` and returns
a list of `Finding`s. No AWS API calls, no I/O. This is what makes them unit
testable against hand-built fixtures without moto or any network access —
see `tests/test_rules_*.py`.

### 3. Rules are discovered dynamically, not registered
`RuleEngine.load_rules()` walks `cloudscan/rules/*.py`, imports each file, and
picks up every `BaseRule` subclass *defined in that file* (not merely
imported into its namespace — `inspect.getmembers()` would otherwise also
pick up a rule class imported for reuse in a different rule file, causing it
to be instantiated twice; see `RuleEngine._load_rules_from_file`). Adding a
rule means dropping a new file in `rules/` — no central registry to edit.

### 4. Scoring augments severity, never overrides it
Every finding gets a 0–100 score to rank findings *within* a severity tier
(a HIGH indicating internet exposure vs. a HIGH that's a best-practice gap).
The score is capped so a boosted lower-severity finding can never outrank an
unboosted higher-severity one — enforced by a parametrized test over every
severity pair in `tests/test_scoring.py`.

### 5. Read-only, credential-safe
Collectors only call `Describe*`/`Get*`/`List*` APIs (see the IAM policy in
the README). No credentials are ever written to findings or logs.

## Data flow

**1. Collection / loading**
```
boto3 (live)  ──> Collector.collect() ──┐
                                          ├──> normalize_collected_data() ──> dict matching schema.py
JSON/YAML (offline) ──> FileLoader.load() ─┘
```

**2. Context construction**
```
normalized dict ──> ScanContext(data) ──> typed accessors (get_buckets(), get_security_groups(), ...)
```

**3. Evaluation**
```
for rule in RuleEngine.rules:
    findings += rule.evaluate(context)
score_findings(findings)   # sets .score, sorts CRITICAL -> INFO, ties by score desc
```

**4. Reporting**
```
findings ──> OutputFormatter.format() ──> console / json / jsonl / sarif / html
```

Optionally filtered first by `compliance.filter_findings_by_framework()` when
`--framework cis` is passed, with a coverage summary printed alongside.

## Testing strategy

- **Rule unit tests** (`tests/test_rules_*.py`): hand-built `ScanContext`
  fixtures via builder helpers in `tests/conftest.py`, one test per rule
  branch (trigger / don't-trigger / edge case).
- **Collector tests** (`tests/test_collectors_*.py`): `moto`-mocked AWS —
  these caught a real bug where `s3_client.exceptions.NoSuchBucketPolicy`
  and similar dynamically-generated exception attributes didn't exist on the
  installed botocore version, aborting collection for any bucket missing
  optional config, not just the one field being fetched.
- **Formatter tests** (`tests/test_output_*.py`): SARIF output is validated
  against the official OASIS SARIF 2.1.0 JSON schema
  (`tests/fixtures/sarif-2.1.0-schema.json`); HTML output is checked for
  balanced tags via `HTMLParser`.
- **Integration test** (`tests/test_integration_moto.py`,
  `tests/test_integration_sample_file.py`): seeds a mock account end-to-end
  and asserts on the findings that come out, exercising the full
  collect → normalize → evaluate → score pipeline.

## Not implemented (by scope, not by oversight)

- **Auto-remediation**: intentionally out of scope — CloudScan is read-only
  by design; an auto-fix mode would need a much more conservative,
  explicitly opt-in change-management story than a portfolio project
  warrants.
- **Historical findings / diffing between scans**: no persistence layer;
  each run is stateless. Would need a datastore to track finding lifecycle.
- **Non-CIS compliance frameworks** (PCI-DSS, NIST, SOC 2): the
  `compliance/mappings.py` layer is built to support additional frameworks
  the same way CIS was added, just not populated yet.
