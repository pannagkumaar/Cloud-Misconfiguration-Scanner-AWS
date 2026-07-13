# Website scanner (secondary module)

`cloudscan website-scan <url>` is an unauthenticated, passive recon check
against a public website — useful as an opportunistic first step when you
don't have AWS credentials yet, but it is **not** the scanner's core
capability. The real security analysis is `cloudscan aws-scan`, which
evaluates actual AWS resource configuration against 31 rules (see
[README.md](README.md)). This module can't see IAM policies, security
groups, or encryption settings — it only sees what's observable from the
outside of a single URL.

## What it checks

All checks run against one target URL, no credentials, no active exploitation:

- **Security headers** — HSTS, X-Content-Type-Options, X-Frame-Options, CSP,
  X-XSS-Protection, Referrer-Policy, Permissions-Policy, Cache-Control; flags
  `Server`/`X-Powered-By` disclosure.
- **TLS certificate** — expiration, self-signed detection, CN/hostname mismatch.
- **DNS** — confirms the hostname resolves (flags `NXDOMAIN`).
- **AWS infrastructure fingerprinting** — looks for AWS response headers
  (`X-Amzn-RequestId`, `X-Amz-Cf-Pop`) and page-content references to S3,
  CloudFront, RDS, API Gateway, Cognito, DynamoDB, Lambda, ElastiCache endpoints.
- **Credential exposure** — regex scan of page content for AWS access key IDs,
  secret keys, session tokens accidentally left in client-side code.
- **S3 bucket name discovery** — regex scan for `*.s3.amazonaws.com`-style
  URLs referenced in the page.
- **Subdomain probing** — tries a fixed list of common subdomains
  (`api`, `admin`, `staging`, `dev`, `rds`, ...) and reports any that resolve.
- **Error page disclosure** — requests a handful of common paths
  (`/admin`, `/.aws`, `/config`, ...) and flags AWS-related text in 4xx/5xx responses.

## Usage

```bash
cloudscan website-scan https://example.com
cloudscan website-scan https://example.com --output json
cloudscan website-scan https://example.com --output-file findings.txt
```

If it detects AWS infrastructure, it suggests the natural next step:

```bash
cloudscan aws-scan --from-file aws-config.json
```

which is where the actual finding volume and depth comes from.

## Implementation

`cloudscan/website/scanner.py` — `WebsiteScanner.scan()` runs each check and
returns a list of `WebsiteIndicator`s (type, severity, title, evidence,
remediation). `cloudscan/website/output.py` formats them for console/JSON.

## Known limitations

- Subdomain probing is a fixed wordlist, not real enumeration (no DNS
  brute-force, no certificate-transparency lookup).
- AWS service fingerprinting is substring matching against page content and
  response headers — it will miss anything not referenced client-side, and
  can false-positive on unrelated text containing e.g. `amazonaws.com`.
- No rate limiting or scope controls — only point this at targets you're
  authorized to scan.
