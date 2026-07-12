"""
Compliance framework coverage reporting.

Rather than maintaining a separate, hand-typed table of official CIS
control text (which risks drifting from or misquoting the benchmark
document), this module aggregates the `cis_id` each rule class already
declares against itself -- the rule's own title serves as the
human-readable description of what it checks. Rules without a CIS
mapping (cis_id is None) are simply excluded from CIS coverage
reporting rather than misrepresented as covering some control.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from cloudscan.engine.finding import Finding
from cloudscan.rules.base import BaseRule

FRAMEWORKS = {
    "cis": "CIS AWS Foundations Benchmark",
}


@dataclass
class ControlCoverage:
    """Coverage status for a single compliance control."""

    control_id: str
    rule_ids: List[str] = field(default_factory=list)
    rule_titles: List[str] = field(default_factory=list)
    failed_rule_ids: List[str] = field(default_factory=list)

    @property
    def status(self) -> str:
        return "FAIL" if self.failed_rule_ids else "PASS"


def get_cis_mapped_rules(rules: List[BaseRule]) -> Dict[str, List[BaseRule]]:
    """Group rules by their CIS control id. Rules without a cis_id are excluded."""
    mapping: Dict[str, List[BaseRule]] = {}
    for rule in rules:
        if not rule.cis_id:
            continue
        mapping.setdefault(rule.cis_id, []).append(rule)
    return mapping


def build_cis_coverage(rules: List[BaseRule], findings: List[Finding]) -> List[ControlCoverage]:
    """
    Build a per-control coverage summary: which CIS controls this scanner
    checks, and whether any rule mapped to each one produced a finding.
    """
    mapped = get_cis_mapped_rules(rules)

    findings_by_rule: Dict[str, List[Finding]] = {}
    for finding in findings:
        findings_by_rule.setdefault(finding.rule_id, []).append(finding)

    coverage = []
    for control_id in sorted(mapped.keys(), key=_control_sort_key):
        control_rules = mapped[control_id]
        coverage.append(ControlCoverage(
            control_id=control_id,
            rule_ids=[r.id for r in control_rules],
            rule_titles=[r.title for r in control_rules],
            failed_rule_ids=[r.id for r in control_rules if findings_by_rule.get(r.id)],
        ))

    return coverage


def _control_sort_key(control_id: str):
    """Sort dotted CIS control ids numerically (so "1.10" sorts after "1.9")."""
    parts = []
    for segment in control_id.split("."):
        try:
            parts.append((0, int(segment)))
        except ValueError:
            parts.append((1, segment))
    return parts


def filter_findings_by_framework(
    findings: List[Finding], rules: List[BaseRule], framework: str
) -> List[Finding]:
    """Return only findings produced by rules mapped to the given framework."""
    if framework not in FRAMEWORKS:
        raise ValueError(f"Unknown framework: {framework!r}. Known: {sorted(FRAMEWORKS)}")

    mapped_rule_ids = {r.id for r in rules if r.cis_id}
    return [f for f in findings if f.rule_id in mapped_rule_ids]


def format_coverage_summary(coverage: List[ControlCoverage]) -> str:
    """Render a coverage summary as plain text for console output."""
    if not coverage:
        return "No CIS-mapped rules were evaluated."

    lines = [
        "",
        "=" * 80,
        f"{FRAMEWORKS['cis']} Coverage",
        "-" * 80,
    ]

    passed = sum(1 for c in coverage if c.status == "PASS")
    failed = sum(1 for c in coverage if c.status == "FAIL")

    for c in coverage:
        rules_desc = ", ".join(c.rule_ids)
        lines.append(f"  [{c.status}] {c.control_id} ({rules_desc})")

    lines.append("-" * 80)
    lines.append(f"  Controls checked: {len(coverage)}  Passed: {passed}  Failed: {failed}")
    lines.append("=" * 80)

    return "\n".join(lines)
