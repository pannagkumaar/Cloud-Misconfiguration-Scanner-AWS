"""
Tests for the self-contained HTML output formatter.

Validates structural HTML correctness (balanced tags, valid JS syntax)
and content correctness (escaping, severity counts, empty state) rather
than pixel-level rendering.
"""

import re
from html.parser import HTMLParser

from cloudscan.engine.finding import Finding, Severity
from cloudscan.output.html import HTMLOutputFormatter

VOID_TAGS = {"meta", "br", "hr", "img", "input", "link"}


class _TagBalanceChecker(HTMLParser):
    """Verifies every non-void opening tag has a matching, correctly
    nested closing tag."""

    def __init__(self):
        super().__init__()
        self.stack = []
        self.mismatches = []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID_TAGS:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        pass  # self-closing (<tag />); nothing to push

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.mismatches.append((tag, self.stack[-1] if self.stack else None))
        else:
            self.stack.pop()


def make_finding(
    rule_id="S3-001", severity=Severity.HIGH, resource_id="my-bucket",
    title="Test finding", cis_id=None,
):
    return Finding(
        rule_id=rule_id, title=title, description="Test description",
        severity=severity, service="s3", cis_id=cis_id,
        resource_id=resource_id, resource_type="S3 Bucket",
        risk="Test risk", evidence={"key": "value"},
        remediation="Fix it", remediation_url="https://docs.aws.amazon.com/x",
    )


def assert_balanced_html(document: str):
    checker = _TagBalanceChecker()
    checker.feed(document)
    assert checker.mismatches == [], f"Mismatched tags: {checker.mismatches}"
    assert checker.stack == [], f"Unclosed tags: {checker.stack}"


class TestHTMLStructure:
    def test_is_complete_html_document(self):
        doc = HTMLOutputFormatter().format([make_finding()])
        assert doc.startswith("<!DOCTYPE html>")
        assert doc.rstrip().endswith("</html>")
        assert "<head>" in doc and "</head>" in doc
        assert "<body>" in doc and "</body>" in doc

    def test_tags_are_balanced_with_findings(self):
        findings = [make_finding(rule_id=f"S3-00{i}") for i in range(1, 4)]
        assert_balanced_html(HTMLOutputFormatter().format(findings))

    def test_tags_are_balanced_with_no_findings(self):
        assert_balanced_html(HTMLOutputFormatter().format([]))

    def test_inline_script_has_valid_syntax_markers(self):
        """Sanity check: braces inside the CSS/JS template are balanced
        (a common failure mode when str.format() literal braces are
        miscounted in a template this large)."""
        doc = HTMLOutputFormatter().format([make_finding()])
        script_match = re.search(r"<script>(.*?)</script>", doc, re.DOTALL)
        assert script_match is not None
        script = script_match.group(1)
        assert script.count("{") == script.count("}")
        assert script.count("(") == script.count(")")


class TestHTMLContent:
    def test_finding_count_in_heading(self):
        findings = [make_finding(rule_id=f"S3-00{i}") for i in range(1, 4)]
        doc = HTMLOutputFormatter().format(findings)
        assert "3 findings" in doc

    def test_singular_finding_count(self):
        doc = HTMLOutputFormatter().format([make_finding()])
        assert "1 finding " in doc  # not "1 findings"

    def test_empty_state_message_shown(self):
        doc = HTMLOutputFormatter().format([])
        assert "No findings. Clean scan." in doc

    def test_severity_counts_present(self):
        findings = [
            make_finding(rule_id="A", severity=Severity.CRITICAL),
            make_finding(rule_id="B", severity=Severity.CRITICAL),
            make_finding(rule_id="C", severity=Severity.LOW),
        ]
        doc = HTMLOutputFormatter().format(findings)
        assert 'data-severity-filter="CRITICAL"' in doc
        assert 'data-severity-filter="LOW"' in doc

    def test_html_special_characters_are_escaped(self):
        finding = make_finding(title='Bucket <script>alert("xss")</script> exposed')
        doc = HTMLOutputFormatter().format([finding])
        assert "<script>alert(" not in doc.split("<body>")[1].split("<script>")[0]
        assert "&lt;script&gt;" in doc

    def test_cis_badge_shown_when_present(self):
        doc = HTMLOutputFormatter().format([make_finding(cis_id="1.5")])
        assert "CIS 1.5" in doc

    def test_no_cis_badge_when_absent(self):
        doc = HTMLOutputFormatter().format([make_finding(cis_id=None)])
        assert "badge-cis" not in doc

    def test_resource_id_appears_in_output(self):
        doc = HTMLOutputFormatter().format([make_finding(resource_id="prod-db-1")])
        assert "prod-db-1" in doc

    def test_both_theme_tokens_defined(self):
        """Light and dark theme overrides must both exist so the viewer's
        toggle works in either direction."""
        doc = HTMLOutputFormatter().format([])
        assert ':root[data-theme="dark"]' in doc
        assert ':root[data-theme="light"]' in doc
        assert "@media (prefers-color-scheme: dark)" in doc


class TestHTMLFileWriting:
    def test_write_to_file(self, tmp_path):
        output_file = tmp_path / "report.html"
        formatter = HTMLOutputFormatter(output_file=str(output_file))
        content = formatter.format([make_finding()])
        formatter.write(content)
        assert output_file.exists()
        assert output_file.read_text(encoding="utf-8").startswith("<!DOCTYPE html>")
