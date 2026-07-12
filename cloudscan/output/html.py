"""
HTML output formatter - a single, self-contained HTML report.

No external requests (fonts, scripts, stylesheets are all inline), so the
file opens correctly straight from disk with no network access. Supports
the viewer's light/dark preference and a manual toggle.
"""

import html
import json
from datetime import datetime, timezone
from typing import List

from cloudscan.engine.finding import Finding
from cloudscan.output.base import BaseOutputFormatter

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class HTMLOutputFormatter(BaseOutputFormatter):
    """Formats findings as a single self-contained HTML report."""

    def format(self, findings: List[Finding]) -> str:
        counts = self._get_severity_count(findings)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        rows_html = "\n".join(self._render_row(f, i) for i, f in enumerate(findings))
        stat_tiles_html = "\n".join(self._render_stat_tile(sev, counts[sev]) for sev in SEVERITY_ORDER)

        return _PAGE_TEMPLATE.format(
            timestamp=html.escape(timestamp),
            total=len(findings),
            plural="" if len(findings) == 1 else "s",
            stat_tiles=stat_tiles_html,
            rows=rows_html or _EMPTY_STATE,
        )

    def _render_stat_tile(self, severity: str, count: int) -> str:
        return f"""
        <button class="stat-tile" data-severity-filter="{severity}" aria-pressed="false">
          <span class="stat-count sev-{severity.lower()}">{count}</span>
          <span class="stat-label">{severity.title()}</span>
        </button>"""

    def _render_row(self, finding: Finding, index: int) -> str:
        sev = finding.severity.value
        evidence_html = self._render_evidence(finding.evidence)
        remediation_html = html.escape(finding.remediation or "").replace("\n", "<br>")
        cis_badge = (
            f'<span class="badge badge-cis">CIS {html.escape(finding.cis_id)}</span>'
            if finding.cis_id else ""
        )
        remediation_link = (
            f'<a class="ref-link" href="{html.escape(finding.remediation_url)}" '
            f'target="_blank" rel="noopener noreferrer">Reference &rarr;</a>'
            if finding.remediation_url else ""
        )

        return f"""
        <article class="finding sev-border-{sev.lower()}" data-severity="{sev}" data-index="{index}">
          <button class="finding-summary" aria-expanded="false">
            <span class="sev-chip sev-{sev.lower()}">{sev}</span>
            <span class="finding-rule-id">{html.escape(finding.rule_id)}</span>
            <span class="finding-title">{html.escape(finding.title)}</span>
            {cis_badge}
            <span class="finding-resource">{html.escape(finding.resource_id)}</span>
            <span class="chevron" aria-hidden="true">&#9656;</span>
          </button>
          <div class="finding-detail">
            <p class="finding-description">{html.escape(finding.description)}</p>
            <dl class="detail-grid">
              <dt>Resource</dt><dd>{html.escape(finding.resource_type)} &mdash; <code>{html.escape(finding.resource_id)}</code></dd>
              <dt>Risk</dt><dd>{html.escape(finding.risk)}</dd>
              <dt>Evidence</dt><dd>{evidence_html}</dd>
              <dt>Remediation</dt><dd>{remediation_html} {remediation_link}</dd>
            </dl>
          </div>
        </article>"""

    def _render_evidence(self, evidence: dict) -> str:
        if not evidence:
            return '<span class="text-muted">none</span>'
        items = []
        for key, value in evidence.items():
            items.append(
                f'<code>{html.escape(str(key))}</code>: '
                f'<code>{html.escape(json.dumps(value, default=str))}</code>'
            )
        return '<span class="evidence-list">' + ", ".join(items) + "</span>"


_EMPTY_STATE = '<p class="empty-state">No findings. Clean scan.</p>'

_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CloudScan Report</title>
<style>
:root {{
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-raised: #ffffff;
  --border: #e1e4ea;
  --text: #161b22;
  --text-muted: #5b6472;
  --accent: #2c5282;
  --accent-contrast: #ffffff;
  --sev-critical: #b91c1c;
  --sev-high: #c2410c;
  --sev-medium: #a16207;
  --sev-low: #15803d;
  --sev-info: #475569;
  --shadow: 0 1px 2px rgba(20, 24, 32, 0.06), 0 4px 12px rgba(20, 24, 32, 0.05);
  --radius: 10px;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", "Consolas", "Liberation Mono", monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}}

@media (prefers-color-scheme: dark) {{
  :root {{
    --bg: #0d1117;
    --surface: #141a22;
    --surface-raised: #181f29;
    --border: #262c36;
    --text: #e6e9ef;
    --text-muted: #8b95a5;
    --accent: #6f9bd4;
    --accent-contrast: #0d1117;
    --shadow: 0 1px 2px rgba(0, 0, 0, 0.3), 0 4px 16px rgba(0, 0, 0, 0.35);
  }}
}}

:root[data-theme="dark"] {{
  --bg: #0d1117;
  --surface: #141a22;
  --surface-raised: #181f29;
  --border: #262c36;
  --text: #e6e9ef;
  --text-muted: #8b95a5;
  --accent: #6f9bd4;
  --accent-contrast: #0d1117;
  --shadow: 0 1px 2px rgba(0, 0, 0, 0.3), 0 4px 16px rgba(0, 0, 0, 0.35);
}}

:root[data-theme="light"] {{
  --bg: #f6f7f9;
  --surface: #ffffff;
  --surface-raised: #ffffff;
  --border: #e1e4ea;
  --text: #161b22;
  --text-muted: #5b6472;
  --accent: #2c5282;
  --accent-contrast: #ffffff;
  --shadow: 0 1px 2px rgba(20, 24, 32, 0.06), 0 4px 12px rgba(20, 24, 32, 0.05);
}}

* {{ box-sizing: border-box; }}

body {{
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 15px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}}

.wrap {{
  max-width: 960px;
  margin: 0 auto;
  padding: 2rem 1.5rem 4rem;
}}

header.masthead {{
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
  padding-bottom: 1.5rem;
  margin-bottom: 1.75rem;
  border-bottom: 1px solid var(--border);
}}

.eyebrow {{
  font-family: var(--mono);
  font-size: 0.75rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--accent);
}}

h1 {{
  margin: 0;
  font-size: 1.65rem;
  font-weight: 700;
  letter-spacing: -0.01em;
  text-wrap: balance;
}}

.meta-line {{
  font-family: var(--mono);
  font-size: 0.8rem;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}}

.stat-row {{
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 0.6rem;
  margin-bottom: 1.75rem;
}}

.stat-tile {{
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 0.15rem;
  padding: 0.85rem 0.9rem;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  cursor: pointer;
  font-family: inherit;
  text-align: left;
  transition: border-color 0.15s ease, transform 0.1s ease;
}}

.stat-tile:hover {{ border-color: var(--accent); }}
.stat-tile[aria-pressed="true"] {{
  border-color: var(--accent);
  box-shadow: 0 0 0 1px var(--accent);
}}
.stat-tile:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; }}

.stat-count {{
  font-family: var(--mono);
  font-size: 1.6rem;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}}

.stat-label {{
  font-size: 0.72rem;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--text-muted);
}}

.sev-critical {{ color: var(--sev-critical); }}
.sev-high {{ color: var(--sev-high); }}
.sev-medium {{ color: var(--sev-medium); }}
.sev-low {{ color: var(--sev-low); }}
.sev-info {{ color: var(--sev-info); }}

.toolbar {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  margin-bottom: 0.9rem;
}}

.toolbar-label {{
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--text-muted);
  font-variant-numeric: tabular-nums;
}}

#clear-filter {{
  font-family: var(--mono);
  font-size: 0.75rem;
  color: var(--accent);
  background: none;
  border: none;
  cursor: pointer;
  padding: 0;
  display: none;
}}
#clear-filter.visible {{ display: inline; }}

.findings-list {{
  display: flex;
  flex-direction: column;
  gap: 0.55rem;
}}

.finding {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-left-width: 4px;
  border-radius: var(--radius);
  overflow: hidden;
}}

.sev-border-critical {{ border-left-color: var(--sev-critical); }}
.sev-border-high {{ border-left-color: var(--sev-high); }}
.sev-border-medium {{ border-left-color: var(--sev-medium); }}
.sev-border-low {{ border-left-color: var(--sev-low); }}
.sev-border-info {{ border-left-color: var(--sev-info); }}

.finding-summary {{
  width: 100%;
  display: flex;
  align-items: center;
  gap: 0.65rem;
  padding: 0.7rem 0.85rem;
  background: none;
  border: none;
  cursor: pointer;
  text-align: left;
  color: inherit;
  font-family: inherit;
  font-size: 0.88rem;
}}
.finding-summary:focus-visible {{ outline: 2px solid var(--accent); outline-offset: -2px; }}

.sev-chip {{
  font-family: var(--mono);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.03em;
  padding: 0.15rem 0.4rem;
  border-radius: 4px;
  background: color-mix(in srgb, currentColor 14%, transparent);
  flex-shrink: 0;
}}

.finding-rule-id {{
  font-family: var(--mono);
  font-size: 0.78rem;
  color: var(--text-muted);
  flex-shrink: 0;
}}

.finding-title {{
  flex: 1;
  font-weight: 500;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}}

.badge {{
  font-family: var(--mono);
  font-size: 0.68rem;
  padding: 0.1rem 0.35rem;
  border-radius: 4px;
  border: 1px solid var(--border);
  color: var(--text-muted);
  flex-shrink: 0;
}}

.finding-resource {{
  font-family: var(--mono);
  font-size: 0.76rem;
  color: var(--text-muted);
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  flex-shrink: 1;
}}

.chevron {{
  flex-shrink: 0;
  color: var(--text-muted);
  transition: transform 0.15s ease;
  font-size: 0.7rem;
}}
.finding.open .chevron {{ transform: rotate(90deg); }}

.finding-detail {{
  display: none;
  padding: 0 0.85rem 1rem 0.85rem;
  border-top: 1px solid var(--border);
}}
.finding.open .finding-detail {{ display: block; }}

.finding-description {{
  color: var(--text-muted);
  font-size: 0.85rem;
  margin: 0.75rem 0;
}}

.detail-grid {{
  display: grid;
  grid-template-columns: 110px 1fr;
  gap: 0.4rem 0.9rem;
  margin: 0;
  font-size: 0.85rem;
}}
.detail-grid dt {{
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 0.72rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  padding-top: 0.1rem;
}}
.detail-grid dd {{ margin: 0; }}

code {{
  font-family: var(--mono);
  font-size: 0.82em;
  background: var(--bg);
  padding: 0.05rem 0.3rem;
  border-radius: 4px;
  border: 1px solid var(--border);
}}

.evidence-list code {{ margin: 0 0.15rem 0.15rem 0; display: inline-block; }}

.ref-link {{
  font-size: 0.8rem;
  color: var(--accent);
  text-decoration: none;
  white-space: nowrap;
}}
.ref-link:hover {{ text-decoration: underline; }}

.text-muted {{ color: var(--text-muted); }}

.empty-state {{
  text-align: center;
  padding: 3rem 1rem;
  color: var(--text-muted);
  font-family: var(--mono);
}}

.theme-toggle {{
  position: fixed;
  top: 1rem;
  right: 1rem;
  font-family: var(--mono);
  font-size: 0.72rem;
  color: var(--text-muted);
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.3rem 0.55rem;
  cursor: pointer;
}}

@media (max-width: 640px) {{
  .stat-row {{ grid-template-columns: repeat(3, 1fr); }}
  .finding-resource {{ display: none; }}
}}
</style>
</head>
<body>

<div class="wrap">
  <button class="theme-toggle" id="theme-toggle" type="button">theme</button>

  <header class="masthead">
    <span class="eyebrow">CloudScan &mdash; AWS Misconfiguration Report</span>
    <h1>{total} finding{plural} across the scanned account</h1>
    <span class="meta-line">generated {timestamp}</span>
  </header>

  <div class="stat-row" id="stat-row">
    {stat_tiles}
  </div>

  <div class="toolbar">
    <span class="toolbar-label" id="visible-count"></span>
    <button id="clear-filter" type="button">clear filter &times;</button>
  </div>

  <div class="findings-list" id="findings-list">
    {rows}
  </div>
</div>

<script>
(function() {{
  var root = document.documentElement;
  var toggle = document.getElementById('theme-toggle');
  toggle.addEventListener('click', function() {{
    var current = root.getAttribute('data-theme');
    var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    var isDark = current ? current === 'dark' : prefersDark;
    root.setAttribute('data-theme', isDark ? 'light' : 'dark');
  }});

  var findings = document.querySelectorAll('.finding');
  findings.forEach(function(el) {{
    var btn = el.querySelector('.finding-summary');
    btn.addEventListener('click', function() {{
      var isOpen = el.classList.toggle('open');
      btn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
    }});
  }});

  var activeSeverity = null;
  var tiles = document.querySelectorAll('.stat-tile');
  var clearBtn = document.getElementById('clear-filter');
  var visibleCount = document.getElementById('visible-count');
  var total = findings.length;

  function applyFilter() {{
    var visible = 0;
    findings.forEach(function(el) {{
      var match = !activeSeverity || el.getAttribute('data-severity') === activeSeverity;
      el.style.display = match ? '' : 'none';
      if (match) visible++;
    }});
    tiles.forEach(function(t) {{
      t.setAttribute('aria-pressed', t.getAttribute('data-severity-filter') === activeSeverity ? 'true' : 'false');
    }});
    clearBtn.classList.toggle('visible', !!activeSeverity);
    visibleCount.textContent = activeSeverity
      ? 'Showing ' + visible + ' of ' + total + ' (' + activeSeverity.toLowerCase() + ')'
      : 'Showing all ' + total + ' finding' + (total === 1 ? '' : 's');
  }}

  tiles.forEach(function(tile) {{
    tile.addEventListener('click', function() {{
      var sev = tile.getAttribute('data-severity-filter');
      activeSeverity = activeSeverity === sev ? null : sev;
      applyFilter();
    }});
  }});

  clearBtn.addEventListener('click', function() {{
    activeSeverity = null;
    applyFilter();
  }});

  applyFilter();
}})();
</script>
</body>
</html>
"""
