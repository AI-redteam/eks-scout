"""Interactive HTML report export for EKS Scout findings."""
import json
import logging
from datetime import datetime


def export_findings_to_html(findings, filename="eks_scout_report.html",
                            combos=None, scan_metadata=None):
    """Export findings to a self-contained interactive HTML report.

    Args:
        findings: List of finding dicts.
        filename: Output HTML file path.
        combos: Optional list of combo result dicts.
        scan_metadata: Optional dict with cluster_name, region, profile, scan_time.
    """
    if not findings and not combos:
        logging.info("No findings to export.")
        return

    logging.info(f"Exporting {len(findings)} findings to {filename} in HTML format...")

    data_json = _serialize_data(findings, combos, scan_metadata)
    css = _build_css()
    html_body = _build_html_skeleton(scan_metadata)
    js = _build_javascript()

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>EKS Scout Report{' — ' + scan_metadata['cluster_name'] if scan_metadata and scan_metadata.get('cluster_name') else ''}</title>
<style>
{css}
</style>
</head>
<body>
<script>const REPORT_DATA = {data_json};</script>
{html_body}
<script>
{js}
</script>
</body>
</html>"""

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        logging.info(f"Successfully exported HTML report to {filename}")
    except IOError as e:
        logging.error(f"Failed to write HTML file {filename}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during HTML export: {e}")


def _serialize_data(findings, combos, scan_metadata):
    """Serialize findings and combos to a JSON string for embedding."""
    serializable_combos = None
    if combos:
        serializable_combos = []
        for combo in combos:
            c = dict(combo)
            if 'matched_finding_types' in c:
                c['matched_finding_types'] = sorted(c['matched_finding_types'])
            serializable_combos.append(c)

    data = {
        'findings': findings,
        'combos': serializable_combos or [],
        'scan_metadata': scan_metadata or {},
        'generated_at': datetime.now().isoformat(),
    }

    raw = json.dumps(data, ensure_ascii=True, default=str)
    # Escape </script> sequences in embedded data to prevent premature tag close
    return raw.replace("</", "<\\/")


def _build_css():
    """Return the full stylesheet for the report."""
    return """
/* === Reset & Base === */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  background: #0d1117; color: #c9d1d9; line-height: 1.6;
}
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }

/* === Layout === */
.container { max-width: 1280px; margin: 0 auto; padding: 24px 16px; }

/* === Header === */
.header {
  display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 12px; margin-bottom: 24px; padding-bottom: 16px;
  border-bottom: 1px solid #30363d;
}
.header h1 { font-size: 24px; color: #f0f6fc; font-weight: 600; }
.header-meta { font-size: 13px; color: #8b949e; text-align: right; }
.header-meta span { display: block; }

/* === Dashboard === */
.dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
.metric-card {
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 20px; text-align: center;
}
.metric-card .value { font-size: 36px; font-weight: 700; color: #f0f6fc; }
.metric-card .label { font-size: 13px; color: #8b949e; margin-top: 4px; }

/* === Charts === */
.charts-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 24px; }
.chart-card {
  background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px;
}
.chart-card h3 { font-size: 14px; color: #8b949e; margin-bottom: 16px; font-weight: 500; }
.donut-container { display: flex; align-items: center; justify-content: center; gap: 24px; }
.donut {
  width: 140px; height: 140px; border-radius: 50%; position: relative;
}
.donut-hole {
  position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
  width: 80px; height: 80px; border-radius: 50%; background: #161b22;
  display: flex; align-items: center; justify-content: center;
  font-size: 24px; font-weight: 700; color: #f0f6fc;
}
.legend { display: flex; flex-direction: column; gap: 8px; }
.legend-item { display: flex; align-items: center; gap: 8px; font-size: 13px; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.bar-chart { display: flex; flex-direction: column; gap: 8px; }
.bar-row { display: flex; align-items: center; gap: 8px; }
.bar-label { width: 140px; font-size: 13px; color: #c9d1d9; text-align: right; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.bar-track { flex: 1; height: 22px; background: #21262d; border-radius: 4px; overflow: hidden; }
.bar-fill { height: 100%; border-radius: 4px; min-width: 2px; transition: width 0.3s; }
.bar-count { width: 36px; font-size: 13px; color: #8b949e; }

/* === Controls === */
.controls {
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 16px; margin-bottom: 16px; display: flex; flex-wrap: wrap;
  gap: 12px; align-items: center;
}
.search-box {
  flex: 1 1 280px; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d;
  border-radius: 6px; color: #c9d1d9; font-size: 14px; outline: none;
}
.search-box:focus { border-color: #58a6ff; }
.search-box::placeholder { color: #484f58; }
.filter-group { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.filter-group label { font-size: 12px; color: #8b949e; margin-right: 4px; }
.chip {
  padding: 4px 12px; border-radius: 16px; font-size: 12px; cursor: pointer;
  border: 1px solid #30363d; background: #21262d; color: #c9d1d9;
  transition: all 0.15s; user-select: none;
}
.chip:hover { border-color: #58a6ff; }
.chip.active { background: #388bfd26; border-color: #58a6ff; color: #58a6ff; }
.chip.sev-critical.active { background: #f8514926; border-color: #f85149; color: #f85149; }
.chip.sev-high.active { background: #f0883e26; border-color: #f0883e; color: #f0883e; }
.chip.sev-medium.active { background: #d2992226; border-color: #d29922; color: #d29922; }
.chip.sev-low.active { background: #58a6ff26; border-color: #58a6ff; color: #58a6ff; }
.chip.sev-info.active { background: #8b949e26; border-color: #8b949e; color: #8b949e; }
select.filter-select {
  padding: 4px 8px; background: #21262d; border: 1px solid #30363d;
  border-radius: 6px; color: #c9d1d9; font-size: 12px; outline: none; cursor: pointer;
}
.results-count { font-size: 13px; color: #8b949e; margin-left: auto; white-space: nowrap; }

/* === Table === */
.table-container { overflow-x: auto; margin-bottom: 24px; }
table { width: 100%; border-collapse: collapse; }
th {
  background: #161b22; color: #8b949e; font-size: 12px; font-weight: 600;
  text-transform: uppercase; letter-spacing: 0.5px; padding: 10px 12px;
  text-align: left; border-bottom: 1px solid #30363d; cursor: pointer;
  user-select: none; white-space: nowrap;
}
th:hover { color: #c9d1d9; }
th .sort-arrow { margin-left: 4px; font-size: 10px; }
td { padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 14px; vertical-align: top; }
tr:hover td { background: #161b22; }
tr.expanded td { background: #161b22; border-bottom-color: transparent; }
.sev-badge {
  display: inline-block; padding: 2px 8px; border-radius: 12px;
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;
}
.sev-critical { background: #f8514926; color: #f85149; }
.sev-high { background: #f0883e26; color: #f0883e; }
.sev-medium { background: #d2992226; color: #d29922; }
.sev-low { background: #58a6ff26; color: #58a6ff; }
.sev-info, .sev-informational { background: #8b949e26; color: #8b949e; }

/* === Detail Row === */
.detail-row td { padding: 0; }
.detail-content {
  padding: 16px 24px; background: #0d1117; border-bottom: 1px solid #30363d;
}
.detail-content dl { display: grid; grid-template-columns: 120px 1fr; gap: 8px 16px; }
.detail-content dt { font-size: 12px; color: #8b949e; font-weight: 600; text-transform: uppercase; }
.detail-content dd { font-size: 14px; color: #c9d1d9; word-break: break-word; }

/* === Combos === */
.section-title {
  font-size: 20px; font-weight: 600; color: #f0f6fc; margin: 32px 0 16px;
  padding-bottom: 8px; border-bottom: 1px solid #30363d;
}
.combo-cards { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 16px; margin-bottom: 24px; }
.combo-card {
  background: #161b22; border: 1px solid #30363d; border-radius: 8px;
  padding: 16px; cursor: pointer; transition: border-color 0.15s;
}
.combo-card:hover { border-color: #58a6ff; }
.combo-card-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; margin-bottom: 8px; }
.combo-card-title { font-size: 15px; font-weight: 600; color: #f0f6fc; }
.combo-workload { font-size: 12px; color: #8b949e; font-family: monospace; margin-bottom: 8px; }
.combo-impact { font-size: 13px; color: #c9d1d9; margin-bottom: 12px; }
.combo-types { display: flex; flex-wrap: wrap; gap: 4px; margin-bottom: 8px; }
.combo-type-badge {
  padding: 2px 8px; border-radius: 4px; font-size: 11px;
  background: #21262d; color: #8b949e; border: 1px solid #30363d;
}
.combo-detail { display: none; margin-top: 12px; padding-top: 12px; border-top: 1px solid #30363d; }
.combo-card.expanded .combo-detail { display: block; }
.mini-table { width: 100%; font-size: 12px; }
.mini-table th { font-size: 11px; padding: 6px 8px; }
.mini-table td { font-size: 12px; padding: 6px 8px; }

/* === Export Bar === */
.export-bar { display: flex; gap: 8px; margin-bottom: 24px; }
.btn {
  padding: 8px 16px; border-radius: 6px; font-size: 13px; font-weight: 500;
  cursor: pointer; border: 1px solid #30363d; background: #21262d; color: #c9d1d9;
  transition: all 0.15s;
}
.btn:hover { background: #30363d; border-color: #58a6ff; color: #f0f6fc; }
.btn-primary { background: #238636; border-color: #238636; color: #fff; }
.btn-primary:hover { background: #2ea043; border-color: #2ea043; }
.toast {
  position: fixed; bottom: 24px; right: 24px; padding: 12px 20px;
  background: #238636; color: #fff; border-radius: 8px; font-size: 14px;
  opacity: 0; transition: opacity 0.3s; pointer-events: none; z-index: 100;
}
.toast.show { opacity: 1; }

/* === Footer === */
.footer { text-align: center; color: #484f58; font-size: 12px; padding: 24px 0; border-top: 1px solid #21262d; }

/* === Responsive === */
@media (max-width: 768px) {
  .charts-row { grid-template-columns: 1fr; }
  .combo-cards { grid-template-columns: 1fr; }
  .controls { flex-direction: column; align-items: stretch; }
  .results-count { margin-left: 0; }
  .header { flex-direction: column; align-items: flex-start; }
  .header-meta { text-align: left; }
  .detail-content dl { grid-template-columns: 1fr; }
}
@media (max-width: 480px) {
  .dashboard { grid-template-columns: 1fr 1fr; }
  .donut-container { flex-direction: column; }
  td, th { padding: 8px 6px; font-size: 12px; }
  .bar-label { width: 80px; }
}
"""


def _build_html_skeleton(scan_metadata):
    """Return the HTML body structure."""
    meta = scan_metadata or {}
    cluster = meta.get('cluster_name', 'Unknown Cluster')
    region = meta.get('region', '')
    profile = meta.get('profile', '')
    scan_time = meta.get('scan_time', '')

    meta_parts = []
    if region:
        meta_parts.append(f'<span>Region: {region}</span>')
    if profile:
        meta_parts.append(f'<span>Profile: {profile}</span>')
    if scan_time:
        meta_parts.append(f'<span>Scanned: {scan_time}</span>')

    return f"""
<div class="container">
  <!-- Header -->
  <div class="header">
    <h1>EKS Scout &mdash; {_escape_html(cluster)}</h1>
    <div class="header-meta">
      {''.join(meta_parts)}
    </div>
  </div>

  <!-- Dashboard Metrics -->
  <div class="dashboard" id="dashboard"></div>

  <!-- Charts -->
  <div class="charts-row">
    <div class="chart-card">
      <h3>Severity Distribution</h3>
      <div class="donut-container" id="severity-chart"></div>
    </div>
    <div class="chart-card">
      <h3>Category Breakdown</h3>
      <div class="bar-chart" id="category-chart"></div>
    </div>
  </div>

  <!-- Export Bar -->
  <div class="export-bar">
    <button class="btn btn-primary" onclick="downloadCSV()">Download CSV</button>
    <button class="btn" onclick="copyJSON()">Copy JSON</button>
  </div>

  <!-- Controls -->
  <div class="controls">
    <input type="text" class="search-box" id="search" placeholder="Search findings...">
    <div class="filter-group" id="severity-filters">
      <label>Severity:</label>
    </div>
    <div class="filter-group">
      <label>Namespace:</label>
      <select class="filter-select" id="ns-filter"><option value="">All</option></select>
    </div>
    <div class="filter-group">
      <label>Asset:</label>
      <select class="filter-select" id="asset-filter"><option value="">All</option></select>
    </div>
    <div class="filter-group" id="category-filters">
      <label>Category:</label>
    </div>
    <span class="results-count" id="results-count"></span>
  </div>

  <!-- Findings Table -->
  <div class="table-container">
    <table>
      <thead>
        <tr>
          <th data-col="severity">Severity <span class="sort-arrow"></span></th>
          <th data-col="type">Finding <span class="sort-arrow"></span></th>
          <th data-col="namespace">Namespace <span class="sort-arrow"></span></th>
          <th data-col="name">Resource <span class="sort-arrow"></span></th>
          <th data-col="asset_type">Asset Type <span class="sort-arrow"></span></th>
        </tr>
      </thead>
      <tbody id="findings-body"></tbody>
    </table>
  </div>

  <!-- High-Risk Combinations -->
  <div id="combos-section" style="display:none;">
    <h2 class="section-title">High-Risk Combinations</h2>
    <div class="combo-cards" id="combo-cards"></div>
  </div>

  <div class="footer">
    Generated by EKS Scout &bull; <span id="gen-time"></span>
  </div>
</div>
<div class="toast" id="toast"></div>
"""


def _escape_html(text):
    """Escape HTML special characters."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _build_javascript():
    """Return all client-side interactivity logic."""
    return r"""
(function() {
  'use strict';

  var data = REPORT_DATA;
  var findings = data.findings || [];
  var combos = data.combos || [];

  var SEV_RANK = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4 };
  var SEV_COLORS = {
    'Critical': '#f85149', 'High': '#f0883e', 'Medium': '#d29922',
    'Low': '#58a6ff', 'Informational': '#8b949e'
  };
  var SEV_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Informational'];
  var SEV_CSS = {
    'Critical': 'sev-critical', 'High': 'sev-high', 'Medium': 'sev-medium',
    'Low': 'sev-low', 'Informational': 'sev-info'
  };

  // State
  var activeFilters = { severities: new Set(), namespace: '', asset: '', category: '', search: '' };
  var sortCol = 'severity';
  var sortAsc = true;
  var filtered = findings.slice();
  var expandedRow = null;
  var debounceTimer = null;

  // --- Helpers ---
  function esc(text) {
    var d = document.createElement('div');
    d.textContent = text || '';
    return d.innerHTML;
  }
  function setText(el, text) { el.textContent = text; }
  function sevClass(sev) { return SEV_CSS[sev] || 'sev-info'; }

  function getCategory(checkId) {
    if (!checkId) return 'Other';
    var parts = checkId.split('.');
    if (parts.length < 2) return checkId;
    var prefix = parts[0] + '.' + parts[1];
    var MAP = {
      'k8s.pods': 'Pod Security', 'k8s.rbac': 'RBAC', 'k8s.netpol': 'Network Policy',
      'k8s.services': 'Services', 'k8s.psa': 'Pod Security Admission',
      'aws.cluster': 'EKS Cluster', 'aws.nodegroups': 'Node Groups',
      'aws.iam': 'IAM', 'aws.sg': 'Security Groups', 'aws.guardduty': 'GuardDuty'
    };
    return MAP[prefix] || prefix;
  }

  // --- Dashboard ---
  function renderDashboard() {
    var sevCounts = {};
    SEV_ORDER.forEach(function(s) { sevCounts[s] = 0; });
    findings.forEach(function(f) { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });

    var dash = document.getElementById('dashboard');
    var cards = [
      { value: findings.length, label: 'Total Findings', color: '#f0f6fc' },
      { value: sevCounts['Critical'] || 0, label: 'Critical', color: SEV_COLORS['Critical'] },
      { value: sevCounts['High'] || 0, label: 'High', color: SEV_COLORS['High'] },
      { value: combos.length, label: 'Attack Chains', color: '#d2a8ff' }
    ];
    dash.innerHTML = cards.map(function(c) {
      return '<div class="metric-card"><div class="value" style="color:' + c.color + '">' +
        c.value + '</div><div class="label">' + c.label + '</div></div>';
    }).join('');
  }

  function renderSeverityChart() {
    var container = document.getElementById('severity-chart');
    var sevCounts = {};
    var total = 0;
    SEV_ORDER.forEach(function(s) { sevCounts[s] = 0; });
    findings.forEach(function(f) { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; total++; });
    if (total === 0) { container.innerHTML = '<span style="color:#8b949e">No findings</span>'; return; }

    var gradParts = [];
    var cumPct = 0;
    SEV_ORDER.forEach(function(s) {
      var pct = (sevCounts[s] / total) * 100;
      if (pct > 0) {
        gradParts.push(SEV_COLORS[s] + ' ' + cumPct.toFixed(2) + '% ' + (cumPct + pct).toFixed(2) + '%');
        cumPct += pct;
      }
    });
    var gradient = 'conic-gradient(' + gradParts.join(', ') + ')';

    var legendHtml = SEV_ORDER.filter(function(s) { return sevCounts[s] > 0; }).map(function(s) {
      return '<div class="legend-item"><span class="legend-dot" style="background:' +
        SEV_COLORS[s] + '"></span>' + s + ': ' + sevCounts[s] + '</div>';
    }).join('');

    container.innerHTML =
      '<div class="donut" style="background:' + gradient + '"><div class="donut-hole">' + total + '</div></div>' +
      '<div class="legend">' + legendHtml + '</div>';
  }

  function renderCategoryChart() {
    var container = document.getElementById('category-chart');
    var cats = {};
    findings.forEach(function(f) {
      var cat = getCategory(f.check_id);
      cats[cat] = (cats[cat] || 0) + 1;
    });
    var entries = Object.keys(cats).map(function(k) { return { name: k, count: cats[k] }; });
    entries.sort(function(a, b) { return b.count - a.count; });
    var maxCount = entries.length > 0 ? entries[0].count : 1;
    var colors = ['#58a6ff', '#d2a8ff', '#7ee787', '#f0883e', '#f85149', '#d29922', '#79c0ff', '#a5d6ff'];

    container.innerHTML = entries.slice(0, 10).map(function(e, i) {
      var pct = (e.count / maxCount * 100).toFixed(1);
      var color = colors[i % colors.length];
      return '<div class="bar-row"><span class="bar-label">' + esc(e.name) +
        '</span><div class="bar-track"><div class="bar-fill" style="width:' + pct +
        '%;background:' + color + '"></div></div><span class="bar-count">' + e.count + '</span></div>';
    }).join('');
  }

  // --- Filters ---
  function buildFilterControls() {
    // Severity chips
    var sevContainer = document.getElementById('severity-filters');
    SEV_ORDER.forEach(function(s) {
      var chip = document.createElement('span');
      chip.className = 'chip sev-' + s.toLowerCase();
      setText(chip, s);
      chip.addEventListener('click', function() {
        if (activeFilters.severities.has(s)) { activeFilters.severities.delete(s); chip.classList.remove('active'); }
        else { activeFilters.severities.add(s); chip.classList.add('active'); }
        applyFilters();
      });
      sevContainer.appendChild(chip);
    });

    // Namespace dropdown
    var namespaces = new Set();
    findings.forEach(function(f) { if (f.namespace) namespaces.add(f.namespace); });
    var nsSelect = document.getElementById('ns-filter');
    Array.from(namespaces).sort().forEach(function(ns) {
      var opt = document.createElement('option');
      opt.value = ns;
      setText(opt, ns);
      nsSelect.appendChild(opt);
    });
    nsSelect.addEventListener('change', function() { activeFilters.namespace = this.value; applyFilters(); });

    // Asset type dropdown
    var assets = new Set();
    findings.forEach(function(f) { if (f.asset_type) assets.add(f.asset_type); });
    var assetSelect = document.getElementById('asset-filter');
    Array.from(assets).sort().forEach(function(a) {
      var opt = document.createElement('option');
      opt.value = a;
      setText(opt, a);
      assetSelect.appendChild(opt);
    });
    assetSelect.addEventListener('change', function() { activeFilters.asset = this.value; applyFilters(); });

    // Category chips
    var categories = new Set();
    findings.forEach(function(f) { categories.add(getCategory(f.check_id)); });
    var catContainer = document.getElementById('category-filters');
    Array.from(categories).sort().forEach(function(cat) {
      var chip = document.createElement('span');
      chip.className = 'chip';
      setText(chip, cat);
      chip.addEventListener('click', function() {
        if (activeFilters.category === cat) { activeFilters.category = ''; chip.classList.remove('active'); }
        else {
          catContainer.querySelectorAll('.chip').forEach(function(c) { c.classList.remove('active'); });
          activeFilters.category = cat; chip.classList.add('active');
        }
        applyFilters();
      });
      catContainer.appendChild(chip);
    });

    // Search
    document.getElementById('search').addEventListener('input', function() {
      var val = this.value;
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(function() { activeFilters.search = val.toLowerCase(); applyFilters(); }, 300);
    });
  }

  function applyFilters() {
    filtered = findings.filter(function(f) {
      if (activeFilters.severities.size > 0 && !activeFilters.severities.has(f.severity)) return false;
      if (activeFilters.namespace && f.namespace !== activeFilters.namespace) return false;
      if (activeFilters.asset && f.asset_type !== activeFilters.asset) return false;
      if (activeFilters.category && getCategory(f.check_id) !== activeFilters.category) return false;
      if (activeFilters.search) {
        var q = activeFilters.search;
        var hay = [f.type, f.namespace, f.name, f.details, f.recommendation, f.reference].join(' ').toLowerCase();
        if (hay.indexOf(q) === -1) return false;
      }
      return true;
    });
    sortFindings();
    renderTable();
    updateCount();
  }

  function updateCount() {
    setText(document.getElementById('results-count'),
      'Showing ' + filtered.length + ' of ' + findings.length + ' findings');
  }

  // --- Sorting ---
  function sortFindings() {
    filtered.sort(function(a, b) {
      var va, vb;
      if (sortCol === 'severity') {
        va = SEV_RANK[a.severity] !== undefined ? SEV_RANK[a.severity] : 99;
        vb = SEV_RANK[b.severity] !== undefined ? SEV_RANK[b.severity] : 99;
      } else {
        va = (a[sortCol] || '').toLowerCase();
        vb = (b[sortCol] || '').toLowerCase();
      }
      if (va < vb) return sortAsc ? -1 : 1;
      if (va > vb) return sortAsc ? 1 : -1;
      return 0;
    });
  }

  function setupSorting() {
    document.querySelectorAll('th[data-col]').forEach(function(th) {
      th.addEventListener('click', function() {
        var col = this.getAttribute('data-col');
        if (sortCol === col) { sortAsc = !sortAsc; }
        else { sortCol = col; sortAsc = true; }
        // Update arrows
        document.querySelectorAll('th[data-col]').forEach(function(h) {
          h.querySelector('.sort-arrow').textContent = '';
        });
        this.querySelector('.sort-arrow').textContent = sortAsc ? '\u25B2' : '\u25BC';
        sortFindings();
        renderTable();
      });
    });
    // Initial arrow
    var initialTh = document.querySelector('th[data-col="severity"]');
    if (initialTh) initialTh.querySelector('.sort-arrow').textContent = '\u25B2';
  }

  // --- Table rendering ---
  function renderTable() {
    var tbody = document.getElementById('findings-body');
    expandedRow = null;
    tbody.innerHTML = '';
    filtered.forEach(function(f, idx) {
      var tr = document.createElement('tr');
      tr.setAttribute('data-idx', idx);

      var tdSev = document.createElement('td');
      tdSev.innerHTML = '<span class="sev-badge ' + sevClass(f.severity) + '">' + esc(f.severity) + '</span>';
      tr.appendChild(tdSev);

      var tdType = document.createElement('td');
      setText(tdType, f.type || '');
      tr.appendChild(tdType);

      var tdNs = document.createElement('td');
      setText(tdNs, f.namespace || '');
      tr.appendChild(tdNs);

      var tdName = document.createElement('td');
      setText(tdName, f.name || '');
      tr.appendChild(tdName);

      var tdAsset = document.createElement('td');
      setText(tdAsset, f.asset_type || '');
      tr.appendChild(tdAsset);

      tr.style.cursor = 'pointer';
      tr.addEventListener('click', function() { toggleDetail(this, f); });
      tbody.appendChild(tr);
    });
  }

  function toggleDetail(tr, f) {
    var next = tr.nextElementSibling;
    if (next && next.classList.contains('detail-row')) {
      next.remove();
      tr.classList.remove('expanded');
      expandedRow = null;
      return;
    }
    // Collapse any other expanded row
    if (expandedRow) {
      var prev = expandedRow.nextElementSibling;
      if (prev && prev.classList.contains('detail-row')) prev.remove();
      expandedRow.classList.remove('expanded');
    }
    tr.classList.add('expanded');
    expandedRow = tr;

    var detailTr = document.createElement('tr');
    detailTr.className = 'detail-row';
    var detailTd = document.createElement('td');
    detailTd.colSpan = 5;

    var content = document.createElement('div');
    content.className = 'detail-content';
    var dl = document.createElement('dl');

    var fields = [
      ['Check ID', f.check_id],
      ['Details', f.details],
      ['Recommendation', f.recommendation],
      ['Reference', f.reference],
      ['Status', f.status]
    ];
    fields.forEach(function(pair) {
      if (pair[1]) {
        var dt = document.createElement('dt');
        setText(dt, pair[0]);
        var dd = document.createElement('dd');
        if (pair[0] === 'Reference' && pair[1].match(/^https?:\/\//)) {
          var a = document.createElement('a');
          a.href = pair[1];
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          setText(a, pair[1]);
          dd.appendChild(a);
        } else {
          setText(dd, pair[1]);
        }
        dl.appendChild(dt);
        dl.appendChild(dd);
      }
    });

    content.appendChild(dl);
    detailTd.appendChild(content);
    detailTr.appendChild(detailTd);
    tr.parentNode.insertBefore(detailTr, tr.nextSibling);
  }

  // --- Combos ---
  function renderCombos() {
    if (!combos || combos.length === 0) return;
    document.getElementById('combos-section').style.display = '';
    var container = document.getElementById('combo-cards');
    container.innerHTML = '';

    combos.forEach(function(combo) {
      var card = document.createElement('div');
      card.className = 'combo-card';

      var header = document.createElement('div');
      header.className = 'combo-card-header';
      var title = document.createElement('span');
      title.className = 'combo-card-title';
      setText(title, combo.title);
      var badge = document.createElement('span');
      badge.className = 'sev-badge ' + sevClass(combo.risk_level);
      setText(badge, combo.risk_level);
      header.appendChild(title);
      header.appendChild(badge);
      card.appendChild(header);

      var wk = document.createElement('div');
      wk.className = 'combo-workload';
      setText(wk, combo.workload_key);
      card.appendChild(wk);

      var impact = document.createElement('div');
      impact.className = 'combo-impact';
      setText(impact, combo.impact);
      card.appendChild(impact);

      // matched finding types badges
      var types = document.createElement('div');
      types.className = 'combo-types';
      (combo.matched_finding_types || []).forEach(function(t) {
        var b = document.createElement('span');
        b.className = 'combo-type-badge';
        setText(b, t);
        types.appendChild(b);
      });
      card.appendChild(types);

      // expandable detail with contributing findings
      var detail = document.createElement('div');
      detail.className = 'combo-detail';
      var cfs = combo.contributing_findings || [];
      if (cfs.length > 0) {
        var tbl = document.createElement('table');
        tbl.className = 'mini-table';
        tbl.innerHTML = '<thead><tr><th>Severity</th><th>Finding</th><th>Resource</th></tr></thead>';
        var tBody = document.createElement('tbody');
        cfs.forEach(function(cf) {
          var row = document.createElement('tr');
          var c1 = document.createElement('td');
          c1.innerHTML = '<span class="sev-badge ' + sevClass(cf.severity) + '">' + esc(cf.severity) + '</span>';
          var c2 = document.createElement('td');
          setText(c2, cf.type || '');
          var c3 = document.createElement('td');
          setText(c3, (cf.namespace || '') + '/' + (cf.name || ''));
          row.appendChild(c1); row.appendChild(c2); row.appendChild(c3);
          tBody.appendChild(row);
        });
        tbl.appendChild(tBody);
        detail.appendChild(tbl);
      }
      card.appendChild(detail);

      card.addEventListener('click', function() { card.classList.toggle('expanded'); });
      container.appendChild(card);
    });
  }

  // --- Export ---
  window.downloadCSV = function() {
    var headers = ['Severity', 'Finding', 'Namespace', 'Resource', 'Asset Type', 'Details', 'Recommendation', 'Reference'];
    var rows = [headers.join(',')];
    filtered.forEach(function(f) {
      rows.push([f.severity, f.type, f.namespace, f.name, f.asset_type, f.details, f.recommendation, f.reference]
        .map(function(v) { return '"' + String(v || '').replace(/"/g, '""') + '"'; }).join(','));
    });
    var blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = 'eks_scout_filtered.csv'; a.click();
    URL.revokeObjectURL(url);
    showToast('CSV downloaded (' + filtered.length + ' findings)');
  };

  window.copyJSON = function() {
    var text = JSON.stringify(filtered, null, 2);
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(function() { showToast('JSON copied to clipboard'); });
    } else {
      // fallback
      var ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      document.execCommand('copy'); document.body.removeChild(ta);
      showToast('JSON copied to clipboard');
    }
  };

  function showToast(msg) {
    var t = document.getElementById('toast');
    setText(t, msg);
    t.classList.add('show');
    setTimeout(function() { t.classList.remove('show'); }, 2500);
  }

  // --- Init ---
  document.getElementById('gen-time').textContent = data.generated_at || '';
  renderDashboard();
  renderSeverityChart();
  renderCategoryChart();
  buildFilterControls();
  applyFilters();
  setupSorting();
  renderCombos();
})();
"""
