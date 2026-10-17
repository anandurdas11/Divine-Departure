"""
report.py

Renders all collected findings (source-level + native-level) into a single,
self-contained, executive-grade cybersecurity dashboard HTML file.
Features:
- Professional Dark / Light mode toggle with persistent preference
- Executive KPI summary HUD (Total Findings, Risk Posture, Confidence breakdown, Defense Vectors)
- Interactive category summary cards with smooth scroll navigation
- Real-time live search & multi-facet filtering (by signature, file, snippet, confidence)
- 1-click clipboard copy for code snippets, file paths, and executive summary
- Interactive D3 Security Mind-Map with side-drawer Frida hook generator
- High-contrast, clean printable stylesheet for PDF exports and client deliverables
"""

import html
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

CATEGORY_LABELS = {
    "ROOT_DETECTION": "Root Detection",
    "INTEGRITY_CHECK": "Integrity / Attestation Check",
    "ANTI_DEBUG": "Anti-Debug",
    "ANTI_HOOK": "Anti-Hook / Anti-Frida",
    "EMULATOR_DETECT": "Emulator Detection",
    "MDM_CHECK": "MDM / Device-Management Detection",
    "SSL_PINNING": "SSL / Certificate Pinning",
    "RASP_DETECTION": "RASP / App Shielding",
    "ENFORCEMENT": "Enforcement Chokepoints",
    "HARDCODED_SECRETS": "Hardcoded Secrets & API Keys",
}

IOS_CATEGORY_LABELS = {
    "ROOT_DETECTION": "Jailbreak Detection",
    "INTEGRITY_CHECK": "Integrity / Attestation Check",
    "ANTI_DEBUG": "Anti-Debug",
    "ANTI_HOOK": "Anti-Hook / Anti-Frida",
    "EMULATOR_DETECT": "Simulator Detection",
    "MDM_CHECK": "MDM / Device-Management Detection",
    "SSL_PINNING": "SSL / Certificate Pinning",
    "RASP_DETECTION": "RASP / App Shielding",
    "ENFORCEMENT": "Enforcement Chokepoints",
    "HARDCODED_SECRETS": "Hardcoded Secrets & API Keys",
}

ALL_CATEGORIES = [
    "ROOT_DETECTION", "INTEGRITY_CHECK", "ANTI_DEBUG",
    "ANTI_HOOK", "EMULATOR_DETECT", "MDM_CHECK", "SSL_PINNING", "RASP_DETECTION",
    "ENFORCEMENT", "HARDCODED_SECRETS",
]

CATEGORY_COLOR = {
    "ROOT_DETECTION":  "#ef4444",
    "INTEGRITY_CHECK": "#a855f7",
    "ANTI_DEBUG":      "#3b82f6",
    "ANTI_HOOK":       "#14b8a6",
    "EMULATOR_DETECT": "#f59e0b",
    "MDM_CHECK":       "#64748b",
    "SSL_PINNING":     "#ec4899",
    "RASP_DETECTION":  "#f43f5e",
    "ENFORCEMENT":     "#dc2626",
    "HARDCODED_SECRETS": "#eab308",
}

CONFIDENCE_COLOR = {
    "high": "#ef4444",
    "medium": "#f59e0b",
    "low": "#64748b",
}

CSS = """
:root {
  --bg: #090d16;
  --bg-gradient: radial-gradient(circle at 50% 0%, #151d30 0%, #090d16 85%);
  --panel: #0f172a;
  --panel-hover: #162035;
  --card-bg: #111a2e;
  --card-border: #1e293b;
  --card-hover-border: #334155;
  --line: #1e293b;
  --ink: #f1f5f9;
  --ink-secondary: #cbd5e1;
  --muted: #94a3b8;
  --dim: #64748b;
  --code-bg: #030712;
  --code-ink: #38bdf8;
  --shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.45);
  --shadow-lg: 0 10px 30px -5px rgba(0, 0, 0, 0.6);
  --accent: #7c5cff;
  --accent-gradient: linear-gradient(135deg, #7c5cff 0%, #a855f7 50%, #22d3ee 100%);
  --danger: #ef4444;
  --danger-bg: rgba(239, 68, 68, 0.12);
  --warning: #f59e0b;
  --warning-bg: rgba(245, 158, 11, 0.12);
  --success: #10b981;
  --success-bg: rgba(16, 185, 129, 0.12);
  --info: #3b82f6;
  --th-bg: #0d1526;
  --tr-alt: #0b1120;
  --tr-hover: #162238;
}

[data-theme="light"] {
  --bg: #f8fafc;
  --bg-gradient: radial-gradient(circle at 50% 0%, #ffffff 0%, #f1f5f9 85%);
  --panel: #ffffff;
  --panel-hover: #f8fafc;
  --card-bg: #ffffff;
  --card-border: #e2e8f0;
  --card-hover-border: #cbd5e1;
  --line: #e2e8f0;
  --ink: #0f172a;
  --ink-secondary: #334155;
  --muted: #64748b;
  --dim: #94a3b8;
  --code-bg: #f1f5f9;
  --code-ink: #0369a1;
  --shadow: 0 2px 10px rgba(15, 23, 42, 0.05), 0 10px 25px rgba(15, 23, 42, 0.04);
  --shadow-lg: 0 10px 30px rgba(15, 23, 42, 0.08);
  --accent: #6d28d9;
  --accent-gradient: linear-gradient(135deg, #6d28d9 0%, #7c3aed 50%, #0284c7 100%);
  --danger: #dc2626;
  --danger-bg: rgba(220, 38, 38, 0.08);
  --warning: #d97706;
  --warning-bg: rgba(217, 119, 6, 0.08);
  --success: #059669;
  --success-bg: rgba(5, 150, 105, 0.08);
  --info: #2563eb;
  --th-bg: #f8fafc;
  --tr-alt: #fcfdfe;
  --tr-hover: #f1f5f9;
}

* { box-sizing: border-box; }
body {
  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  margin: 0;
  background: var(--bg);
  background-image: var(--bg-gradient);
  color: var(--ink);
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
  min-height: 100vh;
}

/* ---- Modern HUD Header ---- */
.hud-header {
  background: rgba(15, 23, 42, 0.85);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-bottom: 1px solid var(--line);
  padding: 22px 36px;
  position: sticky;
  top: 0;
  z-index: 1000;
  transition: background .2s, border-color .2s;
}
[data-theme="light"] .hud-header {
  background: rgba(255, 255, 255, 0.88);
}
.hud-inner {
  max-width: 1400px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 18px;
}
.brand-group {
  display: flex;
  align-items: center;
  gap: 16px;
}
.brand-logo {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  background: linear-gradient(135deg, #1e1b4b, #311042);
  border: 1px solid #7c5cff;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 0 0 20px rgba(124, 92, 255, 0.35);
  flex-shrink: 0;
}
.brand-titles h1 {
  margin: 0;
  font-size: 19px;
  font-weight: 800;
  letter-spacing: .02em;
  display: flex;
  align-items: center;
  gap: 10px;
}
.brand-titles .brand-text {
  background: var(--accent-gradient);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  font-weight: 900;
  letter-spacing: 0.05em;
}
.hud-meta-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 4px;
  font-size: 12px;
  color: var(--muted);
  flex-wrap: wrap;
}
.meta-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--code-bg);
  border: 1px solid var(--line);
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 11.5px;
  color: var(--ink-secondary);
}
.meta-chip code {
  color: var(--accent);
  font-weight: 600;
}
.hud-controls {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

/* Header utility buttons */
.hud-btn {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  background: var(--card-bg);
  color: var(--ink-secondary);
  border: 1px solid var(--card-border);
  padding: 8px 14px;
  border-radius: 9px;
  font-size: 12.5px;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  transition: all .15s ease;
  box-shadow: var(--shadow);
}
.hud-btn:hover {
  background: var(--panel-hover);
  border-color: var(--accent);
  color: var(--ink);
  transform: translateY(-1px);
}
.hud-btn.primary {
  background: var(--accent-gradient);
  color: #ffffff;
  border: none;
  box-shadow: 0 4px 15px rgba(124, 92, 255, 0.4);
}
.hud-btn.primary:hover {
  filter: brightness(1.1);
}

/* ---- Main Container ---- */
.container {
  padding: 32px 36px 60px;
  max-width: 1400px;
  margin: 0 auto;
}

/* ---- Action Bar ---- */
.actionbar {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 28px;
}
.btn {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  text-decoration: none;
  background: var(--panel);
  color: var(--ink-secondary);
  border: 1px solid var(--card-border);
  border-radius: 9px;
  padding: 9px 16px;
  font-size: 13px;
  font-weight: 600;
  box-shadow: var(--shadow);
  transition: all .15s ease;
}
.btn:hover {
  transform: translateY(-2px);
  border-color: var(--accent);
  color: var(--ink);
  box-shadow: var(--shadow-lg);
}
.btn.primary {
  background: var(--accent-gradient);
  color: #fff;
  border-color: transparent;
}
.btn .i { font-size: 14px; line-height: 1; }

/* ---- Executive KPI Dashboard ---- */
.kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.kpi-card {
  background: var(--panel);
  border: 1px solid var(--card-border);
  border-radius: 14px;
  padding: 18px 22px;
  box-shadow: var(--shadow);
  position: relative;
  overflow: hidden;
  transition: transform .15s ease, border-color .15s ease;
}
.kpi-card:hover {
  transform: translateY(-2px);
  border-color: var(--card-hover-border);
}
.kpi-card::before {
  content: "";
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 3px;
  background: var(--kpi-accent, var(--accent));
}
.kpi-label {
  font-size: 11.5px;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  font-weight: 700;
  margin-bottom: 6px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.kpi-val {
  font-size: 32px;
  font-weight: 800;
  letter-spacing: -.02em;
  color: var(--ink);
  line-height: 1;
}
.kpi-sub {
  margin-top: 8px;
  font-size: 12px;
  color: var(--dim);
}

/* Posture Progress Bar */
.posture-bar-wrapper {
  background: var(--panel);
  border: 1px solid var(--card-border);
  border-radius: 14px;
  padding: 16px 20px;
  box-shadow: var(--shadow);
  margin-bottom: 28px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.posture-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 12.5px;
  font-weight: 600;
  color: var(--ink-secondary);
}
.posture-track {
  height: 10px;
  background: var(--code-bg);
  border-radius: 999px;
  overflow: hidden;
  display: flex;
  gap: 2px;
}
.posture-seg {
  height: 100%;
  transition: width .4s ease;
}

/* ---- Category Summary Cards ---- */
.summary-title {
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--muted);
  font-weight: 800;
  margin-bottom: 12px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.summary {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 14px;
  margin-bottom: 32px;
}
.card {
  background: var(--panel);
  border: 1px solid var(--card-border);
  border-radius: 12px;
  padding: 14px 18px;
  box-shadow: var(--shadow);
  display: block;
  text-decoration: none;
  color: inherit;
  position: relative;
  transition: all .15s ease;
}
.card:hover {
  transform: translateY(-2px);
  border-color: var(--accent);
  box-shadow: var(--shadow-lg);
}
.card .card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}
.card .dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  display: inline-block;
}
.card .num {
  font-size: 26px;
  font-weight: 800;
  letter-spacing: -.02em;
  line-height: 1.1;
}
.card .label {
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
  letter-spacing: .01em;
  transition: color .15s ease;
}
.card:hover .label {
  color: var(--ink);
}

/* ---- Live Interactive Search & Filter Controls ---- */
.filter-toolbar {
  background: var(--panel);
  border: 1px solid var(--card-border);
  border-radius: 14px;
  padding: 16px 20px;
  box-shadow: var(--shadow);
  margin-bottom: 30px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.filter-row-primary {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 12px;
  justify-content: space-between;
}
.search-wrapper {
  position: relative;
  flex: 1;
  min-width: 280px;
  max-width: 600px;
}
.search-wrapper input {
  width: 100%;
  background: var(--code-bg);
  border: 1px solid var(--card-border);
  border-radius: 9px;
  padding: 10px 14px 10px 38px;
  color: var(--ink);
  font-size: 13.5px;
  outline: none;
  transition: border-color .15s ease, box-shadow .15s ease;
}
.search-wrapper input:focus {
  border-color: var(--accent);
  box-shadow: 0 0 0 3px rgba(124, 92, 255, 0.2);
}
.search-wrapper .search-icon {
  position: absolute;
  left: 13px;
  top: 50%;
  transform: translateY(-50%);
  color: var(--dim);
  pointer-events: none;
}
.filter-pills-row {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.filter-pill {
  background: var(--code-bg);
  border: 1px solid var(--card-border);
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
  padding: 5px 12px;
  border-radius: 999px;
  cursor: pointer;
  transition: all .15s ease;
}
.filter-pill:hover, .filter-pill.active {
  background: var(--accent);
  border-color: var(--accent);
  color: #fff;
}
.filter-stats {
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
}

/* ---- Headings & Content Sections ---- */
.category-section {
  margin-bottom: 44px;
  scroll-margin-top: 100px;
}
h2 {
  font-size: 18px;
  margin: 0 0 16px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--line);
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-weight: 700;
}
.h2-left {
  display: flex;
  align-items: center;
  gap: 10px;
}
h2 .dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  flex-shrink: 0;
}
.h2-top-link {
  font-size: 11px;
  color: var(--dim);
  text-decoration: none;
  font-weight: 600;
  border: 1px solid var(--line);
  padding: 3px 8px;
  border-radius: 6px;
  transition: all .15s;
}
.h2-top-link:hover {
  color: var(--accent);
  border-color: var(--accent);
}
h3 {
  font-size: 12.5px;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: var(--muted);
  margin: 20px 0 10px;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 8px;
}

/* ---- Polished Data Tables ---- */
.table-card {
  background: var(--panel);
  border: 1px solid var(--card-border);
  border-radius: 14px;
  overflow: hidden;
  box-shadow: var(--shadow);
  margin-bottom: 22px;
}
table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  text-align: left;
}
th {
  background: var(--th-bg);
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: .06em;
  font-weight: 700;
  padding: 12px 16px;
  border-bottom: 1px solid var(--line);
  white-space: nowrap;
}
td {
  padding: 12px 16px;
  border-bottom: 1px solid var(--line);
  font-size: 13px;
  vertical-align: middle;
  color: var(--ink-secondary);
}
tbody tr:last-child td {
  border-bottom: none;
}
tbody tr {
  transition: background .12s ease;
}
tbody tr:nth-child(even) {
  background: var(--tr-alt);
}
tbody tr:hover {
  background: var(--tr-hover);
}

code {
  background: var(--code-bg);
  color: var(--code-ink);
  padding: 2.5px 7px;
  border-radius: 6px;
  font-size: 12px;
  font-family: ui-monospace, "SF Mono", "Cascadia Code", Consolas, monospace;
  word-break: break-all;
  border: 1px solid rgba(255,255,255,0.05);
}
[data-theme="light"] code {
  border: 1px solid rgba(0,0,0,0.08);
}

.snippet-box {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 100%;
}
.snippet-text {
  max-width: 380px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
  vertical-align: middle;
}
.copy-inline-btn {
  background: transparent;
  border: none;
  color: var(--dim);
  cursor: pointer;
  padding: 2px 4px;
  border-radius: 4px;
  display: inline-flex;
  align-items: center;
  transition: color .12s, background .12s;
}
.copy-inline-btn:hover {
  color: var(--accent);
  background: var(--card-border);
}

/* Badges */
.badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: .04em;
  text-transform: uppercase;
  white-space: nowrap;
}
.badge-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
}
.badge-high {
  background: var(--danger-bg);
  color: var(--danger);
  border: 1px solid rgba(239, 68, 68, 0.3);
}
.badge-high .badge-dot { background: var(--danger); }
.badge-medium {
  background: var(--warning-bg);
  color: var(--warning);
  border: 1px solid rgba(245, 158, 11, 0.3);
}
.badge-medium .badge-dot { background: var(--warning); }
.badge-low {
  background: rgba(148, 163, 184, 0.12);
  color: var(--muted);
  border: 1px solid rgba(148, 163, 184, 0.3);
}
.badge-low .badge-dot { background: var(--muted); }

/* Empty State Card */
.empty-card {
  padding: 24px;
  text-align: center;
  color: var(--dim);
  font-size: 13px;
  font-style: normal;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 8px;
}
.empty-card svg {
  color: var(--dim);
  opacity: 0.6;
}

/* Warnings box */
.warnings {
  background: var(--warning-bg);
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 12px;
  padding: 16px 20px;
  margin-bottom: 28px;
  font-size: 13px;
  color: var(--ink);
}
.warnings strong {
  color: var(--warning);
}
.warnings ul { margin: 8px 0 0; padding-left: 20px; }
.warnings li { margin: 4px 0; }

footer {
  text-align: center;
  color: var(--dim);
  font-size: 12px;
  padding: 40px 20px;
  border-top: 1px solid var(--line);
  margin-top: 60px;
}

/* ---- Security Mind-Map ---- */
.mindmap {
  background: var(--panel);
  border: 1px solid var(--card-border);
  border-radius: 14px;
  box-shadow: var(--shadow);
  padding: 12px 14px;
  margin-bottom: 24px;
}
.mindmap details { border-radius: 8px; }
.mindmap > details { margin: 6px 2px; }
.mindmap summary {
  cursor: pointer;
  list-style: none;
  padding: 10px 14px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13.5px;
  user-select: none;
  transition: background .12s;
}
.mindmap summary::-webkit-details-marker { display: none; }
.mindmap summary:hover { background: var(--panel-hover); }
.mindmap summary .chev { transition: transform .15s ease; color: var(--dim); font-size: 11px; }
.mindmap details[open] > summary .chev { transform: rotate(90deg); }
.mm-cat > summary { font-weight: 700; }
.mm-pill {
  margin-left: auto;
  font-size: 11px;
  color: var(--muted);
  background: var(--code-bg);
  border: 1px solid var(--line);
  padding: 2px 9px;
  border-radius: 999px;
  font-weight: 600;
}
.mm-jump {
  font-size: 11px;
  font-weight: 600;
  color: var(--accent);
  text-decoration: none;
  margin-left: 12px;
  white-space: nowrap;
}
.mm-jump:hover { text-decoration: underline; }
.mm-class { margin: 4px 0 4px 24px; border-left: 2px solid var(--line); }
.mm-class > summary { font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 12px; color: var(--ink-secondary); }
.mm-methods { margin: 4px 0 10px 36px; display: flex; flex-direction: column; gap: 4px; }
.mm-method {
  font-family: ui-monospace, "SF Mono", Consolas, monospace;
  font-size: 12px;
  color: var(--ink-secondary);
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 3px 0;
}
.mm-method .cdot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.mm-method .src { color: var(--dim); font-size: 11px; margin-left: auto; }
.mm-hints { margin: 6px 0 12px 36px; font-size: 12px; color: var(--muted); }
.mm-hints li { margin: 3px 0; }
.mm-note { font-size: 12px; color: var(--dim); padding: 8px 14px; }

/* ---- D3 Mind Map Container & HUD ---- */
.mm-interactive-card {
  background: #090d16;
  border: 1px solid var(--card-border);
  border-radius: 14px;
  overflow: hidden;
  box-shadow: var(--shadow-lg);
  margin-bottom: 30px;
  position: relative;
}
.mm-toolbar {
  background: #0f172a;
  border-bottom: 1px solid #1e293b;
  padding: 12px 18px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.mm-search-box {
  position: relative;
  min-width: 260px;
  flex: 1;
  max-width: 420px;
}
.mm-search-box input {
  width: 100%;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 8px 12px 8px 34px;
  color: #f8fafc;
  font-size: 13px;
  outline: none;
  transition: border-color .15s;
}
.mm-search-box input:focus { border-color: #7c5cff; }
.mm-search-box .icon {
  position: absolute;
  left: 11px;
  top: 50%;
  transform: translateY(-50%);
  color: #64748b;
  font-size: 13px;
}
.mm-match-count {
  position: absolute;
  right: 12px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 11px;
  color: #94a3b8;
  font-weight: 600;
}
.mm-pills { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
.mm-pill-btn {
  background: #1e293b;
  border: 1px solid #334155;
  color: #94a3b8;
  font-size: 11px;
  font-weight: 600;
  padding: 4px 10px;
  border-radius: 999px;
  cursor: pointer;
  transition: all .15s;
}
.mm-pill-btn:hover, .mm-pill-btn.active {
  background: #7c5cff;
  border-color: #7c5cff;
  color: #fff;
}
.mm-actions { display: flex; gap: 6px; align-items: center; }
.mm-btn {
  background: #1e293b;
  border: 1px solid #334155;
  color: #cbd5e1;
  border-radius: 6px;
  padding: 6px 10px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  transition: background .12s;
}
.mm-btn:hover { background: #334155; color: #fff; }
.mm-viewport {
  position: relative;
  background: radial-gradient(circle at 50% 50%, #0d1527 0%, #090d16 100%);
  height: 650px;
  width: 100%;
  overflow: hidden;
}
.mm-viewport svg { width: 100%; height: 100%; display: block; }
.mm-node text {
  font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
  font-size: 12px;
  font-weight: 500;
  fill: #e2e8f0;
  cursor: pointer;
  user-select: none;
}
.mm-node circle { cursor: pointer; transition: r .2s, stroke-width .2s; }
.mm-link { fill: none; stroke: #334155; stroke-width: 1.5px; stroke-opacity: 0.65; }

/* Drawer */
.mm-drawer {
  position: absolute;
  top: 0; right: 0; bottom: 0;
  width: 400px;
  max-width: 90%;
  background: #0f172a;
  border-left: 1px solid #1e293b;
  box-shadow: -8px 0 25px rgba(0,0,0,0.5);
  transform: translateX(100%);
  transition: transform .28s cubic-bezier(0.16, 1, 0.3, 1);
  z-index: 50;
  display: flex;
  flex-direction: column;
}
.mm-drawer.open { transform: translateX(0); }
.mm-drawer-header {
  padding: 16px 20px;
  border-bottom: 1px solid #1e293b;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.mm-drawer-close {
  background: transparent;
  border: none;
  color: #94a3b8;
  font-size: 22px;
  cursor: pointer;
  line-height: 1;
}
.mm-drawer-close:hover { color: #fff; }
.mm-drawer-body {
  padding: 20px;
  overflow-y: auto;
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 16px;
  color: #cbd5e1;
  font-size: 13px;
}
.mm-drawer-field { display: flex; flex-direction: column; gap: 5px; }
.mm-drawer-label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: #64748b;
  font-weight: 700;
}
.mm-drawer-code {
  background: #020617;
  border: 1px solid #1e293b;
  border-radius: 8px;
  padding: 12px;
  font-family: ui-monospace, "SF Mono", Consolas, monospace;
  font-size: 12px;
  color: #38bdf8;
  position: relative;
  word-break: break-all;
  white-space: pre-wrap;
}
.mm-copy-btn {
  align-self: flex-start;
  background: #1e293b;
  border: 1px solid #334155;
  color: #e2e8f0;
  border-radius: 6px;
  padding: 6px 12px;
  font-size: 11.5px;
  font-weight: 600;
  cursor: pointer;
  margin-top: 4px;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  transition: all .12s;
}
.mm-copy-btn:hover { background: #334155; }
.mm-tooltip {
  position: absolute;
  display: none;
  background: rgba(15, 23, 42, 0.95);
  border: 1px solid #334155;
  color: #f8fafc;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 11.5px;
  pointer-events: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.5);
  z-index: 100;
  max-width: 280px;
  line-height: 1.4;
}

/* Intro overlay */
#dd-overlay {
  position: fixed;
  inset: 0;
  z-index: 9999;
  background: radial-gradient(ellipse at center, #1a0b2e 0%, #05030a 85%);
  display: flex;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  animation: dd-fadeout 0.6s ease-in forwards;
  animation-delay: 1.4s;
  pointer-events: none;
}
#dd-overlay .dd-title {
  font-size: 38px;
  font-weight: 900;
  letter-spacing: 0.15em;
  background: linear-gradient(90deg, #b388ff, #64ffda, #b388ff);
  background-size: 200% auto;
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  animation: dd-glow 1.5s ease-in-out infinite, dd-sheen 2.5s linear infinite;
}
#dd-overlay .dd-sub {
  margin-top: 10px;
  font-size: 12px;
  letter-spacing: 0.35em;
  color: #94a3b8;
  text-transform: uppercase;
}
@keyframes dd-glow {
  0%,100% { filter: drop-shadow(0 0 8px rgba(179,136,255,.5)); }
  50% { filter: drop-shadow(0 0 24px rgba(100,255,218,.75)); }
}
@keyframes dd-sheen { 0% { background-position: 0% center; } 100% { background-position: 200% center; } }
@keyframes dd-fadeout {
  from { opacity: 1; visibility: visible; }
  to { opacity: 0; visibility: hidden; }
}

/* Toast Notification */
#dd-toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  background: #10b981;
  color: #ffffff;
  padding: 10px 18px;
  border-radius: 8px;
  font-size: 13px;
  font-weight: 600;
  box-shadow: 0 4px 15px rgba(0,0,0,0.3);
  opacity: 0;
  transform: translateY(10px);
  transition: all .2s ease;
  z-index: 10000;
  pointer-events: none;
}
#dd-toast.show {
  opacity: 1;
  transform: translateY(0);
}

/* Print Optimization */
@media print {
  #dd-overlay, .hud-controls, .actionbar, .filter-toolbar, .mm-toolbar, .h2-top-link, .copy-inline-btn {
    display: none !important;
  }
  body {
    background: #ffffff !important;
    color: #000000 !important;
    font-size: 11pt !important;
  }
  .hud-header {
    position: static !important;
    background: none !important;
    border-bottom: 2px solid #000000 !important;
    padding: 10px 0 !important;
  }
  .brand-text {
    color: #000000 !important;
    -webkit-text-fill-color: #000000 !important;
  }
  .kpi-card, .table-card, .card {
    border: 1px solid #cccccc !important;
    box-shadow: none !important;
    page-break-inside: avoid;
  }
  table { border: 1px solid #dddddd !important; }
  th { background: #eeeeee !important; color: #000000 !important; }
  td { border-bottom: 1px solid #eeeeee !important; color: #000000 !important; }
  code { background: #f5f5f5 !important; color: #000000 !important; border: 1px solid #e0e0e0 !important; }
}
"""


def _esc(s):
    return html.escape(str(s))


def _badge(confidence):
    conf_str = str(confidence).lower()
    label = conf_str.upper()
    css_class = f"badge-{conf_str}" if conf_str in ("high", "medium", "low") else "badge-low"
    return (
        f'<span class="badge {css_class}">'
        f'<span class="badge-dot"></span>{_esc(label)}'
        f'</span>'
    )


def _copy_btn(text):
    safe_text = _esc(text).replace('"', '&quot;').replace("'", "&#39;")
    return (
        f'<button class="copy-inline-btn" title="Copy to clipboard" data-copy="{safe_text}" onclick="copyValue(this)">'
        f'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
        f'<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>'
        f'<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>'
        f'</svg>'
        f'</button>'
    )


def _empty_state(msg):
    return (
        f'<div class="table-card"><div class="empty-card">'
        f'<svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">'
        f'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>'
        f'</svg>'
        f'<div>{_esc(msg)}</div>'
        f'</div></div>'
    )


def _source_table(findings):
    if not findings:
        return _empty_state("No decompiled source findings in this category.")
    rows = []
    for f in findings:
        conf_lower = str(f.confidence).lower()
        search_blob = f"{f.file_path} {f.pattern_name} {f.description} {f.snippet}".lower()
        rows.append(
            f'<tr class="finding-row" data-category="{_esc(f.category)}" data-confidence="{_esc(conf_lower)}" data-search="{_esc(search_blob)}">'
            f'<td>{_badge(f.confidence)}</td>'
            f'<td>'
            f'<div class="snippet-box">'
            f'<code>{_esc(f.file_path)}:{f.line_number}</code>{_copy_btn(f"{f.file_path}:{f.line_number}")}'
            f'</div>'
            f'</td>'
            f'<td><strong style="color:var(--ink);">{_esc(f.pattern_name)}</strong></td>'
            f'<td>{_esc(f.description)}</td>'
            f'<td>'
            f'<div class="snippet-box">'
            f'<span class="snippet-text"><code>{_esc(f.snippet)}</code></span>{_copy_btn(f.snippet)}'
            f'</div>'
            f'</td></tr>'
        )
    return (
        '<div class="table-card"><table><thead><tr>'
        '<th>Confidence</th><th>File : Line</th><th>Signature</th><th>Description</th><th>Matched Line</th>'
        '</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>"
    )


def _native_string_table(findings):
    if not findings:
        return _empty_state("No native string findings in this category.")
    rows = []
    for f in findings:
        conf_lower = str(f.confidence).lower()
        so_name = Path(f.so_path).name
        search_blob = f"{so_name} {f.pattern_name} {f.description} {f.matched_string}".lower()
        rows.append(
            f'<tr class="finding-row" data-category="{_esc(f.category)}" data-confidence="{_esc(conf_lower)}" data-search="{_esc(search_blob)}">'
            f'<td>{_badge(f.confidence)}</td>'
            f'<td><div class="snippet-box"><code>{_esc(so_name)}</code>{_copy_btn(so_name)}</div></td>'
            f'<td><code>0x{f.file_offset:x}</code></td>'
            f'<td><strong style="color:var(--ink);">{_esc(f.pattern_name)}</strong></td>'
            f'<td>{_esc(f.description)}</td>'
            f'<td>'
            f'<div class="snippet-box">'
            f'<span class="snippet-text"><code>{_esc(f.matched_string)}</code></span>{_copy_btn(f.matched_string)}'
            f'</div>'
            f'</td></tr>'
        )
    return (
        '<div class="table-card"><table><thead><tr>'
        '<th>Confidence</th><th>Native Library</th><th>File Offset</th><th>Signature</th><th>Description</th><th>Matched String</th>'
        '</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>"
    )


def _native_callsite_table(findings):
    if not findings:
        return _empty_state("No native call-site findings in this category.")
    rows = []
    for f in findings:
        conf_lower = str(f.confidence).lower()
        so_name = Path(f.so_path).name
        search_blob = f"{so_name} {f.calling_function} {f.imported_symbol} {f.description}".lower()
        rows.append(
            f'<tr class="finding-row" data-category="{_esc(f.category)}" data-confidence="{_esc(conf_lower)}" data-search="{_esc(search_blob)}">'
            f'<td>{_badge(f.confidence)}</td>'
            f'<td><div class="snippet-box"><code>{_esc(so_name)}</code>{_copy_btn(so_name)}</div></td>'
            f'<td><code>{_esc(f.calling_function)}</code></td>'
            f'<td><code>0x{f.call_instruction_address:x}</code></td>'
            f'<td><strong style="color:var(--accent);">{_esc(f.imported_symbol)}()</strong></td>'
            f'<td>{_esc(f.description)}</td></tr>'
        )
    return (
        '<div class="table-card"><table><thead><tr>'
        '<th>Confidence</th><th>Library</th><th>Calling Function</th><th>Call Address</th><th>Target Import</th><th>Description</th>'
        '</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>"
    )


def _patch_section(patch_records):
    """Render the optional 'what --patch changed' section."""
    if patch_records is None:
        return ""
    if not patch_records:
        body = _empty_state("Patch mode was executed but no defensive checks were modified.")
    else:
        rows = []
        for r in patch_records:
            rows.append(
                f"<tr><td><strong>{_esc(r.get('category', ''))}</strong></td>"
                f"<td><code>{_esc(r.get('location', ''))}</code></td>"
                f"<td><span class=\"badge badge-high\"><span class=\"badge-dot\"></span>{_esc(r.get('action', ''))}</span></td>"
                f"<td>{_esc(r.get('detail', ''))}</td></tr>"
            )
        body = (
            '<div class="table-card"><table><thead><tr><th>Category</th><th>Location</th><th>Action</th>'
            '<th>Detail</th></tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
        )
    return (
        f'<div class="category-section">'
        f'<h2 id="patchlog"><div class="h2-left"><span class="dot" style="background:#ef4444"></span>'
        f'Binary &amp; Bytecode Neutralisation Log (Patched Checks)</div>'
        f'<a class="h2-top-link" href="#">&#8593; Top</a></h2>{body}</div>'
    )


def _action_bar(security_model, frida_json_name, frida_prompt_name, patched_apk_name, mindmap_json_name=None):
    btns = []
    if security_model is not None:
        btns.append('<a class="btn primary" href="#mindmap"><span class="i">&#129504;</span>Interactive Security Mind-Map</a>')
    mm_name = mindmap_json_name or (security_model and security_model.get("mindmap_json_name"))
    if mm_name:
        btns.append(f'<a class="btn" href="{_esc(mm_name)}" target="_blank">'
                    f'<span class="i">&#129504;</span>{_esc(mm_name)}</a>')
    if frida_json_name:
        btns.append(f'<a class="btn" href="{_esc(frida_json_name)}" target="_blank">'
                    f'<span class="i">&#128190;</span>security_model.json</a>')
    if frida_prompt_name:
        btns.append(f'<a class="btn" href="{_esc(frida_prompt_name)}" target="_blank">'
                    f'<span class="i">&#9889;</span>Frida Prompt &amp; Script</a>')
    if patched_apk_name:
        btns.append(f'<a class="btn" href="{_esc(patched_apk_name)}">'
                    f'<span class="i">&#128230;</span>Patched Package ({_esc(patched_apk_name)})</a>')
    if not btns:
        return ""
    return f'<div class="actionbar">{"".join(btns)}</div>'


def _mindmap_section(security_model):
    """Interactive D3 graphical mind map + inline collapsible accordion."""
    if security_model is None:
        return ""

    mindmap_data = security_model.get("mindmap_data")
    mm_json_name = security_model.get("mindmap_json_name", "security_mind_map.json")
    mechs = security_model.get("defense_mechanisms", [])

    head = (
        '<div class="category-section" id="mindmap">'
        '<h2><div class="h2-left"><span class="dot" style="background:var(--accent)"></span>'
        'Interactive Security Mind-Map &mdash; Attack Surface &amp; Defense Tree</div>'
        '<a class="h2-top-link" href="#">&#8593; Top</a></h2>'
        f'<div class="mm-note" style="margin-bottom:12px;">Click any node to inspect details and copy Frida hooks in the slide-out drawer. '
        f'Full structured models: <a href="{_esc(mm_json_name)}" target="_blank" style="color:var(--accent); font-weight:600;"><code>{_esc(mm_json_name)}</code></a> '
        f'&nbsp;|&nbsp; <code>security_model.json</code>.</div>'
    )

    # Textual Accordion fallback / toggleable view
    blocks = []
    for m in mechs:
        cat = m.get("category", "")
        color = CATEGORY_COLOR.get(cat, "#64748b")
        label = m.get("label", cat)
        cands = m.get("hook_candidates", [])
        omitted = m.get("hook_candidates_omitted", 0)

        class_nodes = []
        for c in cands:
            fqcn = c.get("java_class", "?")
            method = c.get("method_hint", "")
            conf = c.get("confidence", "low")
            cdot = CONFIDENCE_COLOR.get(conf, "#94a3b8")
            src = c.get("source", "")
            sig = c.get("signature", "")
            method_txt = f"{method}()" if method else f"&lt;{_esc(sig)}&gt;"
            class_nodes.append(
                '<details class="mm-class"><summary><span class="chev">&#9654;</span>'
                f'<code>{_esc(fqcn)}</code></summary>'
                '<div class="mm-methods">'
                f'<div class="mm-method"><span class="cdot" style="background:{cdot}"></span>'
                f'{method_txt}<span class="src">{_esc(src)}</span></div>'
                '</div></details>'
            )

        hints = m.get("generic_frida_hints", [])
        hints_html = ""
        if hints:
            lis = "".join(f"<li>{_esc(h)}</li>" for h in hints)
            hints_html = (
                '<details class="mm-class"><summary><span class="chev">&#9654;</span>'
                'framework-level bypasses</summary>'
                f'<ul class="mm-hints">{lis}</ul></details>'
            )

        pill = f'{len(cands)} class hook point(s)'
        if omitted:
            pill += f' &middot; +{omitted} more in JSON'
        classes_html = "".join(class_nodes) or (
            '<div class="mm-note">no precise class hook point &mdash; use framework hints below</div>'
        )
        jump = (f'<a class="mm-jump" href="#cat-{cat}" '
                f'onclick="event.stopPropagation()">view findings &#8595;</a>')
        blocks.append(
            f'<details class="mm-cat" open><summary><span class="chev">&#9654;</span>'
            f'<span class="dot" style="background:{color}"></span><b>{_esc(label)}</b>'
            f'<span class="mm-pill">{pill}</span>{jump}</summary>'
            f'{classes_html}{hints_html}</details>'
        )

    accordion_html = f'<div id="mm-accordion-view" class="mindmap" style="display:none;">{"".join(blocks)}</div>'

    if not mindmap_data:
        empty_note = '<div class="mm-note">No defensive mechanisms mapped.</div>'
        content = "".join(blocks) if blocks else empty_note
        return head + f'<div class="mindmap">{content}</div></div>'

    raw_json_str = json.dumps(mindmap_data).replace("</script>", "<\\/script>").replace("<", "\\u003c")

    interactive_template = """
  <div id="mm-interactive-card" class="mm-interactive-card">
    <div class="mm-toolbar">
      <div class="mm-search-box">
        <span class="icon">&#128269;</span>
        <input type="text" id="mm-search-input" placeholder="Search mind-map classes, hooks, methods, secrets..." oninput="mmFilterSearch(this.value)">
        <span id="mm-match-count" class="mm-match-count"></span>
      </div>
      <div class="mm-pills">
        <button class="mm-pill-btn active" onclick="mmFilterCategory('all', this)">All</button>
        <button class="mm-pill-btn" onclick="mmFilterCategory('ENFORCEMENT', this)">Enforcement</button>
        <button class="mm-pill-btn" onclick="mmFilterCategory('RASP_DETECTION', this)">RASP</button>
        <button class="mm-pill-btn" onclick="mmFilterCategory('ROOT_DETECTION', this)">Root/JB</button>
        <button class="mm-pill-btn" onclick="mmFilterCategory('ANTI_DEBUG', this)">Anti-Debug</button>
        <button class="mm-pill-btn" onclick="mmFilterCategory('ANTI_HOOK', this)">Anti-Hook</button>
        <button class="mm-pill-btn" onclick="mmFilterCategory('INTEGRITY_CHECK', this)">Integrity</button>
        <button class="mm-pill-btn" onclick="mmFilterCategory('HARDCODED_SECRETS', this)">Secrets</button>
        <button class="mm-pill-btn" onclick="mmFilterCategory('NATIVE', this)">Native</button>
      </div>
      <div class="mm-actions">
        <button class="mm-btn" onclick="mmZoomIn()" title="Zoom In">+</button>
        <button class="mm-btn" onclick="mmZoomOut()" title="Zoom Out">&minus;</button>
        <button class="mm-btn" onclick="mmResetView()" title="Fit View">Fit</button>
        <button class="mm-btn" onclick="mmExpandAll()" title="Expand All">Expand</button>
        <button class="mm-btn" onclick="mmCollapseAll()" title="Collapse All">Collapse</button>
        <button class="mm-btn" onclick="mmToggleView()" title="Toggle View">&#9776; List</button>
      </div>
    </div>
    <div class="mm-viewport" id="mm-viewport">
      <svg id="mm-svg"><g id="mm-main-group"></g></svg>
      <div id="mm-tooltip" class="mm-tooltip"></div>
      <div id="mm-drawer" class="mm-drawer">
        <div class="mm-drawer-header">
          <span id="mm-drawer-badge" class="badge badge-high">INFO</span>
          <button class="mm-drawer-close" onclick="mmCloseDrawer()">&times;</button>
        </div>
        <div class="mm-drawer-body">
          <div class="mm-drawer-field">
            <div class="mm-drawer-label">Target Name</div>
            <strong id="mm-drawer-title" style="color:#f8fafc; font-size:14px; word-break:break-all;"></strong>
          </div>
          <div class="mm-drawer-field">
            <div class="mm-drawer-label">Full Identifier / Class</div>
            <code id="mm-drawer-fullname" style="background:#020617; color:#cbd5e1; padding:6px 8px; border-radius:6px; font-size:11px;"></code>
          </div>
          <div id="mm-val-group" class="mm-drawer-field" style="display:none;">
            <div class="mm-drawer-label">Value / Frida Hook Implementation</div>
            <div id="mm-drawer-val" class="mm-drawer-code"></div>
            <button class="mm-copy-btn" onclick="mmCopyText('mm-drawer-val')">&#128203; Copy Frida Hook</button>
          </div>
          <div class="mm-drawer-field">
            <div class="mm-drawer-label">Detection Details &amp; Confidence</div>
            <div id="mm-drawer-details" style="line-height:1.45;"></div>
          </div>
          <div id="mm-snippet-group" class="mm-drawer-field" style="display:none;">
            <div class="mm-drawer-label">Code Snippet / Source Evidence</div>
            <div id="mm-drawer-snippet" class="mm-drawer-code" style="color:#e2e8f0;"></div>
          </div>
        </div>
      </div>
    </div>
  </div>
  """

    js_code = """
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <script>
  (function() {
    const rawData = __MINDMAP_DATA__;
    if (!rawData || !window.d3) return;

    const colors = {
      root: "#7c5cff",
      ROOT_DETECTION: "#ef4444",
      INTEGRITY_CHECK: "#a855f7",
      ANTI_DEBUG: "#3b82f6",
      ANTI_HOOK: "#14b8a6",
      EMULATOR_DETECT: "#f59e0b",
      MDM_CHECK: "#64748b",
      SSL_PINNING: "#ec4899",
      RASP_DETECTION: "#f43f5e",
      ENFORCEMENT: "#dc2626",
      HARDCODED_SECRETS: "#eab308",
      NATIVE: "#06b6d4"
    };

    let root, svg, g, zoom, tree;

    function initMindMap() {
      const container = document.getElementById("mm-viewport");
      if (!container) return;
      const width = container.clientWidth || 1000;
      const height = container.clientHeight || 650;

      svg = d3.select("#mm-svg");
      g = d3.select("#mm-main-group");

      zoom = d3.zoom()
        .scaleExtent([0.15, 3])
        .on("zoom", (event) => g.attr("transform", event.transform));

      svg.call(zoom);
      svg.call(zoom.transform, d3.zoomIdentity.translate(80, height / 2).scale(0.8));

      root = d3.hierarchy(rawData);
      root.x0 = height / 2;
      root.y0 = 0;

      // Collapse level 2+ by default to avoid initial clutter
      if (root.children) {
        root.children.forEach(group => {
          if (group.children) {
            group._children = group.children;
            group.children = null;
          }
        });
      }

      update(root);
    }

    function truncate(str, maxLen = 32) {
      if (!str) return "";
      return str.length > maxLen ? str.slice(0, maxLen - 3) + "..." : str;
    }

    function update(source) {
      const nodes = root.descendants();
      const links = root.links();

      const nodeHeight = 36;
      const dynamicHeight = Math.max(650, nodes.length * nodeHeight);
      tree = d3.tree().size([dynamicHeight - 80, Math.max(1000, (root.height + 1) * 240)]);
      tree(root);

      nodes.forEach(d => { d.y = d.depth * 230; });

      let i = 0;
      const node = g.selectAll("g.mm-node")
        .data(nodes, d => d.id || (d.id = ++i));

      const nodeEnter = node.enter().append("g")
        .attr("class", "mm-node")
        .attr("transform", d => `translate(${source.y0 || source.y},${source.x0 || source.x})`)
        .on("click", (event, d) => {
          if (d.children) {
            d._children = d.children;
            d.children = null;
          } else if (d._children) {
            d.children = d._children;
            d._children = null;
          }
          mmOpenDrawer(d.data);
          update(d);
        })
        .on("mouseover", (event, d) => mmShowTooltip(event, d.data))
        .on("mousemove", mmMoveTooltip)
        .on("mouseout", mmHideTooltip);

      nodeEnter.append("circle")
        .attr("r", 1e-6)
        .attr("fill", d => d._children ? (colors[d.data.category] || '#94a3b8') : (d.children ? '#0f172a' : (colors[d.data.category] || '#94a3b8')))
        .attr("stroke", d => colors[d.data.category] || '#94a3b8')
        .attr("stroke-width", d => d._children ? "2.5px" : "1.8px");

      nodeEnter.append("text")
        .attr("dy", ".35em")
        .attr("x", d => (d.children || d._children) ? -14 : 14)
        .attr("text-anchor", d => (d.children || d._children) ? "end" : "start")
        .text(d => truncate(d.data.name))
        .style("fill-opacity", 1e-6);

      const nodeUpdate = node.merge(nodeEnter).transition().duration(320)
        .attr("transform", d => `translate(${d.y},${d.x})`);

      nodeUpdate.select("circle")
        .attr("r", d => d.depth === 0 ? 9 : (d._children ? 7 : 5))
        .attr("fill", d => d._children ? (colors[d.data.category] || '#94a3b8') : (d.children ? '#0f172a' : (colors[d.data.category] || '#94a3b8')))
        .attr("stroke", d => colors[d.data.category] || '#94a3b8')
        .attr("stroke-width", d => d._children ? "2.5px" : "1.8px");

      nodeUpdate.select("text")
        .style("fill-opacity", 1)
        .attr("x", d => (d.children || d._children) ? -14 : 14)
        .attr("text-anchor", d => (d.children || d._children) ? "end" : "start")
        .text(d => truncate(d.data.name));

      const nodeExit = node.exit().transition().duration(320)
        .attr("transform", d => `translate(${source.y},${source.x})`)
        .remove();

      nodeExit.select("circle").attr("r", 1e-6);
      nodeExit.select("text").style("fill-opacity", 1e-6);

      const link = g.selectAll("path.mm-link")
        .data(links, d => d.target.id);

      const linkEnter = link.enter().insert("path", "g")
        .attr("class", "mm-link")
        .attr("d", d => {
          const o = {x: source.x0 || source.x, y: source.y0 || source.y};
          return mmDiagonal(o, o);
        });

      link.merge(linkEnter).transition().duration(320)
        .attr("d", d => mmDiagonal(d.source, d.target));

      link.exit().transition().duration(320)
        .attr("d", d => {
          const o = {x: source.x, y: source.y};
          return mmDiagonal(o, o);
        })
        .remove();

      nodes.forEach(d => {
        d.x0 = d.x;
        d.y0 = d.y;
      });
    }

    function mmDiagonal(s, d) {
      return `M ${s.y} ${s.x} C ${(s.y + d.y) / 2} ${s.x}, ${(s.y + d.y) / 2} ${d.x}, ${d.y} ${d.x}`;
    }

    window.mmOpenDrawer = function(data) {
      const drawer = document.getElementById("mm-drawer");
      const badge = document.getElementById("mm-drawer-badge");
      const title = document.getElementById("mm-drawer-title");
      const fullname = document.getElementById("mm-drawer-fullname");
      const valGroup = document.getElementById("mm-val-group");
      const valElem = document.getElementById("mm-drawer-val");
      const details = document.getElementById("mm-drawer-details");
      const snippetGroup = document.getElementById("mm-snippet-group");
      const snippet = document.getElementById("mm-drawer-snippet");

      const catColor = colors[data.category] || '#7c5cff';
      badge.textContent = (data.category || 'INFO').toUpperCase();
      badge.style.background = catColor;
      badge.style.color = '#fff';

      title.textContent = data.name || "Details";
      fullname.textContent = data.full_name || data.name || "N/A";

      if (data.val) {
        valGroup.style.display = "flex";
        valElem.textContent = data.val;
      } else {
        valGroup.style.display = "none";
      }

      details.textContent = data.details || "No further details available.";

      if (data.snippet) {
        snippetGroup.style.display = "flex";
        snippet.textContent = data.snippet;
      } else {
        snippetGroup.style.display = "none";
      }

      drawer.classList.add("open");
    };

    window.mmCloseDrawer = function() {
      const d = document.getElementById("mm-drawer");
      if (d) d.classList.remove("open");
    };

    const tooltip = document.getElementById("mm-tooltip");
    window.mmShowTooltip = function(event, data) {
      if (!tooltip) return;
      tooltip.innerHTML = `<strong>${data.name}</strong><br><span style="color:#94a3b8; font-size:10px;">${(data.category||'').toUpperCase()}</span><br>${data.details || ''}`;
      tooltip.style.display = "block";
      mmMoveTooltip(event);
    };
    window.mmMoveTooltip = function(event) {
      if (!tooltip) return;
      const rect = document.getElementById("mm-viewport").getBoundingClientRect();
      tooltip.style.left = (event.clientX - rect.left + 15) + "px";
      tooltip.style.top = (event.clientY - rect.top + 15) + "px";
    };
    window.mmHideTooltip = function() {
      if (tooltip) tooltip.style.display = "none";
    };

    window.mmCopyText = function(elemId) {
      const el = document.getElementById(elemId);
      if (!el) return;
      navigator.clipboard.writeText(el.textContent).then(() => {
        showToast("Frida hook copied to clipboard");
        const btn = document.querySelector(".mm-copy-btn");
        if (btn) {
          const old = btn.innerHTML;
          btn.innerHTML = "&#10003; Copied!";
          setTimeout(() => btn.innerHTML = old, 1800);
        }
      });
    };

    window.mmFilterCategory = function(cat, btn) {
      document.querySelectorAll(".mm-pill-btn").forEach(b => b.classList.remove("active"));
      if (btn) btn.classList.add("active");

      if (cat === "all") {
        if (root.children) {
          root.children.forEach(g => {
            if (g._children) { g.children = g._children; g._children = null; }
          });
        }
      } else {
        if (root.children) {
          root.children.forEach(g => {
            if (g.data.category === cat) {
              if (g._children) { g.children = g._children; g._children = null; }
            } else {
              if (g.children) { g._children = g.children; g.children = null; }
            }
          });
        }
      }
      update(root);
      mmResetView();
    };

    window.mmFilterSearch = function(keyword) {
      const countLabel = document.getElementById("mm-match-count");
      if (!keyword || keyword.trim() === "") {
        countLabel.textContent = "";
        return;
      }
      const q = keyword.toLowerCase().trim();
      let matches = 0;

      function searchNode(d) {
        const match = (d.data.name && d.data.name.toLowerCase().includes(q)) ||
                      (d.data.full_name && d.data.full_name.toLowerCase().includes(q)) ||
                      (d.data.details && d.data.details.toLowerCase().includes(q)) ||
                      (d.data.val && d.data.val.toLowerCase().includes(q));
        if (match) matches++;

        let childMatch = false;
        const allChildren = (d.children || []).concat(d._children || []);
        allChildren.forEach(c => {
          if (searchNode(c)) childMatch = true;
        });

        if (childMatch) {
          if (d._children) {
            d.children = d._children;
            d._children = null;
          }
        }
        return match || childMatch;
      }

      searchNode(root);
      countLabel.textContent = matches > 0 ? `${matches} match${matches > 1 ? 'es' : ''}` : "No matches";
      update(root);
    };

    window.mmExpandAll = function() {
      function expand(d) {
        if (d._children) { d.children = d._children; d._children = null; }
        if (d.children) d.children.forEach(expand);
      }
      expand(root);
      update(root);
    };

    window.mmCollapseAll = function() {
      function collapse(d) {
        if (d.children) { d._children = d.children; d.children = null; }
      }
      if (root.children) root.children.forEach(collapse);
      update(root);
      mmResetView();
    };

    window.mmResetView = function() {
      const container = document.getElementById("mm-viewport");
      const h = container ? container.clientHeight : 650;
      svg.transition().duration(400).call(
        zoom.transform,
        d3.zoomIdentity.translate(80, h / 2).scale(0.8)
      );
    };

    window.mmZoomIn = function() {
      svg.transition().duration(250).call(zoom.scaleBy, 1.3);
    };

    window.mmZoomOut = function() {
      svg.transition().duration(250).call(zoom.scaleBy, 0.7);
    };

    window.mmToggleView = function() {
      const treeView = document.getElementById("mm-interactive-card");
      const accView = document.getElementById("mm-accordion-view");
      if (accView.style.display === "none") {
        accView.style.display = "block";
        treeView.style.display = "none";
      } else {
        accView.style.display = "none";
        treeView.style.display = "block";
      }
    };

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") mmCloseDrawer();
    });

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", initMindMap);
    } else {
      initMindMap();
    }
  })();
  </script>
  """.replace("__MINDMAP_DATA__", raw_json_str)

    return head + interactive_template + accordion_html + js_code + "</div>"



DASHBOARD_JS = """
<script>
// Theme Management
function toggleTheme() {
  const html = document.documentElement;
  const current = html.getAttribute('data-theme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  html.setAttribute('data-theme', next);
  try { localStorage.setItem('dd_theme', next); } catch(e){}
  updateThemeUI(next);
}

function updateThemeUI(theme) {
  const lbl = document.getElementById('theme-label');
  if (lbl) lbl.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
}

(function initTheme() {
  let saved = 'dark';
  try { saved = localStorage.getItem('dd_theme') || 'dark'; } catch(e){}
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeUI(saved);
})();

// Toast Notification
function showToast(msg) {
  const t = document.getElementById('dd-toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2200);
}

// Inline Copy Helper
window.copyValue = function(btn) {
  const val = btn.getAttribute('data-copy');
  if (!val) return;
  navigator.clipboard.writeText(val).then(() => {
    showToast("Copied to clipboard");
    const originalSvg = btn.innerHTML;
    btn.innerHTML = '<span style="color:#10b981; font-size:11px; font-weight:bold;">&#10003;</span>';
    setTimeout(() => { btn.innerHTML = originalSvg; }, 1400);
  });
};

// Copy Executive Summary
window.copyExecutiveSummary = function() {
  const el = document.getElementById('exec-summary-data');
  const summary = el ? el.textContent : "DIVINE DEPARTURE ASSESSMENT";
  navigator.clipboard.writeText(summary).then(() => {
    showToast("Executive summary copied to clipboard!");
  });
};

// Filter & Live Search Logic
let activeConfidence = 'all';

window.filterByConfidence = function(conf, btn) {
  document.querySelectorAll('.conf-pill').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  activeConfidence = conf;
  applyFindingsFilter();
};

window.resetAllFilters = function() {
  const searchInput = document.getElementById('global-search');
  if (searchInput) searchInput.value = '';
  document.querySelectorAll('.conf-pill').forEach(b => b.classList.remove('active'));
  const allBtn = document.querySelector('.conf-pill[data-conf="all"]');
  if (allBtn) allBtn.classList.add('active');
  activeConfidence = 'all';
  applyFindingsFilter();
};

window.applyFindingsFilter = function() {
  const searchInput = document.getElementById('global-search');
  const q = (searchInput ? searchInput.value : '').toLowerCase().trim();
  const rows = document.querySelectorAll('.finding-row');
  let matchCount = 0;

  rows.forEach(r => {
    const rConf = r.getAttribute('data-confidence');
    const rSearch = r.getAttribute('data-search') || '';

    const matchConf = (activeConfidence === 'all' || rConf === activeConfidence);
    const matchQuery = (!q || rSearch.includes(q));

    if (matchConf && matchQuery) {
      r.style.display = '';
      matchCount++;
    } else {
      r.style.display = 'none';
    }
  });

  // Toggle category section visibility if all rows inside are hidden
  document.querySelectorAll('.category-section').forEach(sec => {
    const secRows = sec.querySelectorAll('.finding-row');
    if (secRows.length > 0) {
      const visible = sec.querySelectorAll('.finding-row:not([style*="display: none"])').length;
      sec.style.display = visible > 0 ? '' : 'none';
    }
  });

  const countLabel = document.getElementById('filter-match-count');
  if (countLabel) {
    countLabel.textContent = 'Showing ' + matchCount + ' of ' + rows.length + ' findings';
  }
};
</script>
"""


def build_report(apk_name, source_findings, native_string_findings, native_callsite_findings,
                  warnings, out_path, patch_records=None, security_model=None,
                  frida_json_name=None, frida_prompt_name=None, patched_apk_name=None,
                  platform="android"):
    all_categories = ALL_CATEGORIES
    labels = IOS_CATEGORY_LABELS if platform == "ios" else CATEGORY_LABELS

    cat_counts = Counter()
    for f in source_findings:
        cat_counts[f.category] += 1
    for f in native_string_findings:
        cat_counts[f.category] += 1
    for f in native_callsite_findings:
        cat_counts[f.category] += 1

    total = sum(cat_counts.values())

    all_findings = list(source_findings) + list(native_string_findings) + list(native_callsite_findings)
    high_count = sum(1 for f in all_findings if str(getattr(f, 'confidence', '')).lower() == 'high')
    medium_count = sum(1 for f in all_findings if str(getattr(f, 'confidence', '')).lower() == 'medium')
    low_count = sum(1 for f in all_findings if str(getattr(f, 'confidence', '')).lower() == 'low')
    vectors_count = sum(1 for cat in all_categories if cat_counts[cat] > 0)

    # Posture rating
    if high_count >= 5:
        posture_badge = '<span class="badge badge-high"><span class="badge-dot"></span>HIGH RESISTANCE</span>'
        posture_color = "var(--danger)"
    elif high_count > 0 or medium_count >= 5:
        posture_badge = '<span class="badge badge-medium"><span class="badge-dot"></span>MODERATE DEFENSES</span>'
        posture_color = "var(--warning)"
    elif total > 0:
        posture_badge = '<span class="badge badge-low"><span class="badge-dot"></span>BASELINE / MINIMAL</span>'
        posture_color = "var(--info)"
    else:
        posture_badge = '<span class="badge badge-low"><span class="badge-dot"></span>NO DETECTIONS</span>'
        posture_color = "var(--dim)"

    # Percentages for posture track
    pct_high = (high_count / total * 100) if total else 0
    pct_med = (medium_count / total * 100) if total else 0
    pct_low = (low_count / total * 100) if total else 0

    # Summary Cards
    summary_cards = "".join(
        f'<a class="card" href="#cat-{cat}">'
        f'<div class="card-head">'
        f'<span class="dot" style="background:{CATEGORY_COLOR.get(cat, "#64748b")}"></span>'
        f'<div class="num" style="color:{CATEGORY_COLOR.get(cat, "#64748b")}">{cat_counts.get(cat, 0)}</div>'
        f'</div>'
        f'<div class="label">{_esc(labels[cat])}</div></a>'
        for cat in all_categories
    )

    warnings_html = ""
    if warnings:
        items = "".join(f"<li>{_esc(w)}</li>" for w in warnings)
        warnings_html = f'<div class="warnings"><strong>Tool Execution Notes / Scanner Warnings:</strong><ul>{items}</ul></div>'

    platform_label = "iOS Application" if platform == "ios" else "Android APK / AAB"
    source_label = "Decompiled Objective-C / Swift / Binary symbols" if platform == "ios" else "Decompiled Java &amp; Smali Bytecode Patterns"

    sections = []
    for cat in all_categories:
        src = [f for f in source_findings if f.category == cat]
        nstr = [f for f in native_string_findings if f.category == cat]
        ncall = [f for f in native_callsite_findings if f.category == cat]
        color = CATEGORY_COLOR.get(cat, "#64748b")
        cat_total = len(src) + len(nstr) + len(ncall)

        sec_html = [
            f'<div class="category-section" id="cat-{cat}">'
            f'<h2><div class="h2-left">'
            f'<span class="dot" style="background:{color}"></span>'
            f'{_esc(labels[cat])}'
            f'<span class="badge badge-low" style="margin-left:8px;">{cat_total} findings</span>'
            f'</div>'
            f'<a class="h2-top-link" href="#">&#8593; Top</a></h2>'
        ]
        sec_html.append(f"<h3>{source_label}</h3>")
        sec_html.append(_source_table(src))
        if nstr:
            sec_html.append("<h3>Native Library &mdash; Hardcoded Defense String References</h3>")
            sec_html.append(_native_string_table(nstr))
        if ncall:
            sec_html.append("<h3>Native Library &mdash; Disassembled Call Sites &amp; C Imports</h3>")
            sec_html.append(_native_callsite_table(ncall))
        sec_html.append('</div>')
        sections.append("".join(sec_html))

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    exec_summary_plain = (
        f"DIVINE DEPARTURE SECURITY ASSESSMENT REPORT\\n"
        f"Target: {apk_name}\\n"
        f"Platform: {platform_label}\\n"
        f"Generated: {generated_at}\\n"
        f"Total Findings: {total}\\n"
        f"High Confidence: {high_count} | Medium: {medium_count} | Low: {low_count}\\n"
        f"Active Defense Vectors: {vectors_count} of 10\\n"
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DIVINE DEPARTURE &mdash; {_esc(apk_name)} Audit Report</title>
<style>{CSS}</style>
</head>
<body>

<div id="dd-overlay">
  <div class="dd-title">DIVINE DEPARTURE</div>
  <div class="dd-sub">Security Audit &amp; Reverse Engineering Report</div>
</div>

<header class="hud-header">
  <div class="hud-inner">
    <div class="brand-group">
      <div class="brand-logo">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          <path d="m9 12 2 2 4-4"></path>
        </svg>
      </div>
      <div class="brand-titles">
        <h1><span class="brand-text">DIVINE DEPARTURE</span> <span style="font-size:14px; color:var(--muted); font-weight:500;">/ Security Posture Assessment</span></h1>
        <div class="hud-meta-row">
          <span class="meta-chip">Target: <code>{_esc(apk_name)}</code></span>
          <span class="meta-chip">Platform: <code>{_esc(platform_label)}</code></span>
          <span class="meta-chip">Generated: <code>{generated_at}</code></span>
        </div>
      </div>
    </div>
    <div class="hud-controls">
      <button class="hud-btn" id="theme-toggle-btn" onclick="toggleTheme()" title="Toggle Dark/Light Theme">
        <svg id="theme-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="5"></circle>
          <line x1="12" y1="1" x2="12" y2="3"></line>
          <line x1="12" y1="21" x2="12" y2="23"></line>
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
          <line x1="1" y1="12" x2="3" y2="12"></line>
          <line x1="21" y1="12" x2="23" y2="12"></line>
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        </svg>
        <span id="theme-label">Light Mode</span>
      </button>
      <button class="hud-btn" onclick="copyExecutiveSummary()" title="Copy executive summary to clipboard">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
        Copy Summary
      </button>
      <button class="hud-btn" onclick="window.print()" title="Export PDF / Print Report">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="6 9 6 2 18 2 18 9"></polyline>
          <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path>
          <rect x="6" y="14" width="12" height="8"></rect>
        </svg>
        Export PDF
      </button>
    </div>
  </div>
</header>

<div class="container">
  {_action_bar(security_model, frida_json_name, frida_prompt_name, patched_apk_name)}

  <!-- KPI Posture HUD -->
  <div class="kpi-grid">
    <div class="kpi-card" style="--kpi-accent: var(--accent);">
      <div class="kpi-label">Total Detections <span>&#128065;</span></div>
      <div class="kpi-val">{total}</div>
      <div class="kpi-sub">Across source bytecode &amp; native libraries</div>
    </div>
    <div class="kpi-card" style="--kpi-accent: var(--danger);">
      <div class="kpi-label">High Confidence Findings <span>&#128293;</span></div>
      <div class="kpi-val" style="color:var(--danger);">{high_count}</div>
      <div class="kpi-sub">Definite anti-tamper &amp; active checks</div>
    </div>
    <div class="kpi-card" style="--kpi-accent: var(--warning);">
      <div class="kpi-label">Medium Confidence <span>&#9888;</span></div>
      <div class="kpi-val" style="color:var(--warning);">{medium_count}</div>
      <div class="kpi-sub">Heuristic signatures &amp; suspicious symbols</div>
    </div>
    <div class="kpi-card" style="--kpi-accent: {posture_color};">
      <div class="kpi-label">Security Posture Rating <span>&#128737;</span></div>
      <div style="margin-top:6px;">{posture_badge}</div>
      <div class="kpi-sub" style="margin-top:10px;">{vectors_count} of 10 defense vectors identified</div>
    </div>
  </div>

  <!-- Confidence Distribution Meter -->
  <div class="posture-bar-wrapper">
    <div class="posture-header">
      <span>Confidence Distribution: {high_count} High ({pct_high:.0f}%) &middot; {medium_count} Medium ({pct_med:.0f}%) &middot; {low_count} Low ({pct_low:.0f}%)</span>
      <span>{vectors_count} Defense Categories Active</span>
    </div>
    <div class="posture-track">
      <div class="posture-seg" style="width:{pct_high}%; background:var(--danger);" title="High Confidence: {high_count}"></div>
      <div class="posture-seg" style="width:{pct_med}%; background:var(--warning);" title="Medium Confidence: {medium_count}"></div>
      <div class="posture-seg" style="width:{pct_low}%; background:var(--dim);" title="Low Confidence: {low_count}"></div>
    </div>
  </div>

  <div class="summary-title">&#9632; Security Defense Vectors &mdash; Quick Jump Matrix</div>
  <div class="summary">{summary_cards}</div>

  {warnings_html}

  <!-- Live Finding Search & Filter Toolbar -->
  <div class="filter-toolbar">
    <div class="filter-row-primary">
      <div class="search-wrapper">
        <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"></circle>
          <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        </svg>
        <input type="text" id="global-search" placeholder="Filter findings by signature, class name, snippet, or description..." oninput="applyFindingsFilter()">
      </div>
      <div class="filter-stats" id="filter-match-count">Showing all {total} findings</div>
    </div>
    <div class="filter-pills-row">
      <span style="font-size:11.5px; color:var(--dim); font-weight:700; text-transform:uppercase; margin-right:4px;">Confidence:</span>
      <button class="filter-pill active conf-pill" data-conf="all" onclick="filterByConfidence('all', this)">All</button>
      <button class="filter-pill conf-pill" data-conf="high" onclick="filterByConfidence('high', this)">High ({high_count})</button>
      <button class="filter-pill conf-pill" data-conf="medium" onclick="filterByConfidence('medium', this)">Medium ({medium_count})</button>
      <button class="filter-pill conf-pill" data-conf="low" onclick="filterByConfidence('low', this)">Low ({low_count})</button>
      <button class="filter-pill" style="margin-left:auto;" onclick="resetAllFilters()">Reset Filters</button>
    </div>
  </div>

  {_mindmap_section(security_model)}
  {_patch_section(patch_records)}
  {''.join(sections)}
</div>

<div id="dd-toast">Notification</div>
<div id="exec-summary-data" style="display:none;">{_esc(exec_summary_plain)}</div>

<footer>
  <strong>DIVINE DEPARTURE</strong> &mdash; Reverse Engineering &amp; AppSec Posture Suite.<br>
  All findings are produced via static heuristic signature analysis and require dynamic validation before inclusion in formal compliance reports.
</footer>

{DASHBOARD_JS}

</body>
</html>"""

    out_path = Path(out_path)
    out_path.write_text(html_doc, encoding="utf-8")
    return out_path

