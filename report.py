"""
report.py

Renders all collected findings (source-level + native-level) into a single
self-contained HTML file -- no external CSS/JS dependencies, easy to attach to a
pentest report or open directly in a browser.

When a Frida brief was produced (`--frida-brief`), the report also gets an inline,
collapsible "Security Mind-Map" (category -> class -> method hook points) plus an
action bar linking to security_model.json / frida_prompt.md / the patched APK.
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

# Accent colour per category -- used for summary cards, section headers, mind-map nodes.
CATEGORY_COLOR = {
    "ROOT_DETECTION":  "#e5484d",
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
    "high": "#e5484d",
    "medium": "#f59e0b",
    "low": "#94a3b8",
}

CSS = """
:root {
  --bg: #f5f6f9; --panel: #ffffff; --ink: #1b2230; --muted: #64748b;
  --line: #e6e9ef; --code-bg: #eef1f6; --shadow: 0 1px 2px rgba(16,24,40,.06), 0 8px 24px rgba(16,24,40,.05);
  --accent: #7c5cff; --accent2: #22d3ee;
}
* { box-sizing: border-box; }
body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  margin: 0; background: var(--bg); color: var(--ink); line-height: 1.5; -webkit-font-smoothing: antialiased; }

header { background: linear-gradient(120deg, #1a0b2e 0%, #241146 45%, #0b2b3a 100%); color: #fff;
  padding: 30px 34px 26px; border-bottom: 3px solid var(--accent); }
header h1 { margin: 0 0 6px; font-size: 20px; font-weight: 700; letter-spacing: .01em; }
header .brand { font-weight: 800; background: linear-gradient(90deg, #b388ff, #64ffda);
  -webkit-background-clip: text; background-clip: text; color: transparent; }
header .meta { color: #b7c4d6; font-size: 12.5px; }

.container { padding: 26px 34px 40px; max-width: 1180px; margin: 0 auto; }

/* action bar */
.actionbar { display: flex; flex-wrap: wrap; gap: 10px; margin: -14px 0 26px; }
.btn { display: inline-flex; align-items: center; gap: 7px; text-decoration: none;
  background: var(--panel); color: var(--ink); border: 1px solid var(--line); border-radius: 9px;
  padding: 9px 15px; font-size: 13px; font-weight: 600; box-shadow: var(--shadow); transition: transform .06s ease, border-color .15s; }
.btn:hover { transform: translateY(-1px); border-color: var(--accent); }
.btn.primary { background: linear-gradient(120deg, var(--accent), #9b7bff); color: #fff; border-color: transparent; }
.btn .i { font-size: 15px; line-height: 1; }

/* summary cards */
.summary { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 14px; margin-bottom: 30px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 15px 17px;
  box-shadow: var(--shadow); border-left: 4px solid var(--muted); display: block; text-decoration: none; color: inherit;
  transition: transform .06s ease, border-color .15s, box-shadow .15s; }
a.card:hover { transform: translateY(-2px); box-shadow: 0 2px 4px rgba(16,24,40,.08), 0 14px 30px rgba(16,24,40,.1); }
a.card:hover .label { color: var(--ink); }
.card .num { font-size: 25px; font-weight: 800; letter-spacing: -.01em; }
.card .label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-top: 2px; }
.card.total { border-left-color: var(--accent); background: linear-gradient(120deg, #ffffff, #f3efff); }
:target > h2, h2:target { animation: dd-flash 1.4s ease-out; }
@keyframes dd-flash { 0% { background: #fff3bf; } 100% { background: transparent; } }

h2 { font-size: 17px; margin: 40px 0 14px; padding-bottom: 8px; border-bottom: 1px solid var(--line);
  display: flex; align-items: center; gap: 10px; }
h2 .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--muted); flex: none; }
h3 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted);
  margin: 22px 0 8px; font-weight: 700; }

table { width: 100%; border-collapse: separate; border-spacing: 0; background: var(--panel);
  border: 1px solid var(--line); border-radius: 12px; overflow: hidden; box-shadow: var(--shadow); margin-bottom: 10px; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); font-size: 12.5px; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #fafbfe; }
th { background: #f7f8fb; font-size: 10.5px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); font-weight: 700; }
code { background: var(--code-bg); padding: 1.5px 6px; border-radius: 5px; font-size: 11.5px;
  font-family: "SF Mono", "Cascadia Code", Consolas, monospace; word-break: break-all; }

.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; color: #fff; font-size: 10.5px; font-weight: 700; letter-spacing: .03em; }
.empty { color: var(--muted); font-style: italic; padding: 10px 2px; font-size: 13px; }
.warnings { background: #fffaf0; border: 1px solid #f3dca6; border-radius: 12px; padding: 13px 17px; margin-bottom: 24px; font-size: 12.5px; }
.warnings ul { margin: 6px 0 0; padding-left: 18px; }
.warnings li { margin: 3px 0; white-space: pre-wrap; }
footer { text-align: center; color: var(--muted); font-size: 11.5px; padding: 26px; }

/* ---- Security Mind-Map ---- */
.mindmap { background: var(--panel); border: 1px solid var(--line); border-radius: 14px;
  box-shadow: var(--shadow); padding: 8px 6px; margin-bottom: 10px; }
.mindmap details { border-radius: 8px; }
.mindmap > details { margin: 4px 2px; }
.mindmap summary { cursor: pointer; list-style: none; padding: 8px 10px; border-radius: 8px;
  display: flex; align-items: center; gap: 9px; font-size: 13px; user-select: none; }
.mindmap summary::-webkit-details-marker { display: none; }
.mindmap summary:hover { background: #f6f7fb; }
.mindmap summary .chev { transition: transform .15s ease; color: var(--muted); font-size: 11px; }
.mindmap details[open] > summary .chev { transform: rotate(90deg); }
.mm-cat > summary { font-weight: 700; }
.mm-pill { margin-left: auto; font-size: 10.5px; color: var(--muted); background: var(--code-bg);
  padding: 1px 8px; border-radius: 999px; font-weight: 600; }
.mm-jump { font-size: 10.5px; font-weight: 600; color: var(--accent); text-decoration: none;
  margin-left: 10px; white-space: nowrap; }
.mm-jump:hover { text-decoration: underline; }
.mm-class { margin: 2px 0 2px 22px; border-left: 2px solid var(--line); }
.mm-class > summary { font-family: "SF Mono", Consolas, monospace; font-size: 12px; color: #334155; }
.mm-methods { margin: 2px 0 8px 34px; display: flex; flex-direction: column; gap: 3px; }
.mm-method { font-family: "SF Mono", Consolas, monospace; font-size: 11.5px; color: #475569;
  display: flex; align-items: center; gap: 8px; padding: 2px 0; }
.mm-method .cdot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
.mm-method .src { color: var(--muted); font-size: 10.5px; margin-left: auto; }
.mm-hints { margin: 4px 0 10px 34px; font-size: 11.5px; color: var(--muted); }
.mm-hints li { margin: 2px 0; }
.mm-note { font-size: 11px; color: var(--muted); padding: 6px 12px; }

/* ---- Divine Departure intro overlay ---- */
#dd-overlay { position: fixed; inset: 0; z-index: 9999;
  background: radial-gradient(ellipse at center, #1a0b2e 0%, #05030a 80%);
  display: flex; align-items: center; justify-content: center; flex-direction: column;
  animation: dd-fadeout 0.8s ease-in forwards; animation-delay: 2.4s; }
#dd-overlay .dd-title { font-size: 40px; font-weight: 800; letter-spacing: 0.12em;
  background: linear-gradient(90deg, #b388ff, #64ffda, #b388ff); background-size: 200% auto;
  -webkit-background-clip: text; background-clip: text; color: transparent;
  animation-fill-mode: forwards; animation-name: dd-rise, dd-glow, dd-sheen;
  animation-duration: 0.9s, 1.8s, 3s; animation-timing-function: ease-out, ease-in-out, linear;
  animation-iteration-count: 1, infinite, infinite; }
#dd-overlay .dd-sub { margin-top: 10px; font-size: 12px; letter-spacing: 0.3em; color: #7f8c8d;
  text-transform: uppercase; opacity: 0; animation: dd-rise 0.9s ease-out 0.4s forwards; }
@keyframes dd-rise { from { opacity: 0; transform: translateY(14px) scale(.98); } to { opacity: 1; transform: translateY(0) scale(1); } }
@keyframes dd-glow { 0%,100% { filter: drop-shadow(0 0 6px rgba(179,136,255,.5)); } 50% { filter: drop-shadow(0 0 22px rgba(100,255,218,.75)); } }
@keyframes dd-sheen { 0% { background-position: 0% center; } 100% { background-position: 200% center; } }
@keyframes dd-fadeout { from { opacity: 1; visibility: visible; } to { opacity: 0; visibility: hidden; } }
@media print { #dd-overlay { display: none; } .btn { display: none; } }

/* ---- Interactive D3 Mind Map Container & HUD ---- */
.mm-interactive-card {
  background: #090d16;
  border: 1px solid #1e293b;
  border-radius: 14px;
  overflow: hidden;
  box-shadow: 0 4px 20px rgba(0,0,0,0.25);
  margin-bottom: 24px;
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
  max-width: 400px;
}
.mm-search-box input {
  width: 100%;
  background: #1e293b;
  border: 1px solid #334155;
  border-radius: 8px;
  padding: 7px 12px 7px 32px;
  color: #f8fafc;
  font-size: 13px;
  outline: none;
  transition: border-color .15s;
}
.mm-search-box input:focus {
  border-color: #7c5cff;
}
.mm-search-box .icon {
  position: absolute;
  left: 10px;
  top: 50%;
  transform: translateY(-50%);
  color: #64748b;
  font-size: 13px;
}
.mm-match-count {
  position: absolute;
  right: 10px;
  top: 50%;
  transform: translateY(-50%);
  font-size: 11px;
  color: #94a3b8;
  font-weight: 600;
}
.mm-pills {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  align-items: center;
}
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
.mm-actions {
  display: flex;
  gap: 6px;
  align-items: center;
}
.mm-btn {
  background: #1e293b;
  border: 1px solid #334155;
  color: #cbd5e1;
  border-radius: 6px;
  padding: 5px 9px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  gap: 5px;
  transition: background .12s;
}
.mm-btn:hover {
  background: #334155;
  color: #fff;
}
.mm-viewport {
  position: relative;
  background: radial-gradient(circle at 50% 50%, #0d1527 0%, #090d16 100%);
  height: 650px;
  width: 100%;
  overflow: hidden;
}
.mm-viewport svg {
  width: 100%;
  height: 100%;
  display: block;
}
.mm-node text {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
  font-size: 12px;
  font-weight: 500;
  fill: #e2e8f0;
  cursor: pointer;
  user-select: none;
}
.mm-node circle {
  cursor: pointer;
  transition: r .2s, stroke-width .2s;
}
.mm-link {
  fill: none;
  stroke: #334155;
  stroke-width: 1.5px;
  stroke-opacity: 0.65;
}
.mm-drawer {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  width: 380px;
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
.mm-drawer.open {
  transform: translateX(0);
}
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
  font-size: 20px;
  cursor: pointer;
  line-height: 1;
}
.mm-drawer-close:hover {
  color: #fff;
}
.mm-drawer-body {
  padding: 20px;
  overflow-y: auto;
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 16px;
  color: #cbd5e1;
  font-size: 12.5px;
}
.mm-drawer-field {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.mm-drawer-label {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: #64748b;
  font-weight: 700;
}
.mm-drawer-code {
  background: #020617;
  border: 1px solid #1e293b;
  border-radius: 8px;
  padding: 10px 12px;
  font-family: "SF Mono", Consolas, monospace;
  font-size: 11.5px;
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
  padding: 4px 10px;
  font-size: 11px;
  cursor: pointer;
  margin-top: 4px;
}
.mm-copy-btn:hover {
  background: #334155;
}
.mm-tooltip {
  position: absolute;
  display: none;
  background: rgba(15, 23, 42, 0.94);
  border: 1px solid #334155;
  color: #f8fafc;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 11px;
  pointer-events: none;
  box-shadow: 0 4px 12px rgba(0,0,0,0.4);
  z-index: 100;
  max-width: 280px;
  line-height: 1.4;
}
"""


def _esc(s):
    return html.escape(str(s))


def _badge(confidence):
    color = CONFIDENCE_COLOR.get(confidence, "#94a3b8")
    return f'<span class="badge" style="background:{color}">{_esc(str(confidence).upper())}</span>'


def _source_table(findings):
    if not findings:
        return '<div class="empty">No findings in this category.</div>'
    rows = []
    for f in findings:
        rows.append(
            f"<tr><td>{_badge(f.confidence)}</td>"
            f"<td><code>{_esc(f.file_path)}</code>:{f.line_number}</td>"
            f"<td>{_esc(f.pattern_name)}</td>"
            f"<td>{_esc(f.description)}</td>"
            f"<td><code>{_esc(f.snippet)}</code></td></tr>"
        )
    return (
        "<table><thead><tr><th>Confidence</th><th>File : Line</th><th>Signature</th>"
        "<th>Description</th><th>Matched line</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )


def _native_string_table(findings):
    if not findings:
        return '<div class="empty">No native string findings in this category.</div>'
    rows = []
    for f in findings:
        rows.append(
            f"<tr><td>{_badge(f.confidence)}</td>"
            f"<td><code>{_esc(Path(f.so_path).name)}</code></td>"
            f"<td>0x{f.file_offset:x}</td>"
            f"<td>{_esc(f.pattern_name)}</td>"
            f"<td>{_esc(f.description)}</td>"
            f"<td><code>{_esc(f.matched_string)}</code></td></tr>"
        )
    return (
        "<table><thead><tr><th>Confidence</th><th>Library</th><th>File Offset</th>"
        "<th>Signature</th><th>Description</th><th>Matched string</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )


def _native_callsite_table(findings):
    if not findings:
        return '<div class="empty">No native call-site findings in this category.</div>'
    rows = []
    for f in findings:
        rows.append(
            f"<tr><td>{_badge(f.confidence)}</td>"
            f"<td><code>{_esc(Path(f.so_path).name)}</code></td>"
            f"<td>{_esc(f.calling_function)}</td>"
            f"<td>0x{f.call_instruction_address:x}</td>"
            f"<td>{_esc(f.imported_symbol)}()</td>"
            f"<td>{_esc(f.description)}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Confidence</th><th>Library</th><th>Calling Function</th>"
        "<th>Call Address</th><th>Target Import</th><th>Description</th></tr></thead><tbody>"
        + "".join(rows) + "</tbody></table>"
    )


def _patch_section(patch_records):
    """Render the optional 'what --patch changed' section."""
    if patch_records is None:
        return ""
    if not patch_records:
        body = '<div class="empty">Patch mode ran but made no changes.</div>'
    else:
        rows = []
        for r in patch_records:
            rows.append(
                f"<tr><td>{_esc(r.get('category', ''))}</td>"
                f"<td><code>{_esc(r.get('location', ''))}</code></td>"
                f"<td>{_esc(r.get('action', ''))}</td>"
                f"<td>{_esc(r.get('detail', ''))}</td></tr>"
            )
        body = (
            "<table><thead><tr><th>Category</th><th>Location</th><th>Action</th>"
            "<th>Detail</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    return f'<h2 id="patchlog"><span class="dot" style="background:#e5484d"></span>APK Patch Log &mdash; neutralised checks</h2>{body}'


def _action_bar(security_model, frida_json_name, frida_prompt_name, patched_apk_name, mindmap_json_name=None):
    btns = []
    if security_model is not None:
        btns.append('<a class="btn primary" href="#mindmap"><span class="i">&#129504;</span>Security Mind-Map</a>')
    mm_name = mindmap_json_name or (security_model and security_model.get("mindmap_json_name"))
    if mm_name:
        btns.append(f'<a class="btn" href="{_esc(mm_name)}" target="_blank">'
                    f'<span class="i">&#129504;</span>{_esc(mm_name)}</a>')
    if frida_json_name:
        btns.append(f'<a class="btn" href="{_esc(frida_json_name)}" target="_blank">'
                    f'<span class="i">&#128190;</span>security_model.json</a>')
    if frida_prompt_name:
        btns.append(f'<a class="btn" href="{_esc(frida_prompt_name)}" target="_blank">'
                    f'<span class="i">&#9889;</span>Frida prompt</a>')
    if patched_apk_name:
        btns.append(f'<a class="btn" href="{_esc(patched_apk_name)}">'
                    f'<span class="i">&#128230;</span>Patched APK</a>')
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
        '<h2 id="mindmap"><span class="dot" style="background:var(--accent)"></span>'
        'Interactive Security Mind-Map &mdash; Attack Surface &amp; Defense Tree</h2>'
        f'<div class="mm-note">Click any node to inspect details and copy Frida hooks in the slide-out drawer. '
        f'Full structured data: <a href="{_esc(mm_json_name)}" target="_blank" style="color:var(--accent); font-weight:600;"><code>{_esc(mm_json_name)}</code></a> '
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
        return head + f'<div class="mindmap">{content}</div>'

    raw_json_str = json.dumps(mindmap_data).replace("</script>", "<\\/script>").replace("<", "\\u003c")

    interactive_template = """
  <div id="mm-interactive-card" class="mm-interactive-card">
    <div class="mm-toolbar">
      <div class="mm-search-box">
        <span class="icon">&#128269;</span>
        <input type="text" id="mm-search-input" placeholder="Search classes, hooks, methods, secrets..." oninput="mmFilterSearch(this.value)">
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
          <span id="mm-drawer-badge" class="badge" style="background:#7c5cff">INFO</span>
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
      ROOT_DETECTION: "#e5484d",
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

      // Collapse level 2+ by default to avoid clutter
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
        const btn = document.querySelector(".mm-copy-btn");
        if (btn) {
          const old = btn.textContent;
          btn.textContent = "✓ Copied!";
          setTimeout(() => btn.textContent = old, 1800);
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

    return head + interactive_template + accordion_html + js_code


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

    summary_cards = "".join(
        f'<a class="card" href="#cat-{cat}" style="border-left-color:{CATEGORY_COLOR.get(cat, "#64748b")}">'
        f'<div class="num">{cat_counts.get(cat, 0)}</div>'
        f'<div class="label">{_esc(labels[cat])}</div></a>'
        for cat in all_categories
    )
    summary_cards += (
        f'<div class="card total"><div class="num">{total}</div>'
        f'<div class="label">Total Findings</div></div>'
    )

    warnings_html = ""
    if warnings:
        items = "".join(f"<li>{_esc(w)}</li>" for w in warnings)
        warnings_html = f'<div class="warnings"><strong>Notes / tool warnings:</strong><ul>{items}</ul></div>'

    platform_label = "Jailbreak" if platform == "ios" else "Root"
    source_label = "Decompiled Objective-C / Swift / Binary strings" if platform == "ios" else "Decompiled Java / Smali source"

    sections = []
    for cat in all_categories:
        src = [f for f in source_findings if f.category == cat]
        nstr = [f for f in native_string_findings if f.category == cat]
        ncall = [f for f in native_callsite_findings if f.category == cat]
        color = CATEGORY_COLOR.get(cat, "#64748b")

        sections.append(f'<h2 id="cat-{cat}"><span class="dot" style="background:{color}"></span>'
                        f'{_esc(labels[cat])}</h2>')
        sections.append(f"<h3>{source_label}</h3>")
        sections.append(_source_table(src))
        if nstr:
            sections.append("<h3>Native library &mdash; string references</h3>")
            sections.append(_native_string_table(nstr))
        if ncall:
            sections.append("<h3>Native library &mdash; disassembled call sites</h3>")
            sections.append(_native_callsite_table(ncall))

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header_subtitle = f"{platform_label} / Integrity / Anti-Tamper / MDM / SSL-Pinning Analysis"

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DIVINE DEPARTURE -- {_esc(apk_name)}</title>
<style>{CSS}</style>
</head>
<body>
<div id="dd-overlay">
  <div class="dd-title">DIVINE DEPARTURE</div>
  <div class="dd-sub">scan complete</div>
</div>
<header>
  <h1><span class="brand">DIVINE DEPARTURE</span> &mdash; {header_subtitle}</h1>
  <div class="meta">Target: {_esc(apk_name)} &nbsp;|&nbsp; Generated: {generated_at}</div>
</header>
<div class="container">
  {_action_bar(security_model, frida_json_name, frida_prompt_name, patched_apk_name)}
  <div class="summary">{summary_cards}</div>
  {warnings_html}
  {_mindmap_section(security_model)}
  {_patch_section(patch_records)}
  {''.join(sections)}
</div>
<footer>Generated by DIVINE DEPARTURE &mdash; findings require manual verification before inclusion in a client report.</footer>
</body>
</html>"""

    out_path = Path(out_path)
    out_path.write_text(html_doc, encoding="utf-8")
    return out_path
