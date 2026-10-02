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
}

ALL_CATEGORIES = [
    "ROOT_DETECTION", "INTEGRITY_CHECK", "ANTI_DEBUG",
    "ANTI_HOOK", "EMULATOR_DETECT", "MDM_CHECK", "SSL_PINNING", "RASP_DETECTION"
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


def _action_bar(security_model, frida_json_name, frida_prompt_name, patched_apk_name):
    btns = []
    if security_model is not None:
        btns.append('<a class="btn primary" href="#mindmap"><span class="i">&#129504;</span>Security Mind-Map</a>')
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
    """Inline collapsible mind-map: category -> java class -> method hook points."""
    if security_model is None:
        return ""
    mechs = security_model.get("defense_mechanisms", [])
    tgt = security_model.get("target", {})
    head = (
        '<h2 id="mindmap"><span class="dot" style="background:var(--accent)"></span>'
        'Security Mind-Map &mdash; hook points for Frida</h2>'
        '<div class="mm-note">Class &amp; method names are heuristic (derived from decompiled '
        'paths and nearby headers) &mdash; verify before hooking. Full data: '
        '<code>security_model.json</code> &nbsp;|&nbsp; ready-to-use LLM prompt: <code>frida_prompt.md</code>.</div>'
    )
    if not mechs:
        return head + '<div class="mindmap"><div class="mm-note">No defensive mechanisms mapped.</div></div>'

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

    return head + f'<div class="mindmap">{"".join(blocks)}</div>'


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
