"""
java_scanner.py

Walks decompiled Java (from jadx) and/or Smali (from apktool) source trees, matching every
line against the signature database in patterns.py. Every hit records the exact file path
and line number so the pentester can jump straight to the code responsible.
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from patterns import SOURCE_PATTERNS, build_prefilter

SOURCE_EXTENSIONS = {".java", ".kt", ".smali", ".js", ".swift", ".m", ".h"}

# Lines longer than this are truncated before regex matching (see loop below).
MAX_LINE_LEN = 2000

# Skip generated/noise directories that bloat scan time without adding signal.
SKIP_DIR_NAMES = {
    "resources", "res", "original", "unknown", "assets", "lib", "META-INF",
    "kotlin", "build", ".gradle", "R", "BuildConfig", "databinding",
    "generated", "test", "androidTest",
}


@dataclass
class SourceFinding:
    pattern_name: str
    category: str
    description: str
    confidence: str
    file_path: str
    line_number: int
    snippet: str


def _iter_source_files(root: Path):
    """Yield source files under root, pruning known noise directories."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            if name.endswith(tuple(SOURCE_EXTENSIONS)):
                yield Path(dirpath) / name


# _build_prefilter lives in patterns.build_prefilter (shared with native_scanner).
_build_prefilter = build_prefilter


def count_source_files(*root_dirs) -> int:
    """Total number of scannable source files across the given roots (for progress bars)."""
    total = 0
    for root in root_dirs:
        if root and Path(root).exists():
            total += sum(1 for _ in _iter_source_files(Path(root)))
    return total


def scan_source_tree(root_dir: Path, patterns=None, max_file_size_bytes=3_000_000,
                     progress=None) -> list[SourceFinding]:
    """Scan every .java/.kt/.smali file under root_dir against all SOURCE_PATTERNS.

    `progress`, if given, is called once per file with no arguments.
    Findings are deduplicated by (pattern_name, file_path, line_number).
    """
    if patterns is None:
        patterns = SOURCE_PATTERNS
    findings: list[SourceFinding] = []
    seen: set[tuple] = set()  # dedup key: (pattern_name, file_path, line_number)
    if root_dir is None or not Path(root_dir).exists():
        return findings

    gate, gated, always_run = _build_prefilter(patterns)
    root_dir = Path(root_dir)
    for file_path in _iter_source_files(root_dir):
        if progress is not None:
            progress()
        try:
            if file_path.stat().st_size > max_file_size_bytes:
                continue  # skip pathological huge generated files
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_no, line in enumerate(f, start=1):
                    # Detection logic is never on a multi-KB line; those are embedded
                    # data blobs (certs, base64, minified arrays) and only make the
                    # regex engine backtrack. Bound the work per line.
                    if len(line) > MAX_LINE_LEN:
                        line = line[:MAX_LINE_LEN]
                    if gate is not None and gate.search(line):
                        candidates = gated + always_run
                    else:
                        candidates = always_run
                    if not candidates:
                        continue
                    for pat in candidates:
                        if pat["regex"].search(line):
                            rel_path = str(file_path.relative_to(root_dir))
                            key = (pat["name"], rel_path, line_no)
                            if key in seen:
                                continue
                            seen.add(key)
                            findings.append(SourceFinding(
                                pattern_name=pat["name"],
                                category=pat["category"],
                                description=pat["description"],
                                confidence=pat["confidence"],
                                file_path=rel_path,
                                line_number=line_no,
                                snippet=line.strip()[:200],
                            ))
        except (OSError, UnicodeDecodeError):
            continue
    return findings


def scan_all_sources(jadx_dir, apktool_dir, progress=None) -> list[SourceFinding]:
    """Convenience wrapper: scan jadx Java output and apktool smali output together.

    Findings are globally deduplicated by (pattern_name, snippet) to avoid double-reporting
    the same check from both jadx and apktool decompiled output.
    """
    findings = []
    seen_global: set[tuple] = set()

    def _add_deduped(new_findings):
        for f in new_findings:
            key = (f.pattern_name, f.snippet)
            if key not in seen_global:
                seen_global.add(key)
                findings.append(f)

    if jadx_dir:
        _add_deduped(scan_source_tree(Path(jadx_dir), progress=progress))
    if apktool_dir:
        smali_root = Path(apktool_dir)
        # apktool_out contains smali/, smali_classes2/, etc. rglob in scan_source_tree
        # already recurses, so just point it at the whole apktool output dir.
        _add_deduped(scan_source_tree(smali_root, progress=progress))
    return findings
