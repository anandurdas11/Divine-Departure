"""
flutter_scanner.py

Optional --blutter stage: Flutter apps compile all Dart app logic into libapp.so, so
the jadx/apktool Java/Smali scan never sees it. This module shells out to Blutter
(https://github.com/worawit/blutter) to reverse-engineer the Dart snapshot into
resolved-symbol assembly + object-pool dumps, then greps that output against
patterns.DART_FLUTTER_PATTERNS (+ the generic SOURCE_PATTERNS, since plain strings
like root paths still show up verbatim in the dumped object pool).

Blutter is not pip-installable; the caller must either put a `blutter` launcher on
PATH, or set BLUTTER_HOME to the directory containing blutter.py from the repo.
If neither is available, run_blutter() returns a clear warning instead of failing.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

from java_scanner import SourceFinding
from patterns import DART_FLUTTER_PATTERNS, SOURCE_PATTERNS, build_prefilter

# Preferred ABI order -- blutter's Dart-version detection is most reliable on arm64.
_ABI_PREFERENCE = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"]

_BLUTTER_OUT_EXTENSIONS = {".txt", ".js"}

_PATTERNS = SOURCE_PATTERNS + DART_FLUTTER_PATTERNS
_GATE, _GATED, _ALWAYS_RUN = build_prefilter(_PATTERNS)


def find_flutter_lib_dir(native_libs_dir) -> "Path | None":
    """Locate the lib/<abi>/ dir holding both libapp.so and libflutter.so (Flutter's
    Dart snapshot + engine). Returns None if this isn't a Flutter app."""
    if native_libs_dir is None or not Path(native_libs_dir).exists():
        return None
    native_libs_dir = Path(native_libs_dir)

    candidates = {}
    for so in native_libs_dir.rglob("libapp.so"):
        abi_dir = so.parent
        if (abi_dir / "libflutter.so").is_file():
            candidates[abi_dir.name] = abi_dir

    for abi in _ABI_PREFERENCE:
        if abi in candidates:
            return candidates[abi]
    return next(iter(candidates.values()), None)


def _resolve_blutter():
    """Return an argv prefix that launches blutter.py, or None if unavailable."""
    path = shutil.which("blutter")
    if path:
        if os.name == "nt" and path.lower().endswith((".bat", ".cmd")):
            return ["cmd", "/c", path]
        return [path]

    blutter_home = os.environ.get("BLUTTER_HOME")
    if blutter_home:
        script = Path(blutter_home) / "blutter.py"
        if script.is_file():
            return [sys.executable, str(script)]
    return None


def run_blutter(lib_dir: Path, out_dir: Path, timeout=900) -> tuple["Path | None", "str | None"]:
    """Run blutter against lib_dir (a lib/<abi>/ directory), producing <out_dir>/blutter_out/.

    Returns (blutter_out_dir, warning). blutter_out_dir is returned even on partial/failed
    runs if it has any content, matching the jadx/apktool best-effort pattern.
    """
    tool = _resolve_blutter()
    if tool is None:
        return None, (
            "blutter not found -- skipping Flutter Dart analysis. Install from "
            "https://github.com/worawit/blutter and either put a `blutter` launcher on "
            "PATH or set BLUTTER_HOME to the directory containing blutter.py"
        )

    blutter_out = out_dir / "blutter_out"
    blutter_out.mkdir(parents=True, exist_ok=True)
    cmd = tool + [str(lib_dir), str(blutter_out)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0 and not any(blutter_out.rglob("*")):
            err = (proc.stderr or proc.stdout or "").strip()[-500:]
            return None, f"blutter failed (exit {proc.returncode}): {err}"
    except subprocess.TimeoutExpired:
        return blutter_out, f"blutter timed out after {timeout}s -- partial output may still be usable"
    except Exception as e:
        return None, f"blutter failed: {e}"

    if not any(blutter_out.rglob("*")):
        return None, "blutter produced no output -- unsupported Dart/Flutter version or bad input?"
    return blutter_out, None


def count_blutter_files(blutter_dir) -> int:
    if blutter_dir is None or not Path(blutter_dir).exists():
        return 0
    return sum(1 for p in Path(blutter_dir).rglob("*")
               if p.suffix in _BLUTTER_OUT_EXTENSIONS and p.is_file())


def scan_blutter_output(blutter_dir: Path, progress=None,
                         max_file_size_bytes=8_000_000) -> list[SourceFinding]:
    """Scan Blutter's asm/*.txt, objs.txt, pp.txt (and blutter_frida.js) for security-check
    signatures. Findings are deduplicated by (pattern_name, file_path, line_number)."""
    findings: list[SourceFinding] = []
    seen: set[tuple] = set()
    if blutter_dir is None or not Path(blutter_dir).exists():
        return findings
    blutter_dir = Path(blutter_dir)

    for file_path in sorted(blutter_dir.rglob("*")):
        if not file_path.is_file() or file_path.suffix not in _BLUTTER_OUT_EXTENSIONS:
            continue
        if progress is not None:
            progress()
        try:
            if file_path.stat().st_size > max_file_size_bytes:
                continue
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_no, line in enumerate(f, start=1):
                    if len(line) > 2000:
                        line = line[:2000]
                    if _GATE is not None and _GATE.search(line):
                        candidates = _GATED + _ALWAYS_RUN
                    else:
                        candidates = _ALWAYS_RUN
                    for pat in candidates:
                        if pat["regex"].search(line):
                            rel_path = "blutter_out/" + str(file_path.relative_to(blutter_dir)).replace("\\", "/")
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
