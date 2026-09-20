#!/usr/bin/env python3
"""
DIVINE DEPARTURE -- locate root-detection / integrity-check / anti-tamper mechanisms
in an Android APK or iOS IPA, across both decompiled source and native code.

Usage:
    python main.py -a /path/to/app.apk -o /path/to/output_dir [options]
    python main.py -a /path/to/app.ipa -o /path/to/output_dir [options]

Options:
    -a, --apk         Path to the .apk or .ipa file to analyze (required)
    -o, --output      Output directory for decompiled sources + report (required)
    --skip-java       Skip Java/Kotlin/Smali source scanning (APK only)
    --skip-native     Skip native .so / Mach-O scanning
    --no-banner       Disable the animated intro/outro terminal banners
    --no-progress     Disable the scan progress bars
    --frida-brief     Also emit security_model.json + frida_prompt.md (AI-ready
                      "security mind-map" for Frida bypass-script generation)
    --blutter         Reverse-engineer libapp.so (Flutter apps) via Blutter and scan the
                      Dart assembly / object-pool dumps for security checks
                      (APK only; needs blutter on PATH or BLUTTER_HOME set)
    --patch           Build a pentest-ready APK with the detected checks neutralised
                      (APK only; needs apktool + Android SDK build-tools)
    --keep-manifest   With --patch, do NOT harden AndroidManifest (debuggable / user CAs)

Requires on PATH (auto-discovered): jadx, apktool (APK only).
Requires via pip: pyelftools, capstone  (for native call-site tracing)

Example:
    python main.py -a ./target.apk -o ./scan_target --frida-brief --patch
    python main.py -a ./target.ipa -o ./scan_ipa_out
"""

import argparse
import sys
import time
from pathlib import Path

from decompiler import decompile_apk
from java_scanner import scan_all_sources, count_source_files
from native_scanner import scan_native_dir, count_so_files
from progress import ProgressBar
from report import build_report

# ANSI colors
_PURPLE = "\033[95m"
_CYAN = "\033[96m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_INTRO_ART = r"""
   _____ _____ _    _____ _   _ ______   ____  ______ _____  ___    ____ _______ _    _ _____  ______
  |  __ \_   _| |  / /_ _| \ | |  ____| |  _ \|  ____|  __ \/ _ \  |  _ \__   __| |  | |  __ \|  ____|
  | |  | || | | | | | | ||  \| | |__    | | | | |__  | |__) | |_| | |_) | | |  | |  | | |__) | |__
  | |  | || | | | | | | || . ` |  __|   | | | |  __| |  ___/\__, |  _ <  | |  | |  | |  _  /|  __|
  | |__| || |_| |__/ |_| || |\  | |____  | |__| | |____| |     / /| |_) | | |  | |__| | | \ \| |____
  |_____/_____|_____|___||_| \_|______| |_____/|______|_|    /_/ |____/  |_|   \____/|_|  \_\______|
"""

_OUTRO_ART = r"""
        .  .  .
      .  ~*~  .
    .   /|\    .
       / | \
      /  |  \
   ~~~~~~~~~~~~~
   D I V I N E   D E P A R T U R E
   ~~~~~~~~~~~~~
"""


def _typewriter(text, delay=0.0006):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)


def print_intro_banner():
    print(f"{_PURPLE}{_BOLD}", end="")
    _typewriter(_INTRO_ART, delay=0.0004)
    print(f"{_RESET}{_DIM}{_CYAN}      static root / integrity / anti-tamper locator{_RESET}\n")


def print_outro_banner(total_findings):
    # a slow "glow pulse" simulated with a few redraws in alternating color
    frames = [_CYAN, _PURPLE, _CYAN, _BOLD + _PURPLE]
    for color in frames:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.write(f"{color}  ✦ ✦ ✦  DIVINE DEPARTURE  ✦ ✦ ✦{_RESET}")
        sys.stdout.flush()
        time.sleep(0.15)
    print()
    print(f"{_DIM}{_CYAN}{_OUTRO_ART}{_RESET}")
    print(f"{_BOLD}{_PURPLE}  scan complete -- {total_findings} finding(s) surfaced for review{_RESET}\n")


def parse_args():
    p = argparse.ArgumentParser(
        description="DIVINE DEPARTURE -- locate root-detection / integrity / anti-tamper mechanisms in an APK/IPA."
    )
    p.add_argument("-a", "--apk", required=True, help="Path to the .apk or .ipa file")
    p.add_argument("-o", "--output", required=True, help="Output directory")
    p.add_argument("--skip-java", action="store_true", help="Skip Java/Smali source scanning")
    p.add_argument("--skip-native", action="store_true", help="Skip native .so scanning")
    p.add_argument("--no-banner", action="store_true", help="Disable animated intro/outro banners")
    p.add_argument("--no-progress", action="store_true", help="Disable scan progress bars")
    p.add_argument("--frida-brief", action="store_true",
                   help="Emit security_model.json + frida_prompt.md for AI Frida-script generation")
    p.add_argument("--blutter", action="store_true",
                   help="Reverse-engineer a Flutter app's libapp.so via Blutter and scan the "
                        "resulting Dart assembly / object-pool dumps for security checks "
                        "(APK only; needs blutter on PATH or BLUTTER_HOME set)")
    p.add_argument("--patch", action="store_true",
                   help="Build a pentest-ready APK with detected checks neutralised (rebuild + re-sign)")
    p.add_argument("--keep-manifest", action="store_true",
                   help="With --patch, skip AndroidManifest hardening (debuggable / user-CA trust)")
    return p.parse_args()


# -----------------------------------------------------------------------
# IPA analysis pipeline
# -----------------------------------------------------------------------
def _run_ipa_pipeline(args, apk_path, out_dir):
    """Ghidra-style deep iOS IPA static analysis pipeline."""
    from ios_scanner import scan_ipa, IOSFinding
    from java_scanner import SourceFinding
    from native_scanner import NativeStringFinding

    print(f"[*] Extracting IPA {apk_path.name} ...")
    result = decompile_apk(str(apk_path), str(out_dir))
    for w in result.warnings:
        print(f"    [warn] {w}")

    ipa_dir = result.jadx_dir  # extract_ipa stores output here
    if ipa_dir is None:
        print("[!] Failed to extract IPA.", file=sys.stderr)
        sys.exit(1)

    show_progress = not args.no_progress

    # ── Stage 1: Surface-level MobSF-style analysis ─────────────────────────
    bar = ProgressBar(7, label="    ios surface") if show_progress else None
    print("[*] Stage 1 — Surface analysis (plist / strings / ObjC metadata) ...")
    ios_findings, plist_info, binary_info = scan_ipa(
        Path(ipa_dir), progress=(bar.update if bar else None))
    if bar:
        bar.finish()

    # Print surface summary
    if plist_info:
        print(f"    Bundle:      {plist_info.bundle_id} v{plist_info.version}")
        print(f"    Min iOS:     {plist_info.min_os}")
        if plist_info.permissions:
            print(f"    Permissions: {len(plist_info.permissions)}")
        if plist_info.url_schemes:
            print(f"    URL Schemes: {', '.join(plist_info.url_schemes[:5])}")
        if plist_info.ats_findings:
            for af in plist_info.ats_findings:
                print(f"    [!] ATS: {af}")

    if binary_info:
        flags = []
        if binary_info.has_pie:            flags.append("PIE")
        if binary_info.has_arc:            flags.append("ARC")
        if binary_info.has_stack_canary:   flags.append("StackCanary")
        if binary_info.has_code_signature: flags.append("CodeSign")
        if binary_info.is_encrypted:       flags.append("Encrypted(FairPlay)")
        print(f"    Binary:      {binary_info.name} [{', '.join(binary_info.architectures)}] "
              f"flags=[{', '.join(flags) or 'none'}]")

    print(f"    -> {len(ios_findings)} surface finding(s)")

    # ── Stage 2: Deep Ghidra-style disassembly & call-graph analysis ─────────
    deep_findings_raw = []
    try:
        from ios_deep_analyzer import deep_scan_ipa, DeepFinding
        print("[*] Stage 2 — Deep analysis (ARM64 disasm / CFG / ObjC class hierarchy / "
              "Swift metadata / entitlements / dylib xref) ...")
        bar2 = ProgressBar(10, label="    ios deep   ") if show_progress else None
        deep_findings_raw, deep_warnings = deep_scan_ipa(
            Path(ipa_dir), progress=(bar2.update if bar2 else None))
        if bar2:
            bar2.finish()
        print(f"    -> {len(deep_findings_raw)} deep finding(s) "
              f"(disasm + CFG + ObjC + Swift + entitlements)")
        for w in deep_warnings:
            print(f"    [deep-warn] {w}")
    except ImportError:
        deep_warnings = ["ios_deep_analyzer not available -- deep analysis skipped"]
        print(f"    [warn] {deep_warnings[0]}")

    # ── Merge and deduplicate all findings ───────────────────────────────────
    source_findings = []
    seen_keys: set[tuple] = set()

    def _add_ios_finding(f: "IOSFinding"):
        key = (f.category, (f.snippet or f.title)[:80])
        if key in seen_keys:
            return
        seen_keys.add(key)
        source_findings.append(SourceFinding(
            pattern_name=f.title,
            category=f.category,
            description=f.description,
            confidence=f.severity if f.severity != "info" else "low",
            file_path=f.location,
            line_number=0,
            snippet=f.snippet or "",
        ))

    def _add_deep_finding(f: "DeepFinding"):
        key = (f.category, (f.snippet or f.title)[:80])
        if key in seen_keys:
            return
        seen_keys.add(key)
        source_findings.append(SourceFinding(
            pattern_name=f.title,
            category=f.category,
            description=f.description,
            confidence=f.severity if f.severity != "info" else "low",
            file_path=f.location,
            line_number=f.address,
            snippet=f.snippet or f.calling_function or "",
        ))

    for f in ios_findings:
        _add_ios_finding(f)
    for f in deep_findings_raw:
        _add_deep_finding(f)

    all_warnings = result.warnings + (deep_warnings if 'deep_warnings' in dir() else [])

    print(f"    -> {len(source_findings)} unique findings after deduplication")

    # ── Frida brief ──────────────────────────────────────────────────────────
    security_model = None
    frida_json_name = frida_prompt_name = None
    if args.frida_brief:
        print("[*] Building AI security model / Frida brief ...")
        from security_model import build_security_model
        json_path, prompt_path, security_model = build_security_model(
            apk_name=apk_path.name,
            source_findings=source_findings,
            native_string_findings=[],
            native_callsite_findings=[],
            warnings=all_warnings,
            out_dir=out_dir,
            jadx_dir=str(ipa_dir) if ipa_dir else None,
            apktool_dir=None,
            patch_records=None,
        )
        frida_json_name = json_path.name
        frida_prompt_name = prompt_path.name
        print(f"[+] Security model: {json_path}")
        print(f"[+] Frida prompt:   {prompt_path}")

    # ── Report ───────────────────────────────────────────────────────────────
    report_path = out_dir / "report.html"
    build_report(
        apk_name=apk_path.name,
        source_findings=source_findings,
        native_string_findings=[],
        native_callsite_findings=[],
        warnings=all_warnings,
        out_path=report_path,
        patch_records=None,
        security_model=security_model,
        frida_json_name=frida_json_name,
        frida_prompt_name=frida_prompt_name,
        patched_apk_name=None,
        platform="ios",
    )

    total = len(source_findings)
    print(f"\n[+] Done. {total} total unique findings.")
    print(f"[+] Report: {report_path}")
    return total


# -----------------------------------------------------------------------
# APK analysis pipeline (original)
# -----------------------------------------------------------------------
def _run_apk_pipeline(args, apk_path, out_dir):
    """Android APK analysis pipeline."""
    print(f"[*] Decompiling {apk_path.name} ...")
    result = decompile_apk(str(apk_path), str(out_dir))
    for w in result.warnings:
        print(f"    [warn] {w}")

    show_progress = not args.no_progress

    source_findings = []
    if not args.skip_java:
        n_src = count_source_files(result.jadx_dir, result.apktool_dir)
        print(f"[*] Scanning {n_src} decompiled Java/Kotlin/Smali source files ...")
        bar = ProgressBar(n_src, label="    java/smali") if show_progress else None
        source_findings = scan_all_sources(
            result.jadx_dir, result.apktool_dir,
            progress=(bar.update if bar else None),
        )
        if bar:
            bar.finish()
        print(f"    -> {len(source_findings)} source-level findings")

    native_string_findings, native_callsite_findings = [], []
    native_warnings = []
    if not args.skip_native:
        n_so = count_so_files(result.native_libs_dir)
        print(f"[*] Scanning {n_so} native library file(s) (strings + disassembly) ...")
        bar = ProgressBar(n_so, label="    native .so") if show_progress else None
        native_string_findings, native_callsite_findings, native_warnings = scan_native_dir(
            result.native_libs_dir,
            progress=(bar.update if bar else None),
        )
        if bar:
            bar.finish()
        print(f"    -> {len(native_string_findings)} native string findings, "
              f"{len(native_callsite_findings)} native call-site findings")

    flutter_findings = []
    blutter_warnings = []
    if args.blutter:
        from flutter_scanner import find_flutter_lib_dir, run_blutter, scan_blutter_output, count_blutter_files
        lib_dir = find_flutter_lib_dir(result.native_libs_dir)
        if lib_dir is None:
            print("[*] --blutter: no libapp.so/libflutter.so pair found -- not a Flutter app, skipping.")
        else:
            print(f"[*] Reversing Flutter Dart snapshot via Blutter ({lib_dir.name}) ...")
            blutter_out, warn = run_blutter(lib_dir, out_dir)
            if warn:
                blutter_warnings.append(warn)
                print(f"    [warn] {warn}")
            if blutter_out:
                n_bl = count_blutter_files(blutter_out)
                bar = ProgressBar(n_bl, label="    blutter   ") if show_progress else None
                flutter_findings = scan_blutter_output(blutter_out, progress=(bar.update if bar else None))
                if bar:
                    bar.finish()
                print(f"    -> {len(flutter_findings)} Dart/Flutter findings from Blutter output")
                source_findings.extend(flutter_findings)

    all_warnings = result.warnings + native_warnings + blutter_warnings

    patch_records = None
    final_apk = None
    if args.patch:
        print("[*] Patching APK -- neutralising detected checks, rebuilding, re-signing ...")
        from patcher import patch_apk
        final_apk, patch_records, patch_warnings = patch_apk(
            str(apk_path), str(out_dir), keep_manifest=args.keep_manifest,
        )
        all_warnings += patch_warnings
        for w in patch_warnings:
            print(f"    [patch] {w}")
        if final_apk:
            print(f"[+] Patched APK: {final_apk}")
        else:
            print("[!] Patch stage did not produce an APK (see notes above).")

    security_model = None
    frida_json_name = frida_prompt_name = None
    if args.frida_brief:
        print("[*] Building AI security model / Frida brief ...")
        from security_model import build_security_model
        json_path, prompt_path, security_model = build_security_model(
            apk_name=apk_path.name,
            source_findings=source_findings,
            native_string_findings=native_string_findings,
            native_callsite_findings=native_callsite_findings,
            warnings=all_warnings,
            out_dir=out_dir,
            jadx_dir=result.jadx_dir,
            apktool_dir=result.apktool_dir,
            patch_records=patch_records,
        )
        frida_json_name = json_path.name
        frida_prompt_name = prompt_path.name
        print(f"[+] Security model: {json_path}")
        print(f"[+] Frida prompt:   {prompt_path}")

    patched_apk_name = None
    if final_apk:
        try:
            patched_apk_name = str(Path(final_apk).relative_to(out_dir)).replace("\\", "/")
        except ValueError:
            patched_apk_name = str(final_apk)

    report_path = out_dir / "report.html"
    build_report(
        apk_name=apk_path.name,
        source_findings=source_findings,
        native_string_findings=native_string_findings,
        native_callsite_findings=native_callsite_findings,
        warnings=all_warnings,
        out_path=report_path,
        patch_records=patch_records,
        security_model=security_model,
        frida_json_name=frida_json_name,
        frida_prompt_name=frida_prompt_name,
        patched_apk_name=patched_apk_name,
    )

    total = len(source_findings) + len(native_string_findings) + len(native_callsite_findings)
    print(f"\n[+] Done. {total} total findings.")
    print(f"[+] Report: {report_path}")
    return total


def main():
    args = parse_args()
    apk_path = Path(args.apk)
    out_dir = Path(args.output)

    if not args.no_banner:
        print_intro_banner()

    if not apk_path.exists():
        print(f"[!] File not found: {apk_path}", file=sys.stderr)
        sys.exit(1)

    out_dir.mkdir(parents=True, exist_ok=True)

    is_ipa = apk_path.suffix.lower() == ".ipa"

    if is_ipa:
        if args.patch:
            print("[!] --patch is not supported for IPA files (iOS apps cannot be rebuilt this way).")
        total = _run_ipa_pipeline(args, apk_path, out_dir)
    else:
        total = _run_apk_pipeline(args, apk_path, out_dir)

    if not args.no_banner:
        print_outro_banner(total)


if __name__ == "__main__":
    main()
