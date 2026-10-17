"""
security_model.py

Distils every static finding into a compact, structured "security model" of the target
app -- the defensive mechanisms it ships, where they live, and which classes/methods are
the highest-value hook points -- then serialises it two ways:

    security_model.json   machine-readable, for tooling / diffing / feeding to an LLM
    frida_prompt.md       a ready-to-paste prompt that embeds the model and asks an AI
                          to emit ONE consolidated Frida bypass script

The point is not to write the Frida script here (that is the LLM's job, with human
review) -- it is to hand the model everything it needs: real class names, real method
names, real file:line anchors, and category-level hints.
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from report import CATEGORY_LABELS, ALL_CATEGORIES

_CONF_RANK = {"high": 3, "medium": 2, "low": 1, "": 0, None: 0}

# Category-level scaffolding the LLM can lean on when no precise hook candidate exists.
GENERIC_FRIDA_HINTS = {
    "ROOT_DETECTION": [
        "Hook java.io.File.exists() and return false for paths containing 'su', 'magisk', 'busybox', 'superuser'.",
        "Hook java.lang.Runtime.exec() / ProcessBuilder.start() and neutralise 'su', 'which su', 'busybox'.",
        "If com.scottyab.rootbeer.RootBeer is present, force isRooted()/isRootedWithoutBusyBoxCheck() to false.",
        "Hook android.app.ApplicationPackageManager.getPackageInfo() to hide Magisk/Superuser packages.",
    ],
    "INTEGRITY_CHECK": [
        "Hook PackageManager.getPackageInfo(..., GET_SIGNATURES / GET_SIGNING_CERTIFICATES) to return the original signature bytes.",
        "Force SafetyNet / Play Integrity result handlers down their success path, or stub the verdict parser.",
        "Hook getInstallerPackageName() to return 'com.android.vending'.",
    ],
    "ANTI_DEBUG": [
        "Hook android.os.Debug.isDebuggerConnected()/waitingForDebugger() -> false.",
        "Hook the app's own TracerPid readers of /proc/self/status to report TracerPid: 0.",
    ],
    "ANTI_HOOK": [
        "Hook File/maps/status readers to strip lines containing 'frida', 'gum', 'gadget', 'xposed'.",
        "Hook Socket.connect() and drop connects to ports 27042/27043.",
    ],
    "EMULATOR_DETECT": [
        "Spoof android.os.Build fields (FINGERPRINT, MODEL, MANUFACTURER, PRODUCT, HARDWARE) to a real device profile.",
        "Hook SystemProperties.get() for ro.kernel.qemu / ro.hardware -> benign values.",
    ],
    "MDM_CHECK": [
        "Hook DevicePolicyManager.isDeviceOwnerApp()/isProfileOwnerApp()/isManagedProfile()/getActiveAdmins() -> false / empty.",
        "Hook UserManager.hasUserRestriction() -> false and getUserProfiles() -> single profile.",
        "Hook RestrictionsManager.getApplicationRestrictions() -> empty Bundle.",
        "If a Knox/AirWatch/Intune/MobileIron SDK class is referenced, stub its 'isManaged'/'isEnrolled' entry points.",
    ],
    "SSL_PINNING": [
        "okhttp3.CertificatePinner.check() -> return (no-op).",
        "Replace the app's X509TrustManager.checkServerTrusted() with a no-op; feed a permissive TrustManager into SSLContext.init().",
        "javax.net.ssl.HostnameVerifier.verify() -> true; HttpsURLConnection.setDefaultHostnameVerifier(allowAll).",
        "com.android.org.conscrypt.TrustManagerImpl.verifyChain() / checkTrustedRecursive() -> return the passed chain.",
        "com.datatheorem.android.trustkit and appmattus CertificateTransparency interceptors -> bypass.",
    ],
    "RASP_DETECTION": [
        "Most RASP SDKs (Appdome, Promon, DexGuard) rely heavily on native code and inline syscalls. Standard framework hooks may be bypassed.",
        "Hook early in the app lifecycle: trace 'attachBaseContext' or early 'ContentProvider' initializations.",
        "Hook native JNI functions early (e.g., JNI_OnLoad, RegisterNatives) to intercept the RASP setup phase.",
        "Look for custom ClassLoaders and dynamically loaded DEX files typically used by app shielders."
    ],
    "HARDCODED_SECRETS": [
        "Audit hardcoded secrets: verify if credentials are active / valid on staging or production endpoints.",
        "Hook API request dispatchers to inspect whether hardcoded keys are passed in Authorization headers or query params.",
        "Rotate compromised keys and migrate secrets to Android Keystore / backend token exchange.",
    ],
    "ENFORCEMENT": [
        "Hook consequences, not checks: neutralising the single point where a verdict becomes an action disables every upstream detector at once (§0).",
        "Prefer a launch gate / boolean gate: force it to its genuine value (return false for 'is tampered?') rather than blocking the exit, which can leave a half-initialised process stuck at splash (§4).",
        "For terminal actions, keep a termination TRACER on (print a backtrace on System.exit/Runtime.exit/killProcess and on libc exit/_exit/abort/tgkill) to prove the real gate before neutralising it (§7).",
        "Hook libc EXPORTS via Module.findExportByName(null, sym) -- packed RASP libs resolve libc at runtime so callsite patching is unreliable; an inline svc syscall needs raw-syscall/trampoline hooking (§8).",
        "When code is loaded dynamically (secondary DEX / reflection), install launch-critical hooks just-in-time across every classloader before onCreate runs (§3, §6).",
    ],
}

# Directory prefixes that jadx / apktool prepend and that are not part of the class name.
_STRIP_PREFIXES = ("sources/", "sources\\", "smali/", "smali\\")
_SMALI_MULTIDEX_RE = re.compile(r"^smali_classes\d+[/\\]", re.IGNORECASE)

# In-memory caches to accelerate repeated file queries across hundreds of findings
_FILE_LINES_CACHE = {}          # str(Path) -> list[str]
_FILE_TEXT_CACHE = {}           # str(Path) -> str
_ENCLOSING_METHOD_CACHE = {}    # (str(Path), line_number) -> str
_RESOLVE_PATH_CACHE = {}        # rel_path -> Path | None
_SMALI_FILE_CACHE = {}          # (candidate_rel, tuple(smali_dirs)) -> (sfile, multidex, verified)
_SMALI_DESC_CACHE = {}


def clear_cache():
    """Clear in-memory caches between runs."""
    _FILE_LINES_CACHE.clear()
    _FILE_TEXT_CACHE.clear()
    _ENCLOSING_METHOD_CACHE.clear()
    _RESOLVE_PATH_CACHE.clear()
    _SMALI_FILE_CACHE.clear()
    _SMALI_DESC_CACHE.clear()


def _get_file_lines(abs_path: Path) -> list:
    key = str(abs_path)
    if key not in _FILE_LINES_CACHE:
        try:
            _FILE_LINES_CACHE[key] = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            _FILE_LINES_CACHE[key] = []
    return _FILE_LINES_CACHE[key]


def _get_file_text(abs_path: Path) -> str:
    key = str(abs_path)
    if key not in _FILE_TEXT_CACHE:
        try:
            _FILE_TEXT_CACHE[key] = abs_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            _FILE_TEXT_CACHE[key] = ""
    return _FILE_TEXT_CACHE[key]


# Hook candidates in these packages are almost always library noise, not the app's
# own anti-tamper code -- keep them, but rank them below first-party classes and
# cap how many make it into the model / prompt.
_LIB_FQCN_PREFIXES = (
    "android.", "androidx.", "kotlin.", "kotlinx.", "java.", "javax.", "org.jetbrains.",
    "okhttp3.", "okio.", "retrofit2.", "com.google.", "com.squareup.", "org.bouncycastle.",
    "org.conscrypt.", "com.android.org.conscrypt.", "io.reactivex.", "rx.", "org.apache.",
    "dagger.", "com.facebook.", "io.flutter.", "com.airbnb.",
)
_MAX_CANDIDATES_PER_CATEGORY = 25


def _is_lib(fqcn: str) -> bool:
    return fqcn.startswith(_LIB_FQCN_PREFIXES)


def _fqcn_from_path(rel_path: str) -> str:
    p = rel_path.replace("\\", "/")
    p = _SMALI_MULTIDEX_RE.sub("", p)
    for pre in ("sources/", "smali/"):
        if p.startswith(pre):
            p = p[len(pre):]
    for ext in (".smali", ".java", ".kt"):
        if p.endswith(ext):
            p = p[: -len(ext)]
    p = p.split("$", 1)[0]           # outer class, drop inner-class suffix
    return p.strip("/").replace("/", ".")


_SMALI_METHOD_RE = re.compile(r"^\s*\.method\b.*?\s([\w$<>]+)\(")
_JAVA_METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|synchronized|native|abstract|\s)+"
    r"[\w<>\[\].,?\s]+?\s([\w$]+)\s*\([^;{]*\)\s*(?:throws[\w,.\s]+)?\{?\s*$"
)


def _enclosing_method(abs_path: Path, line_number: int) -> str:
    """Best-effort: scan backwards from `line_number` for the enclosing method name."""
    if not abs_path:
        return ""
    cache_key = (str(abs_path), line_number)
    if cache_key in _ENCLOSING_METHOD_CACHE:
        return _ENCLOSING_METHOD_CACHE[cache_key]

    lines = _get_file_lines(abs_path)
    if not lines:
        _ENCLOSING_METHOD_CACHE[cache_key] = ""
        return ""

    idx = min(max(line_number - 1, 0), len(lines) - 1)
    is_smali = abs_path.suffix == ".smali"
    found = ""
    start_idx = max(0, idx - 150)
    for k in range(idx, start_idx - 1, -1):
        row = lines[k]
        if "(" not in row:
            if is_smali and row.lstrip().startswith(".end method"):
                break
            continue
        if is_smali:
            if ".method" in row:
                m = _SMALI_METHOD_RE.match(row)
                if m:
                    found = m.group(1)
                    break
            elif row.lstrip().startswith(".end method"):
                break   # we walked out of a method without seeing its header
        else:
            m = _JAVA_METHOD_RE.match(row)
            if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "new"):
                found = m.group(1)
                break
    _ENCLOSING_METHOD_CACHE[cache_key] = found
    return found


# =======================================================================
# Enforcement-aware enrichment (see BYPASS_METHODOLOGY.md)
# -----------------------------------------------------------------------
# §5  Runtime-vs-decompiler names: jadx sanitises class names; Frida needs
#     the runtime (dex/smali) name. De-prefix the jadx spelling, prefer a
#     jadx "renamed from" comment, and verify against the authoritative
#     smali when apktool output is available.
# §0/§9  Classify each candidate by the ROLE it plays in enforcement and
#     rank it so the generator hooks consequences (gates / terminal
#     actions) before individual detectors.
# =======================================================================

# jadx prefixes that are NOT part of the runtime name.
_P_PREFIX_RE = re.compile(r"^p\d+(?=[A-Za-z])")          # p127l5 -> l5
_C_COLLISION_RE = re.compile(r"^C\d+(?=[A-Za-z_])")      # C0998u -> u
_JADX_RENAMED_RE = re.compile(r"renamed from:\s*['\"]?([\w./$]+)")

# pattern_name -> (role, enforcement_rank). Lower rank = hook earlier (§0).
_TERMINAL_PATTERNS = {"enf_system_exit", "enf_kill_process"}
_REACTION_PATTERNS = {
    "enf_block_dialog", "enf_home_eviction", "enf_flag_secure",
    "enf_clear_app_data", "enf_clear_prefs", "enf_verdict_value_object",
    "enf_reflective_dispatch",
}
_DYNAMIC_PATTERNS = {"enf_dynamic_classloader", "enf_reflective_invoke", "enf_native_dex_load"}
_GATE_HINT_PATTERNS = {"enf_gate_signature_hint"}
# Native libc exports that are terminal actions when seen as enforcement.
_NATIVE_TERMINAL_SYMS = {"_exit", "_Exit", "exit", "abort", "tgkill", "pthread_kill", "raise"}


def _classify_enforcement(pattern_name, category):
    """Return (role, enforcement_rank) per §0 priority order."""
    if pattern_name == "enf_launch_gate":
        return "launch_gate", 1
    if pattern_name in _TERMINAL_PATTERNS:
        return "terminal_action", 1
    if pattern_name in _GATE_HINT_PATTERNS:
        return "boolean_gate", 3
    if pattern_name in _REACTION_PATTERNS:
        return "reaction_dispatch", 2
    if pattern_name in _DYNAMIC_PATTERNS:
        return "dynamic_loader", 2
    if category == "HARDCODED_SECRETS":
        return "credential_secret", 5
    return "detector", 4


def _desanitize_fqcn(jadx_fqcn):
    """Strip jadx `p<NNN>` / `C<digits>` sanitisation prefixes segment-wise (§5)."""
    out = []
    for seg in jadx_fqcn.split("."):
        seg = _P_PREFIX_RE.sub("", seg)
        seg = _C_COLLISION_RE.sub("", seg)
        out.append(seg)
    return ".".join(out)


def _smali_dirs(apktool_dir):
    if not apktool_dir:
        return []
    base = Path(apktool_dir)
    dirs = []
    if (base / "smali").is_dir():
        dirs.append((base / "smali", 1))
    for d in sorted(base.glob("smali_classes*")):
        if d.is_dir():
            n = re.search(r"smali_classes(\d+)", d.name)
            dirs.append((d, int(n.group(1)) if n else 2))
    return dirs


def _resolve_runtime(jadx_fqcn, method, abs_path, smali_dirs):
    """
    Resolve the runtime class name + smali descriptor for a jadx candidate (§5).

    Returns dict(runtime_class, smali_descriptor, multidex, name_verified).
    Falls back gracefully to the de-prefixed jadx name when no smali is present.
    """
    candidate = _desanitize_fqcn(jadx_fqcn)
    rel = candidate.replace(".", "/")
    runtime_class = candidate
    descriptor = ""
    multidex = False
    verified = False

    # 1. Authoritative: find the class in decoded smali (unsanitised by design).
    sdir_key = tuple(str(d) for d, _ in smali_dirs)
    cache_key = (rel, sdir_key)
    if cache_key in _SMALI_FILE_CACHE:
        sfile, multidex, verified = _SMALI_FILE_CACHE[cache_key]
    else:
        sfile = None
        for sdir, idx in smali_dirs:
            cand_sfile = sdir / (rel + ".smali")
            if cand_sfile.is_file():
                sfile = cand_sfile
                multidex = idx >= 2
                verified = True
                break
        _SMALI_FILE_CACHE[cache_key] = (sfile, multidex, verified)

    if verified and sfile:
        if method:
            desc_key = (str(sfile), method)
            descriptor = _SMALI_DESC_CACHE.get(desc_key)
            if descriptor is None:
                descriptor = ""
                stext = _get_file_text(sfile)
                if stext:
                    mre = re.compile(
                        r"^\.method\b[^\n]*\b" + re.escape(method) + r"\(([^)]*)\)(\S+)",
                        re.MULTILINE)
                    m = mre.search(stext)
                    if m:
                        descriptor = f"L{rel};->{method}({m.group(1)}){m.group(2)}"
                _SMALI_DESC_CACHE[desc_key] = descriptor

    # 2. Not in smali: honour a jadx "renamed from" comment if the source shows one.
    if not verified and abs_path is not None:
        txt = _get_file_text(abs_path)
        if txt:
            m = _JADX_RENAMED_RE.search(txt)
            if m:
                real = m.group(1).strip().rstrip(";").lstrip("L").replace("/", ".")
                if real:
                    pkg = jadx_fqcn.rsplit(".", 1)[0] if "." in jadx_fqcn else ""
                    runtime_class = f"{pkg}.{real}" if pkg and "." not in real else real

    return dict(runtime_class=runtime_class, smali_descriptor=descriptor,
                multidex=multidex, name_verified=verified)


def _scan_launch_gate(apktool_dir, jadx_dir):
    """
    §4 launch-gate scan: locate the <application android:name> class and look for a
    one-line integrity gate guarding a terminal action inside it. Returns a
    chokepoint dict or None. Best-effort; never raises into the caller.
    """
    try:
        base = Path(apktool_dir) if apktool_dir else None
        if base is None:
            return None
        manifest = base / "AndroidManifest.xml"
        if not manifest.is_file():
            return None
        mtext = manifest.read_text(encoding="utf-8", errors="ignore")
        m = re.search(r"<application[^>]*\bandroid:name\s*=\s*\"([^\"]+)\"", mtext)
        if not m:
            return None
        app_class = m.group(1).lstrip(".")
        if app_class.startswith("."):
            app_class = app_class[1:]
        # Resolve against package when the name is relative.
        pkg_m = re.search(r"\bpackage\s*=\s*\"([^\"]+)\"", mtext)
        if "." not in app_class and pkg_m:
            app_class = f"{pkg_m.group(1)}.{app_class}"
        rel = app_class.replace(".", "/")
        gate_re = re.compile(
            r"if\s*\(\s*([\w.$]+)\s*\(\s*this\s*\)\s*\)\s*\{\s*"
            r"(System\s*\.\s*exit|[\w.$]*killProcess|[\w.$]*exitProcess)")
        for sdir, _ in _smali_dirs(apktool_dir):
            sfile = sdir / (rel + ".smali")
            if sfile.is_file():
                return dict(
                    role="launch_gate", enforcement_rank=1,
                    runtime_class=app_class,
                    source=f"{sfile.relative_to(base)}",
                    evidence=f"Application class {app_class} (verify onCreate/attachBaseContext for an integrity gate)",
                    note="Application-class gate: force the gate boolean to its genuine value rather than blocking the exit (§4).")
        # Fall back to jadx source if smali unavailable.
        if jadx_dir:
            jfile = Path(jadx_dir) / "sources" / (rel + ".java")
            if jfile.is_file():
                txt = jfile.read_text(encoding="utf-8", errors="ignore")
                g = gate_re.search(txt)
                if g:
                    return dict(
                        role="launch_gate", enforcement_rank=1,
                        runtime_class=app_class,
                        gate_call=g.group(1), terminal=g.group(2),
                        source=f"sources/{rel}.java",
                        evidence=f"{app_class}: if ({g.group(1)}(this)) {{ {g.group(2)}(...) }}",
                        return_to_force=False,
                        note="Launch gate found in Application class; force the gate boolean false (§4).")
    except Exception:
        return None
    return None


def build_security_model(apk_name, source_findings, native_string_findings,
                         native_callsite_findings, warnings, out_dir,
                         jadx_dir=None, apktool_dir=None, patch_records=None):
    clear_cache()
    out_dir = Path(out_dir)
    roots = [Path(d) for d in (jadx_dir, apktool_dir) if d]
    smali_dirs = _smali_dirs(apktool_dir)

    def _resolve(rel):
        if rel in _RESOLVE_PATH_CACHE:
            return _RESOLVE_PATH_CACHE[rel]
        for r in roots:
            cand = r / rel
            if cand.is_file():
                _RESOLVE_PATH_CACHE[rel] = cand
                return cand
        _RESOLVE_PATH_CACHE[rel] = None
        return None

    by_cat = defaultdict(list)
    for f in source_findings:
        by_cat[f.category].append(f)

    # §3: does the app load code dynamically (secondary DEX / reflection)? If so a
    # static class list is insufficient and launch-critical hooks need deferred/JIT
    # installation (§6). Flagged per-candidate as requires_deferred_hook.
    dynamic_loading_detected = any(
        f.pattern_name in _DYNAMIC_PATTERNS for f in by_cat.get("ENFORCEMENT", [])
    )

    mechanisms = []
    for cat in ALL_CATEGORIES:
        items = by_cat.get(cat, [])
        if not items:
            continue
        # de-dup hook candidates by (class, method)
        seen = {}
        for f in items:
            fqcn = _fqcn_from_path(f.file_path)
            abs_path = _resolve(f.file_path)
            method = _enclosing_method(abs_path, f.line_number) if abs_path else ""
            key = (fqcn, method)
            cand = seen.get(key)
            if cand is None or _CONF_RANK[f.confidence] > _CONF_RANK[cand["confidence"]]:
                role, rank = _classify_enforcement(f.pattern_name, cat)
                rt = _resolve_runtime(fqcn, method, abs_path, smali_dirs)
                requires_deferred = rt["multidex"] or (
                    dynamic_loading_detected and role in ("launch_gate", "terminal_action"))
                entry = dict(
                    java_class=fqcn,
                    runtime_class=rt["runtime_class"],
                    smali_descriptor=rt["smali_descriptor"],
                    name_verified=rt["name_verified"],
                    method_hint=method,
                    frida_use=f'Java.use("{rt["runtime_class"]}")',
                    role=role,
                    enforcement_rank=rank,
                    requires_deferred_hook=requires_deferred,
                    source=f"{f.file_path}:{f.line_number}",
                    evidence=f"{f.file_path}:{f.line_number} -> {f.pattern_name}",
                    signature=f.pattern_name,
                    confidence=f.confidence,
                    snippet=f.snippet[:120],
                )
                if role in ("launch_gate", "boolean_gate"):
                    entry["return_to_force"] = False   # force the gate to its genuine value
                seen[key] = entry
        candidates = sorted(
            seen.values(),
            key=lambda c: (c["enforcement_rank"],                  # consequences before detectors
                           _is_lib(c["java_class"]),               # first-party first
                           -_CONF_RANK[c["confidence"]],           # then high confidence
                           c["java_class"]),
        )
        conf_max = max((c["confidence"] for c in candidates), key=lambda c: _CONF_RANK[c], default="low")
        shown = candidates[:_MAX_CANDIDATES_PER_CATEGORY]
        mechanisms.append(dict(
            category=cat,
            label=CATEGORY_LABELS[cat],
            finding_count=len(items),
            confidence_max=conf_max,
            hook_candidates=shown,
            hook_candidates_omitted=max(len(candidates) - len(shown), 0),
            generic_frida_hints=GENERIC_FRIDA_HINTS.get(cat, []),
        ))

    native = []
    for f in native_callsite_findings:
        entry = dict(kind="callsite", library=Path(f.so_path).name,
                     category=f.category, symbol=f.imported_symbol,
                     function=f.calling_function,
                     address=f"0x{f.call_instruction_address:x}",
                     confidence=f.confidence, description=f.description)
        if f.imported_symbol in _NATIVE_TERMINAL_SYMS or f.category == "ENFORCEMENT":
            entry["role"] = "terminal_action"
            entry["enforcement_rank"] = 1
            # §8: packed RASP libs resolve libc at runtime -- hook the EXPORT, not a callsite.
            entry["frida_hook"] = f'Interceptor.attach(Module.findExportByName(null, "{f.imported_symbol}"), ...)'
        native.append(entry)
    for f in native_string_findings:
        native.append(dict(kind="string", library=Path(f.so_path).name,
                           category=f.category, signature=f.pattern_name,
                           offset=f"0x{f.file_offset:x}", matched=f.matched_string,
                           confidence=f.confidence))

    by_category_counts = {CATEGORY_LABELS[c]: len(by_cat.get(c, [])) for c in ALL_CATEGORIES
                          if by_cat.get(c)}

    native_cats = {d["category"] for d in native if d.get("category")}
    categories_present = [CATEGORY_LABELS[c] for c in ALL_CATEGORIES
                          if by_cat.get(c) or c in native_cats]

    # -------------------------------------------------------------------
    # §0/§9: a single ranked list of enforcement chokepoints -- the places
    # where a failed verdict becomes an action. Hook these (rank 1 first)
    # to neutralise every upstream detector at once, rather than hooking
    # N detectors. Gathered from every category's candidates + native
    # terminal actions + the Application launch-gate scan.
    # -------------------------------------------------------------------
    chokepoints = []
    for mech in mechanisms:
        for c in mech["hook_candidates"]:
            if c.get("role") in ("launch_gate", "terminal_action", "reaction_dispatch",
                                  "boolean_gate", "dynamic_loader"):
                chokepoints.append(dict(
                    role=c["role"], enforcement_rank=c["enforcement_rank"],
                    runtime_class=c["runtime_class"], method_hint=c["method_hint"],
                    smali_descriptor=c.get("smali_descriptor", ""),
                    requires_deferred_hook=c.get("requires_deferred_hook", False),
                    return_to_force=c.get("return_to_force"),
                    confidence=c["confidence"], source=c["source"],
                    category=mech["category"]))
    for d in native:
        if d.get("role") == "terminal_action":
            chokepoints.append(dict(
                role="terminal_action", enforcement_rank=1,
                symbol=d["symbol"], library=d["library"],
                frida_hook=d.get("frida_hook"), confidence=d["confidence"],
                source=f'{d["library"]}@{d.get("address", "?")}', category="ENFORCEMENT"))

    launch_gate = _scan_launch_gate(apktool_dir, jadx_dir)
    if launch_gate:
        chokepoints.insert(0, launch_gate)

    chokepoints.sort(key=lambda c: (c["enforcement_rank"],
                                     -_CONF_RANK.get(c.get("confidence"), 0)))

    model = dict(
        target=dict(apk=apk_name, generated=datetime.now().isoformat(timespec="seconds")),
        summary=dict(
            total_source_findings=len(source_findings),
            total_native_findings=len(native_string_findings) + len(native_callsite_findings),
            categories_present=categories_present,
            by_category=by_category_counts,
        ),
        enforcement_chokepoints=chokepoints,
        dynamic_code_loading=dynamic_loading_detected,
        defense_mechanisms=mechanisms,
        native_libraries=native,
        patched=bool(patch_records),
        patch_log=patch_records or [],
        tool_warnings=warnings,
        disclaimer=(
            "Static model. Class/method hints are heuristic (derived from decompiled paths "
            "and nearby method headers) and MUST be verified. `runtime_class` is the "
            "de-sanitised name for Frida; when `name_verified` is false it was not confirmed "
            "against smali -- re-check before hooking. Reflection, native, packed, and "
            "server-side attestation logic will be under-represented; prefer the ranked "
            "`enforcement_chokepoints` over per-detector hooks."
        ),
    )

    json_path = out_dir / "security_model.json"
    json_path.write_text(json.dumps(model, indent=2), encoding="utf-8")

    prompt_path = out_dir / "frida_prompt.md"
    prompt_path.write_text(_render_prompt(model), encoding="utf-8")

    # Generate dedicated security_mind_map.json
    mindmap_data = build_security_mindmap_data(model, source_findings, native_string_findings, native_callsite_findings)
    mindmap_json_path = out_dir / "security_mind_map.json"
    mindmap_json_path.write_text(json.dumps(mindmap_data, indent=2), encoding="utf-8")

    model["mindmap_data"] = mindmap_data
    model["mindmap_json_name"] = "security_mind_map.json"

    return json_path, prompt_path, model


def build_security_mindmap_data(model, source_findings, native_string_findings, native_callsite_findings):
    """
    Build a hierarchical, D3-compatible mind map data structure representing the
    application security posture, defense mechanisms, secrets, and enforcement chokepoints.
    """
    apk_name = model.get("target", {}).get("apk", "Target Application")
    total_findings = (
        model.get("summary", {}).get("total_source_findings", 0) +
        model.get("summary", {}).get("total_native_findings", 0)
    )
    root = {
        "name": apk_name,
        "category": "root",
        "full_name": apk_name,
        "details": f"Target: {apk_name} | Total Findings: {total_findings}",
        "children": []
    }

    # 1. Enforcement Chokepoints cluster
    chokepoints = model.get("enforcement_chokepoints", [])
    if chokepoints:
        cp_children = []
        for cp in chokepoints:
            role = cp.get("role", "chokepoint")
            rank = cp.get("enforcement_rank", 1)
            rt_class = cp.get("runtime_class") or cp.get("symbol") or "Unknown"
            method = cp.get("method_hint") or cp.get("library") or ""
            frida_code = cp.get("frida_hook") or (
                f'Java.use("{rt_class}").{method}.implementation = ...' if method else f'Java.use("{rt_class}")'
            )
            cp_children.append({
                "name": f"{rt_class.split('.')[-1]}.{method}" if method else rt_class.split('.')[-1],
                "full_name": f"[{role.upper()}] {rt_class} ({method or 'all'})",
                "category": "ENFORCEMENT",
                "val": frida_code,
                "details": f"Role: {role} (Rank {rank}) | Source: {cp.get('source', '')} | Conf: {cp.get('confidence', 'medium')}",
                "snippet": cp.get("evidence", "")
            })
        root["children"].append({
            "name": f"Enforcement Chokepoints ({len(cp_children)})",
            "category": "ENFORCEMENT",
            "full_name": "Enforcement Chokepoints (Launch Gates, Kill Switches, Reactions)",
            "details": "High-value hook points where failed verdicts trigger terminal or defensive actions.",
            "children": cp_children
        })

    # 2. Defense Mechanisms & Secrets by Category
    mechs = model.get("defense_mechanisms", [])
    for m in mechs:
        cat = m.get("category", "")
        label = m.get("label", cat)
        cands = m.get("hook_candidates", [])
        if not cands:
            continue
        cat_children = []
        for c in cands:
            method = c.get("method_hint") or ""
            cls_name = c.get("runtime_class") or c.get("java_class", "")
            display_name = f"{cls_name.split('.')[-1]}.{method}" if method else cls_name.split('.')[-1]
            cat_children.append({
                "name": display_name or cls_name,
                "full_name": f"{cls_name}.{method}" if method else cls_name,
                "category": cat,
                "val": c.get("frida_use", f'Java.use("{cls_name}")'),
                "details": f"Signature: {c.get('signature', '')} | Method: {method or 'N/A'} | Descriptor: {c.get('smali_descriptor', 'N/A')} | Conf: {c.get('confidence', '')}",
                "snippet": c.get("snippet", ""),
                "file": c.get("source", "")
            })
        root["children"].append({
            "name": f"{label} ({len(cat_children)})",
            "category": cat,
            "full_name": label,
            "details": f"Detected {m.get('finding_count', len(cat_children))} indicators across {len(cat_children)} hook candidates.",
            "children": cat_children
        })

    # 3. Native Binaries
    native_libs = model.get("native_libraries", [])
    if native_libs:
        libs_grouped = defaultdict(list)
        for n in native_libs:
            libs_grouped[n.get("library", "Unknown.so")].append(n)
        native_children = []
        for lib_name, items in libs_grouped.items():
            sub_children = []
            for it in items:
                sym = it.get("symbol") or it.get("signature") or (it.get("matched", "")[:30])
                kind = it.get("kind", "native")
                sub_children.append({
                    "name": f"{kind}: {sym}",
                    "full_name": f"{lib_name} -> {sym}",
                    "category": it.get("category", "ENFORCEMENT"),
                    "val": it.get("frida_hook") or f"Offset/Addr: {it.get('address') or it.get('offset', '')}",
                    "details": f"Kind: {kind} | Category: {it.get('category')} | Func: {it.get('function', '')} | Conf: {it.get('confidence', '')}",
                    "snippet": it.get("matched") or it.get("description", "")
                })
            native_children.append({
                "name": f"{lib_name} ({len(sub_children)})",
                "category": "NATIVE",
                "full_name": f"Shared Library: {lib_name}",
                "details": f"Contains {len(sub_children)} native checks / symbols.",
                "children": sub_children
            })
        root["children"].append({
            "name": f"Native Binaries ({len(native_libs)})",
            "category": "NATIVE",
            "full_name": "Native Libraries (.so / Mach-O)",
            "details": f"Native binary findings across {len(libs_grouped)} shared libraries.",
            "children": native_children
        })

    return root


def _render_prompt(model) -> str:
    cats = ", ".join(model["summary"]["categories_present"]) or "none detected"
    n_choke = len(model.get("enforcement_chokepoints", []))
    dyn = model.get("dynamic_code_loading", False)
    return f"""# Frida bypass script generation -- task brief

You are a senior mobile application security engineer performing an **authorised**
penetration test on an app you have permission to assess. Using the static security
model below, write **one consolidated Frida script** (JavaScript, for `frida` /
`objection`) that disables the defensive mechanisms it describes so the app can be
dynamically analysed on a rooted device / emulator behind an intercepting proxy.

## Strategy -- hook consequences, not checks (read first)

This model ranks **{n_choke} enforcement chokepoints** in `enforcement_chokepoints`
(sorted by `enforcement_rank`, 1 = highest value). A RASP app has many detectors but
very few points where a failed verdict becomes an *action*. Neutralise those and every
upstream detector is moot. Hook order:

1. **`enforcement_rank: 1`** -- `launch_gate` and `terminal_action`. For a gate with
   `return_to_force: false`, force the gate method to return that value (its genuine
   result) -- this is cleaner than blocking the exit, which can leave a half-initialised
   process hung at splash. Install these FIRST.
2. **`enforcement_rank: 2`** -- `reaction_dispatch` (the method that turns a verdict into
   a dialog/redirect/wipe). No-op the dispatcher instead of chasing each reaction.
3. **`enforcement_rank: 3`** -- boolean gates feeding a terminal action.
4. **`enforcement_rank: 4`** -- individual detectors (the `defense_mechanisms[]` lists),
   as a backstop only.

## Requirements

1. Wrap Java hooks in `Java.perform(function () {{ ... }})`. Guard every `Java.use`
   in try/catch so a missing class never aborts the rest of the script.
2. **Always hook `runtime_class`, never `java_class`** -- the latter is the jadx-sanitised
   display name and will not resolve at runtime. Use `smali_descriptor` to disambiguate
   the exact overload when present. If `name_verified` is false, log a warning.
3. For each `enforcement_chokepoints` entry, apply the rank-ordered strategy above. For
   each `defense_mechanisms[].hook_candidates` entry, hook `runtime_class` (and
   `method_hint` when present); if `method_hint` is empty, hook every declared method
   whose name implies a check and force a safe return (`false` for "is this bad?"
   predicates, `true` for "is this genuine/valid?" predicates, no-op for `void`
   validators that throw).
4. Apply the framework-level bypasses in each `generic_frida_hints` block (root, SSL
   pinning, anti-debug, anti-hook, emulator, MDM/device-owner, integrity/attestation).
5. **Keep a termination tracer on (§7).** Before neutralising anything, install
   trace-only hooks that print a stack trace on entry to the exit vectors, so the real
   gate is proven rather than guessed:
   - Java: `System.exit`, `Runtime.exit`, `Runtime.halt`, `Process.killProcess`
     (backtrace via `Java.use('java.lang.Exception').$new()`).
   - Native: `Interceptor.attach(Module.findExportByName(null, sym), ...)` for
     `exit`, `_exit`, `_Exit`, `abort`, `kill`, `tgkill`, `pthread_kill`, `raise`
     (backtrace via `Thread.backtrace(ctx, Backtracer.ACCURATE).map(DebugSymbol.fromAddress)`).
     Hook libc **exports**, not callsites -- packed native libs resolve libc at runtime.
   Default to trace-only; enable blocking only as a last-resort net.
6. {"**Dynamic code loading was detected.** " if dyn else ""}For any candidate with
   `requires_deferred_hook: true` (lives in a secondary DEX / loaded reflectively),
   do NOT rely on a hook installed at spawn-time `Java.perform` -- it will miss the class.
   Instead: (a) resolve across every classloader with
   `Java.enumerateClassLoaders(...)` + `Java.ClassFactory.get(loader).use(name)`, and
   (b) install launch-critical hooks just-in-time by hooking
   `android.app.Instrumentation.callApplicationOnCreate`, force-loading + hooking the
   gate class there before calling the original. Keep a bounded `setInterval` fallback.
7. Cover `native_libraries[]`: for `ptrace`/`fork` anti-debug `Interceptor.attach` on
   `ptrace` returning 0; for native string checks add a comment pointing at the
   library + offset for manual patching.
8. Emit `console.log("[divine-departure] <what was neutralised>")` on each successful
   hook so the operator can see coverage at runtime.
9. Prefer resilience over brevity. No placeholders -- produce runnable code.

## Static security model

```json
{json.dumps(model, indent=2)}
```

## Detected categories

{cats}

Return only the Frida script, preceded by a one-paragraph summary of what it does.
"""
