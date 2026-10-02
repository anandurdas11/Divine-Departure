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
}

# Directory prefixes that jadx / apktool prepend and that are not part of the class name.
_STRIP_PREFIXES = ("sources/", "sources\\", "smali/", "smali\\")
_SMALI_MULTIDEX_RE = re.compile(r"^smali_classes\d+[/\\]", re.IGNORECASE)

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
    try:
        lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""
    idx = min(max(line_number - 1, 0), len(lines) - 1)
    is_smali = abs_path.suffix == ".smali"
    for k in range(idx, -1, -1):
        row = lines[k]
        if is_smali:
            m = _SMALI_METHOD_RE.match(row)
            if m:
                return m.group(1)
            if row.lstrip().startswith(".end method"):
                return ""   # we walked out of a method without seeing its header
        else:
            m = _JAVA_METHOD_RE.match(row)
            if m and m.group(1) not in ("if", "for", "while", "switch", "catch", "new"):
                return m.group(1)
    return ""


def build_security_model(apk_name, source_findings, native_string_findings,
                         native_callsite_findings, warnings, out_dir,
                         jadx_dir=None, apktool_dir=None, patch_records=None):
    out_dir = Path(out_dir)
    roots = [Path(d) for d in (jadx_dir, apktool_dir) if d]

    def _resolve(rel):
        for r in roots:
            cand = r / rel
            if cand.is_file():
                return cand
        return None

    by_cat = defaultdict(list)
    for f in source_findings:
        by_cat[f.category].append(f)

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
                seen[key] = dict(
                    java_class=fqcn,
                    method_hint=method,
                    frida_use=f'Java.use("{fqcn}")',
                    source=f"{f.file_path}:{f.line_number}",
                    signature=f.pattern_name,
                    confidence=f.confidence,
                    snippet=f.snippet[:120],
                )
        candidates = sorted(
            seen.values(),
            key=lambda c: (_is_lib(c["java_class"]),               # first-party first
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
        native.append(dict(kind="callsite", library=Path(f.so_path).name,
                           category=f.category, symbol=f.imported_symbol,
                           function=f.calling_function,
                           address=f"0x{f.call_instruction_address:x}",
                           confidence=f.confidence, description=f.description))
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

    model = dict(
        target=dict(apk=apk_name, generated=datetime.now().isoformat(timespec="seconds")),
        summary=dict(
            total_source_findings=len(source_findings),
            total_native_findings=len(native_string_findings) + len(native_callsite_findings),
            categories_present=categories_present,
            by_category=by_category_counts,
        ),
        defense_mechanisms=mechanisms,
        native_libraries=native,
        patched=bool(patch_records),
        patch_log=patch_records or [],
        tool_warnings=warnings,
        disclaimer=(
            "Static model. Class/method hints are heuristic (derived from decompiled paths "
            "and nearby method headers) and MUST be verified. Reflection, native, packed, "
            "and server-side attestation logic will be under-represented."
        ),
    )

    json_path = out_dir / "security_model.json"
    json_path.write_text(json.dumps(model, indent=2), encoding="utf-8")

    prompt_path = out_dir / "frida_prompt.md"
    prompt_path.write_text(_render_prompt(model), encoding="utf-8")

    return json_path, prompt_path, model


def _render_prompt(model) -> str:
    cats = ", ".join(model["summary"]["categories_present"]) or "none detected"
    return f"""# Frida bypass script generation -- task brief

You are a senior mobile application security engineer performing an **authorised**
penetration test. Using the static security model below, write **one consolidated
Frida script** (JavaScript, for `frida` / `objection`) that disables every defensive
mechanism it describes so the app can be dynamically analysed on a rooted device /
emulator behind an intercepting proxy.

## Requirements

1. Wrap Java hooks in `Java.perform(function () {{ ... }})`. Guard every `Java.use`
   in try/catch so a missing class never aborts the rest of the script.
2. For each entry in `defense_mechanisms[].hook_candidates`, hook the named
   `java_class` (and `method_hint` when present). If `method_hint` is empty, hook
   every declared method of the class whose name implies a check and force a safe
   return (`false` for "is this bad?" predicates, `true` for "is this genuine/valid?"
   predicates, no-op for `void` validators that throw).
3. Also apply the framework-level bypasses listed in each
   `generic_frida_hints` block (root, SSL pinning, anti-debug, anti-hook,
   emulator, MDM/device-owner, integrity/attestation).
4. Cover `native_libraries[]`: for `ptrace`/`fork` anti-debug use an
   `Interceptor.attach` on `ptrace` returning 0; for native string checks add a
   short comment pointing at the library + offset for manual patching.
5. Emit `console.log("[divine-departure] <what was neutralised>")` on each successful
   hook so the operator can see coverage at runtime.
6. Prefer resilience over brevity. No placeholders -- produce runnable code.

## Static security model

```json
{json.dumps(model, indent=2)}
```

## Detected categories

{cats}

Return only the Frida script, preceded by a one-paragraph summary of what it does.
"""
