"""
patcher.py

Optional offensive stage: take the target APK and produce a *pentest-ready* build with
the root / integrity / anti-debug / anti-hook / emulator / MDM checks neutralised, then
rebuild and re-sign it so it installs on a normal device.

Pipeline
--------
    1. Fresh `apktool d` of the APK into a private work dir (keeps the scan output pristine).
    2. Smali rewriting:
         a. Method-body neutralisation -- any method the app itself declares whose name
            matches a known check (isRooted, verifySignature, isDeviceOwnerApp, isEmulator,
            isFridaDetected, ...) has its body replaced with a constant return
            (false for "is this bad?" checks, true for "is this genuine/valid?" checks).
            Only Z (boolean) and V (void) returning, non-abstract/native methods are touched.
         b. AndroidManifest hardening for instrumentation: android:debuggable="true",
            usesCleartextTraffic="true", and a networkSecurityConfig that trusts user CAs
            (so Burp/mitmproxy just works).  [skippable with keep_manifest=True]
    3. `apktool b` -> unsigned APK.
    4. zipalign (if available).
    5. Generate a throwaway keystore (keytool) and sign with apksigner.
       If signing tooling is unavailable the aligned-but-unsigned APK is still emitted
       along with the exact command to sign it manually.

Every change is recorded and returned as a list of dicts for the HTML report / console.

Nothing here is subtle: static method-stubbing is best-effort. Checks wired through
reflection, native code, or server-side attestation will NOT be covered -- those still
need Frida/objection at runtime. The report says so.
"""

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from decompiler import _resolve_tool


# ---------------------------------------------------------------------------
# Tool discovery -- like _resolve_tool but also looks inside the Android SDK
# build-tools and JDK bin dirs, which are commonly installed but not on PATH.
# ---------------------------------------------------------------------------
def _candidate_dirs():
    dirs = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        if os.environ.get(env):
            dirs.append(Path(os.environ[env]) / "build-tools")
    localapp = os.environ.get("LOCALAPPDATA")
    if localapp:
        dirs.append(Path(localapp) / "Android" / "Sdk" / "build-tools")
    dirs.append(Path.home() / "AppData" / "Local" / "Android" / "Sdk" / "build-tools")
    # macOS default Android Studio SDK location
    dirs.append(Path.home() / "Library" / "Android" / "sdk" / "build-tools")
    # Linux default Android Studio SDK location, plus common distro package paths
    dirs.append(Path.home() / "Android" / "Sdk" / "build-tools")
    dirs.append(Path("/usr/lib/android-sdk/build-tools"))
    dirs.append(Path("/opt/android-sdk/build-tools"))
    dirs.append(Path("/opt/android-sdk-linux/build-tools"))

    resolved = []
    for d in dirs:
        if d.is_dir():
            # build-tools/<version>/ -- prefer the highest version
            subs = sorted((p for p in d.iterdir() if p.is_dir()), reverse=True)
            resolved.extend(subs or [d])

    for env in ("JAVA_HOME",):
        if os.environ.get(env):
            resolved.append(Path(os.environ[env]) / "bin")

    if os.name == "nt":
        jdk_bases = (r"C:\Program Files\Java", r"C:\Program Files\Android\Android Studio\jbr",
                     r"C:\Program Files\Eclipse Adoptium")
    elif sys.platform == "darwin":
        jdk_bases = (
            "/Applications/Android Studio.app/Contents/jbr/Contents/Home",
            "/Library/Java/JavaVirtualMachines",   # contains */Contents/Home
            "/opt/homebrew/opt/openjdk",
            "/usr/local/opt/openjdk",
        )
    else:
        jdk_bases = (
            "/usr/lib/jvm",                         # contains one dir per installed JDK
            "/opt/android-studio/jbr",
            str(Path.home() / "android-studio" / "jbr"),
        )

    for base in jdk_bases:
        b = Path(base)
        if not b.is_dir():
            continue
        if (b / "bin").is_dir():
            resolved.append(b / "bin")
        if (b / "Contents" / "Home" / "bin").is_dir():
            resolved.append(b / "Contents" / "Home" / "bin")
        # base is itself a container of versioned JDK dirs (e.g. /usr/lib/jvm/*, JavaVirtualMachines/*)
        for p in sorted(b.glob("*/bin"), reverse=True):
            resolved.append(p)
        for p in sorted(b.glob("*/Contents/Home/bin"), reverse=True):
            resolved.append(p)
    return resolved


def _find_tool(name):
    """Return an argv prefix that launches `name`, searching PATH then SDK/JDK dirs."""
    pre = _resolve_tool(name)
    if pre is not None:
        return pre
    exts = (".exe", ".bat", ".cmd", "") if os.name == "nt" else ("",)
    for d in _candidate_dirs():
        for ext in exts:
            cand = d / f"{name}{ext}"
            if cand.is_file():
                if os.name == "nt" and cand.suffix.lower() in (".bat", ".cmd"):
                    return ["cmd", "/c", str(cand)]
                return [str(cand)]
    return None


# ---------------------------------------------------------------------------
# Smali method-name signatures -> desired constant return
# ---------------------------------------------------------------------------
# "falsey" -> method answers a "is something bad present?" question; force false.
# "truthy" -> method answers "is this genuine / valid / untampered?"; force true.
_FALSEY_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"is(?:device)?rooted|isrooted\w*|hasroot|checkroot\w*|detectroot\w*|"
    r"check(?:for)?su(?:binary)?|issubinarypresent|checkbusybox|checkforbusybox|"
    r"checkrootpackages|detectrootmanagementapps|detectpotentiallydangerousapps|"
    r"checkfordangerousprops|checkforrwpaths|detecttestkeys|checkformagisk|ismagisk\w*|"
    r"isemulator|isrunningonemulator|check(?:for)?emulator|detectemulator|isgenymotion|"
    r"isbeingdebugged|isdebuggerattached|check(?:for)?debug\w*|detectdebugger|antidebug\w*|"
    r"isdebugged|"
    r"isfrida\w*|check(?:for)?frida|detectfrida|ishooked|checkhook\w*|detecthook\w*|"
    r"isxposed\w*|check(?:for)?xposed|detectxposed|issubstrate\w*|"
    r"istampered|isrepackaged|ismodified|iscracked|ispirated|"
    r"ismanaged|isdevicemanaged|ismanageddevice|isdeviceowner\w*|isprofileowner\w*|"
    r"ismanagedprofile|iscompanyowned|ismdm\w*|isenrolled|isenrollment\w*|"
    r"isdeviceadmin\w*|isadminactive|hasdeviceadmin|isworkprofile|isinworkprofile|"
    r"isknox\w*|isafw\w*|iskiosk\w*|islocktask\w*|iscontainer\w*|"
    r"checkpinning|verifypinning|checkcertificatepinning|verifycertificate\w*|"
    r"ispinningenabled|ispinned|checkpin|verifyssl\w*|validatepinning"
    r")$"
)
_TRUTHY_NAME_RE = re.compile(
    r"(?i)^(?:"
    r"verify(?:app)?signature\w*|check(?:app)?signature\w*|issignaturevalid|validatesignature|"
    r"isvalidsignature|iscorrectsignature|verifyapk|checkapksignature|verifyintegrity|"
    r"checkintegrity|isintegrityok|isuntampered|isgenuine\w*|isrealdevice|"
    r"isvalidinstaller|verifyinstaller\w*|isofficial\w*|isplaystoreinstall\w*|"
    r"ispinningsuccessful|ispinvalid|ispinmatch\w*"
    r")$"
)
# void methods that throw on failure -- neutralise by making them return-void.
_VOID_NOOP_NAME_RE = re.compile(
    r"(?i)^(?:checkservertrusted|checkclienttrusted|checkvalidity|"
    r"enforcepinning|assertpinning|verifychain|checktrust\w*)$"
)

# .method line: capture flags + name + descriptor. Descriptor return type is after ')'.
_METHOD_RE = re.compile(r"^\s*\.method\s+(?P<flags>[\w\- ]*?)\s*(?P<name>[\w$<>]+)\((?P<params>[^)]*)\)(?P<ret>.+?)\s*$")

# Third-party packages whose methods we will NOT name-stub -- a generic name like
# verifySignature() inside okhttp/conscrypt is library plumbing, and forcing its
# return value tends to break TLS rather than bypass a check. The app's own
# anti-tamper code lives outside these.
_SKIP_PKG_PREFIXES = (
    "smali/android/", "smali/androidx/", "smali/kotlin/", "smali/kotlinx/",
    "smali/java/", "smali/javax/", "smali/org/jetbrains/", "smali/org/intellij/",
    "smali/okhttp3/", "smali/okio/", "smali/retrofit2/", "smali/com/google/",
    "smali/com/squareup/", "smali/org/bouncycastle/", "smali/org/conscrypt/",
    "smali/com/android/org/conscrypt/", "smali/io/reactivex/", "smali/rx/",
    "smali/org/apache/", "smali/dagger/", "smali/javax/inject/", "smali/kotlin/coroutines/",
)


def _is_skipped_pkg(rel_path: str) -> bool:
    p = re.sub(r"^smali_classes\d+/", "smali/", rel_path.replace("\\", "/"))
    if not p.startswith("smali/"):
        p = "smali/" + p
    return p.startswith(_SKIP_PKG_PREFIXES)


@dataclass
class PatchStats:
    records: list = field(default_factory=list)   # list[dict] for report
    warnings: list = field(default_factory=list)

    def add(self, category, location, action, detail=""):
        self.records.append(dict(category=category, location=location, action=action, detail=detail))


def _classify(name):
    if _VOID_NOOP_NAME_RE.match(name):
        return "noop"
    if _TRUTHY_NAME_RE.match(name):
        return "truthy"
    if _FALSEY_NAME_RE.match(name):
        return "falsey"
    return None


def _stub_body(ret_type, sense):
    """Return smali lines (without .method / .end method) for a constant-return stub."""
    if ret_type == "V":
        return ["    .locals 0\n", "    return-void\n"]
    if ret_type == "Z":
        val = "0x1" if sense in ("truthy", "noop") else "0x0"
        return ["    .locals 1\n", f"    const/4 v0, {val}\n", "    return v0\n"]
    # numeric primitives -> 0 ; not normally a check but harmless
    if ret_type in ("I", "S", "B", "C"):
        return ["    .locals 1\n", "    const/4 v0, 0x0\n", "    return v0\n"]
    if ret_type == "J":
        return ["    .locals 2\n", "    const-wide/16 v0, 0x0\n", "    return-wide v0\n"]
    return None  # object / array / float / double -> don't touch


def _patch_smali_file(path: Path, work_root: Path, stats: PatchStats):
    rel = str(path.relative_to(work_root))
    if _is_skipped_pkg(rel):
        return  # don't name-stub third-party library plumbing (breaks more than it bypasses)
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
    except OSError:
        return
    out = []
    i = 0
    changed = False
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _METHOD_RE.match(line)
        if not m:
            out.append(line)
            i += 1
            continue

        flags = m.group("flags") or ""
        name = m.group("name")
        ret = m.group("ret").strip()

        if ("abstract" in flags or "native" in flags or name in ("<init>", "<clinit>")):
            out.append(line)
            i += 1
            continue

        # find matching .end method
        j = i + 1
        while j < n and not lines[j].lstrip().startswith(".end method"):
            j += 1
        if j >= n:
            out.append(line)
            i += 1
            continue

        sense = _classify(name)
        stub = _stub_body(ret, sense) if sense else None
        if sense and stub is not None:
            out.append(line)
            out.extend(stub)
            out.append(lines[j])  # .end method
            rel = path.relative_to(work_root)
            cat = _guess_category(name)
            if ret == "V":
                action = "stub -> no-op (return-void, no throw)"
            elif sense in ("truthy", "noop"):
                action = "stub -> return true"
            else:
                action = "stub -> return false"
            stats.add(cat, f"{rel}::{name}()", action,
                      f"descriptor ({m.group('params')}){ret}")
            changed = True
            i = j + 1
            continue

        # not a target -- copy through untouched
        out.extend(lines[i:j + 1])
        i = j + 1

    if changed:
        path.write_text("".join(out), encoding="utf-8")


def _guess_category(name):
    n = name.lower()
    if any(k in n for k in ("rasp", "shield")):
        return "RASP_DETECTION"
    if any(k in n for k in ("pin", "servertrusted", "clienttrusted", "trustmanager",
                             "hostname", "certificate", "ssl", "trustchain", "verifychain")):
        return "SSL_PINNING"
    if any(k in n for k in ("owner", "managed", "mdm", "enroll", "admin", "knox", "afw",
                             "workprofile", "kiosk", "locktask", "container")):
        return "MDM_CHECK"
    if any(k in n for k in ("frida", "hook", "xposed", "substrate")):
        return "ANTI_HOOK"
    if any(k in n for k in ("debug",)):
        return "ANTI_DEBUG"
    if any(k in n for k in ("emulator", "genymotion")):
        return "EMULATOR_DETECT"
    if any(k in n for k in ("sign", "integrity", "tamper", "repackag", "genuine",
                             "installer", "apk", "crack", "pirat")):
        return "INTEGRITY_CHECK"
    return "ROOT_DETECTION"


# ---------------------------------------------------------------------------
# AndroidManifest.xml hardening
# ---------------------------------------------------------------------------
_NETSEC_XML = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
"""


def _harden_manifest(work_dir: Path, stats: PatchStats):
    manifest = work_dir / "AndroidManifest.xml"
    if not manifest.is_file():
        stats.warnings.append("AndroidManifest.xml not found in apktool output -- manifest hardening skipped")
        return
    text = manifest.read_text(encoding="utf-8", errors="ignore")
    orig = text

    # ensure android namespace prefix present (it always is in apktool output)
    def _set_app_attr(txt, attr, value):
        app_re = re.compile(r"<application\b[^>]*", re.DOTALL)
        m = app_re.search(txt)
        if not m:
            return txt, False
        tag = m.group(0)
        if re.search(rf'\b{re.escape(attr)}\s*=', tag):
            new_tag = re.sub(rf'{re.escape(attr)}\s*=\s*"[^"]*"', f'{attr}="{value}"', tag)
        else:
            new_tag = tag + f' {attr}="{value}"'
        if new_tag == tag:
            return txt, False
        return txt[:m.start()] + new_tag + txt[m.end():], True

    for attr, value, cat, note in (
        ("android:debuggable", "true", "ANTI_DEBUG", "app is now attachable by jdb/Android Studio"),
        ("android:usesCleartextTraffic", "true", "INTEGRITY_CHECK", "allow HTTP for proxying"),
        ("android:networkSecurityConfig", "@xml/network_security_config", "INTEGRITY_CHECK",
         "trust user-installed CAs (Burp/mitmproxy)"),
    ):
        text, ok = _set_app_attr(text, attr, value)
        if ok:
            stats.add(cat, "AndroidManifest.xml <application>", f'set {attr}="{value}"', note)

    if text != orig:
        manifest.write_text(text, encoding="utf-8")

    # drop the netsec xml
    xml_dir = work_dir / "res" / "xml"
    xml_dir.mkdir(parents=True, exist_ok=True)
    (xml_dir / "network_security_config.xml").write_text(_NETSEC_XML, encoding="utf-8")


# ---------------------------------------------------------------------------
# rebuild / align / sign
# ---------------------------------------------------------------------------
def _run(cmd, timeout=900):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _rebuild(work_dir: Path, out_apk: Path, stats: PatchStats):
    apktool = _find_tool("apktool")
    if apktool is None:
        stats.warnings.append("apktool not found -- cannot rebuild the patched APK")
        return False
    cmd = apktool + ["b", str(work_dir), "-o", str(out_apk)]
    r = _run(cmd)
    if r.returncode != 0 or not out_apk.is_file():
        # retry without aapt2 which sometimes chokes on odd resources
        r2 = _run(apktool + ["b", "--use-aapt2", str(work_dir), "-o", str(out_apk)])
        if r2.returncode != 0 or not out_apk.is_file():
            tail = (r.stderr or r.stdout or "").strip().splitlines()[-8:]
            stats.warnings.append("apktool build failed:\n    " + "\n    ".join(tail))
            return False
    return True


def _zipalign(in_apk: Path, out_apk: Path, stats: PatchStats):
    za = _find_tool("zipalign")
    if za is None:
        stats.warnings.append("zipalign not found -- skipping alignment (apksigner will still accept the APK)")
        shutil.copy2(in_apk, out_apk)
        return out_apk
    r = _run(za + ["-p", "-f", "4", str(in_apk), str(out_apk)])
    if r.returncode != 0 or not out_apk.is_file():
        stats.warnings.append("zipalign failed -- using unaligned APK")
        shutil.copy2(in_apk, out_apk)
    return out_apk


def _ensure_keystore(ks_path: Path, stats: PatchStats):
    if ks_path.is_file():
        return True
    keytool = _find_tool("keytool")
    if keytool is None:
        stats.warnings.append("keytool not found -- cannot create a signing keystore")
        return False
    cmd = keytool + [
        "-genkeypair", "-v", "-keystore", str(ks_path),
        "-storepass", "android", "-keypass", "android",
        "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
        "-validity", "10000", "-dname", "CN=Divine Departure Debug,O=pentest,C=US",
    ]
    r = _run(cmd)
    if r.returncode != 0 or not ks_path.is_file():
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-5:]
        stats.warnings.append("keytool keystore generation failed:\n    " + "\n    ".join(tail))
        return False
    return True


def _sign(in_apk: Path, out_apk: Path, ks_path: Path, stats: PatchStats):
    apksigner = _find_tool("apksigner")
    if apksigner is None:
        stats.warnings.append(
            "apksigner not found -- APK is rebuilt + aligned but UNSIGNED. Sign it with:\n"
            f'    apksigner sign --ks "{ks_path}" --ks-pass pass:android --out "{out_apk}" "{in_apk}"'
        )
        shutil.copy2(in_apk, out_apk)
        return False
    if not _ensure_keystore(ks_path, stats):
        shutil.copy2(in_apk, out_apk)
        return False
    r = _run(apksigner + [
        "sign", "--ks", str(ks_path), "--ks-pass", "pass:android",
        "--key-pass", "pass:android", "--out", str(out_apk), str(in_apk),
    ])
    if r.returncode != 0 or not out_apk.is_file():
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-6:]
        stats.warnings.append("apksigner failed:\n    " + "\n    ".join(tail))
        shutil.copy2(in_apk, out_apk)
        return False
    v = _run(apksigner + ["verify", "--print-certs", str(out_apk)])
    if v.returncode != 0:
        stats.warnings.append("apksigner verify reported problems -- test-install before relying on it")
    return True


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------
def patch_apk(apk_path: str, out_dir: str, keep_manifest: bool = False):
    """
    Returns (final_apk_path_or_None, patch_records:list[dict], warnings:list[str]).
    """
    apk_path = Path(apk_path)
    out_dir = Path(out_dir)
    stats = PatchStats()

    apktool = _find_tool("apktool")
    if apktool is None:
        stats.warnings.append("apktool not found on PATH or in the Android SDK -- cannot patch")
        return None, stats.records, stats.warnings

    work_dir = out_dir / "patch_work"
    if work_dir.exists():
        shutil.rmtree(work_dir, ignore_errors=True)

    r = _run(apktool + ["d", "-f", "-o", str(work_dir), str(apk_path)])
    if r.returncode != 0 or not work_dir.is_dir():
        tail = (r.stderr or r.stdout or "").strip().splitlines()[-8:]
        stats.warnings.append("apktool decode for patching failed:\n    " + "\n    ".join(tail))
        return None, stats.records, stats.warnings

    smali_files = list(work_dir.rglob("*.smali"))
    for sf in smali_files:
        _patch_smali_file(sf, work_dir, stats)

    method_patches = len(stats.records)

    if not keep_manifest:
        _harden_manifest(work_dir, stats)

    dist = out_dir / "patched"
    dist.mkdir(parents=True, exist_ok=True)
    stem = apk_path.stem
    unsigned = dist / f"{stem}.unsigned.apk"
    aligned = dist / f"{stem}.aligned.apk"
    final = dist / f"{stem}.patched.apk"

    if not _rebuild(work_dir, unsigned, stats):
        return None, stats.records, stats.warnings

    _zipalign(unsigned, aligned, stats)
    signed_ok = _sign(aligned, final, out_dir / "divine-departure.keystore", stats)

    stats.warnings.append(
        f"Patch summary: {method_patches} smali method(s) neutralised across "
        f"{len(smali_files)} smali file(s). "
        + ("APK signed and ready to install." if signed_ok
           else "APK rebuilt but NOT signed -- see notes above.")
    )
    stats.warnings.append(
        "Static patching only covers checks in decompiled smali. Reflection-based, "
        "native (.so), packed/DEX-encrypted, or server-side attestation checks are NOT "
        "handled -- pair this build with Frida/objection at runtime for those."
    )
    return (final if final.is_file() else aligned), stats.records, stats.warnings
