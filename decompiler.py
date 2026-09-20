"""
decompiler.py

Wraps external decompilation tools and raw zip extraction to produce, from a single
.apk file, three things the rest of the pipeline needs:

    1. Human-readable Java source (via jadx)          -> <outdir>/jadx_out/
    2. Smali source (via apktool, catches cases jadx    -> <outdir>/apktool_out/
       fails to fully decompile, e.g. heavy obfuscation)
    3. Raw native libraries straight from the APK zip   -> <outdir>/native_libs/<abi>/*.so
       (independent of apktool/jadx -- this always works as long as the APK is a valid zip)

Requires `apktool` and `jadx` to be installed and on PATH. If either is missing, that
stage is skipped with a warning and the pipeline continues with what it has.
"""

import os
import shutil
import subprocess
import zipfile
from pathlib import Path


class DecompileResult:
    def __init__(self, jadx_dir=None, apktool_dir=None, native_libs_dir=None, warnings=None):
        self.jadx_dir = jadx_dir
        self.apktool_dir = apktool_dir
        self.native_libs_dir = native_libs_dir
        self.warnings = warnings or []


def _resolve_tool(name):
    """Return an argv prefix that can actually launch `name` on this OS.

    On Windows, jadx/apktool are installed as .bat/.cmd wrappers. CreateProcess
    (used by subprocess without shell=True) can only start .exe files, so a bare
    ["jadx", ...] raises FileNotFoundError even though the tool is on PATH.
    Resolving the real path and routing .bat/.cmd through `cmd /c` fixes that.
    """
    path = shutil.which(name)
    if path is None:
        return None
    if os.name == "nt" and path.lower().endswith((".bat", ".cmd")):
        return ["cmd", "/c", path]
    return [path]


def run_jadx(apk_path: Path, out_dir: Path, timeout=1200) -> tuple[Path | None, str | None]:
    tool = _resolve_tool("jadx")
    if tool is None:
        return None, "jadx not found on PATH -- skipping Java decompilation (install: https://github.com/skylot/jadx)"
    jadx_out = out_dir / "jadx_out"
    jadx_out.mkdir(parents=True, exist_ok=True)
    # --no-res skips resource decoding (apktool handles it), significantly speeding up jadx and avoiding timeouts
    cmd = tool + ["-d", str(jadx_out), "--show-bad-code", "--no-res", str(apk_path)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return jadx_out, f"jadx timed out after {timeout}s -- partial output may still be usable"
    except Exception as e:
        return None, f"jadx failed: {e}"
    return jadx_out, None


def run_apktool(apk_path: Path, out_dir: Path, timeout=1800) -> tuple[Path | None, str | None]:
    tool = _resolve_tool("apktool")
    if tool is None:
        return None, "apktool not found on PATH -- skipping smali extraction (install: https://apktool.org)"
    apktool_out = out_dir / "apktool_out"
    if apktool_out.exists():
        shutil.rmtree(apktool_out)
    cmd = tool + ["d", "-f", "-o", str(apktool_out), str(apk_path)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return apktool_out, f"apktool timed out after {timeout}s -- partial output may still be usable"
    except Exception as e:
        return None, f"apktool failed: {e}"
    return apktool_out, None


def extract_native_libs(apk_path: Path, out_dir: Path) -> tuple[Path | None, str | None]:
    """Pull lib/**/*.so directly out of the APK zip -- no external tool required."""
    native_dir = out_dir / "native_libs"
    native_dir.mkdir(parents=True, exist_ok=True)
    found = 0
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for info in z.infolist():
                if info.filename.startswith("lib/") and info.filename.endswith(".so"):
                    dest = native_dir / info.filename[len("lib/"):]
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(info) as src, open(dest, "wb") as dst:
                        dst.write(src.read())
                    found += 1
    except zipfile.BadZipFile:
        return None, "Input file is not a valid zip/APK"
    if found == 0:
        return native_dir, "No native (.so) libraries found inside the APK"
    return native_dir, None


def extract_ipa(ipa_path: Path, out_dir: Path) -> tuple[Path | None, str | None]:
    ipa_out = out_dir / "ipa_extracted"
    ipa_out.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(ipa_path, "r") as z:
            z.extractall(ipa_out)
    except zipfile.BadZipFile:
        return None, "Input file is not a valid zip/IPA"
    return ipa_out, None


def decompile_apk(apk_path: str, out_dir: str) -> DecompileResult:
    apk_path = Path(apk_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    warnings = []

    if apk_path.suffix.lower() == ".ipa":
        ipa_dir, w = extract_ipa(apk_path, out_dir)
        if w: warnings.append(w)
        # For IPA, we pass the extracted directory as jadx_dir so java_scanner can sweep it for .js/.swift bundles
        return DecompileResult(jadx_dir=ipa_dir, apktool_dir=None, native_libs_dir=ipa_dir, warnings=warnings)

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        f_jadx = executor.submit(run_jadx, apk_path, out_dir)
        f_apktool = executor.submit(run_apktool, apk_path, out_dir)
        f_native = executor.submit(extract_native_libs, apk_path, out_dir)

        jadx_dir, w1 = f_jadx.result()
        if w1: warnings.append(w1)

        apktool_dir, w2 = f_apktool.result()
        if w2: warnings.append(w2)

        native_dir, w3 = f_native.result()
        if w3: warnings.append(w3)

    return DecompileResult(jadx_dir=jadx_dir, apktool_dir=apktool_dir,
                            native_libs_dir=native_dir, warnings=warnings)
