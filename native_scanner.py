"""
native_scanner.py

Static analysis of native ARM/ARM64/x86 shared objects (.so) extracted from an APK's
lib/<abi>/ directories. Two complementary techniques:

  1. String extraction: pull printable strings out of .rodata/.data and match them
     against the same signature DB used for Java/Smali (patterns.NATIVE_STRING_PATTERNS).
     Fast, always works, no disassembly required.

  2. Call-site tracing: disassemble .text with Capstone, resolve PLT stub addresses for
     "interesting" imported functions (ptrace, fork, kill, access, system, ...) via the
     relocation table, then scan for CALL/BL instructions targeting those stubs. If the
     binary isn't stripped, the enclosing function symbol is reported so you know exactly
     which native function performs the check; if it IS stripped, the raw file offset is
     reported instead so it can be jumped to directly in Ghidra/IDA.

Requires: pyelftools (`pip install pyelftools`) and capstone (`pip install capstone`).
If either is missing, that stage is skipped with a clear warning rather than crashing.
"""

import re
import string
from dataclasses import dataclass
from pathlib import Path

from patterns import NATIVE_INTERESTING_IMPORTS, NATIVE_STRING_PATTERNS, build_prefilter

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    HAVE_ELFTOOLS = True
except ImportError:
    HAVE_ELFTOOLS = False

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

# Cheap literal pre-filter for the per-string pattern loop (see patterns.build_prefilter).
_NATIVE_GATE, _NATIVE_GATED, _NATIVE_ALWAYS_RUN = build_prefilter(NATIVE_STRING_PATTERNS)


@dataclass
class NativeStringFinding:
    so_path: str
    pattern_name: str
    category: str
    description: str
    confidence: str
    file_offset: int
    matched_string: str


@dataclass
class NativeCallSiteFinding:
    so_path: str
    imported_symbol: str
    category: str
    confidence: str
    description: str
    calling_function: str   # symbol name, or "offset 0x1234 (stripped binary)"
    call_instruction_address: int


ARCH_MAP = {
    "EM_AARCH64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM) if HAVE_CAPSTONE else None,
    # ARM: use THUMB mode flag so Capstone auto-switches between ARM/Thumb on .text
    "EM_ARM":     (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB) if HAVE_CAPSTONE else None,
    "EM_386":     (capstone.CS_ARCH_X86, capstone.CS_MODE_32) if HAVE_CAPSTONE else None,
    "EM_X86_64":  (capstone.CS_ARCH_X86, capstone.CS_MODE_64) if HAVE_CAPSTONE else None,
}

_PRINTABLE = set(bytes(string.printable, "ascii"))


def _extract_strings(data: bytes, min_len=5):
    """Yield (offset, string) for printable ASCII runs >= min_len, similar to `strings`.
    Also extracts UTF-16 LE strings (common in obfuscated Android/iOS native code).
    """
    # ASCII pass (C-level regex is ~50x faster than pure-python byte loop)
    for match in re.finditer(b"[ -~]{" + str(min_len).encode() + b",}", data):
        yield match.start(), match.group().decode("ascii", errors="ignore")

    # UTF-16 LE pass: pick up wide-char strings obfuscators sometimes use
    for match in re.finditer(
        b"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + b",}", data
    ):
        try:
            s = match.group().decode("utf-16-le", errors="ignore").strip()
            if s:
                yield match.start(), s
        except Exception:
            pass


def scan_strings_in_so(so_path: Path) -> list[NativeStringFinding]:
    findings = []
    seen: set[tuple] = set()  # dedup: (pattern_name, so_path, snippet)
    try:
        data = so_path.read_bytes()
    except OSError:
        return findings

    for offset, s in _extract_strings(data):
        if len(s) > 2000:
            s = s[:2000]
        if _NATIVE_GATE is not None and _NATIVE_GATE.search(s.lower()):
            candidates = _NATIVE_GATED + _NATIVE_ALWAYS_RUN
        else:
            candidates = _NATIVE_ALWAYS_RUN
        for pat in candidates:
            if pat["regex"].search(s):
                key = (pat["name"], str(so_path), s[:80])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(NativeStringFinding(
                    so_path=str(so_path),
                    pattern_name=pat["name"],
                    category=pat["category"],
                    description=pat["description"],
                    confidence=pat["confidence"],
                    file_offset=offset,
                    matched_string=s[:150],
                ))
    return findings


def _get_function_symbols(elf: "ELFFile"):
    """Return sorted list of (start_addr, size, name) for FUNC symbols, from .symtab if present."""
    funcs = []
    for sec_name in (".symtab", ".dynsym"):
        sec = elf.get_section_by_name(sec_name)
        if sec is None:
            continue
        for sym in sec.iter_symbols():
            if sym["st_info"]["type"] == "STT_FUNC" and sym["st_value"] != 0:
                funcs.append((sym["st_value"], sym["st_size"] or 0, sym.name))
    funcs.sort(key=lambda t: t[0])
    return funcs


def _enclosing_function(addr: int, funcs) -> str:
    for start, size, name in funcs:
        end = start + size if size else start + 1
        if start <= addr < end:
            return name or f"sub_{start:x}"
    return f"offset 0x{addr:x} (stripped binary -- no symbol covers this address)"


def _resolve_plt_targets(elf: "ELFFile") -> dict:
    """
    Map PLT stub address -> imported symbol name, by walking .rela.plt / .rel.plt
    relocations against the .plt section. This is a best-effort heuristic: exact PLT
    stub layout varies by arch/linker, so we approximate by assuming stub #i in .plt
    corresponds to relocation #i in .rela.plt (true for the common lazy-binding layout
    produced by the Android NDK toolchain).
    """
    plt_map = {}
    plt_section = elf.get_section_by_name(".plt")
    if plt_section is None:
        return plt_map

    plt_addr = plt_section["sh_addr"]
    plt_entry_size = plt_section["sh_entsize"] or 16
    # first stub is usually a reserved/header entry on some archs; we conservatively
    # start matching from stub 0 and let symbol-name filtering do the real work below.
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection):
            symtab = elf.get_section(sec["sh_link"])
            for idx, reloc in enumerate(sec.iter_relocations()):
                sym = symtab.get_symbol(reloc["r_info_sym"])
                if not sym or not sym.name:
                    continue
                stub_addr = plt_addr + (idx + 1) * plt_entry_size  # +1 skips PLT0 header stub
                plt_map[stub_addr] = sym.name
    return plt_map


def scan_callsites_in_so(so_path: Path) -> tuple[list[NativeCallSiteFinding], str | None]:
    if not HAVE_ELFTOOLS:
        return [], "pyelftools not installed -- skipping disassembly-based call-site tracing (pip install pyelftools)"
    if not HAVE_CAPSTONE:
        return [], "capstone not installed -- skipping disassembly-based call-site tracing (pip install capstone)"

    findings = []
    try:
        with open(so_path, "rb") as f:
            elf = ELFFile(f)
            arch_key = elf.header["e_machine"]
            arch = ARCH_MAP.get(arch_key)
            if arch is None:
                return [], f"Unsupported architecture {arch_key} for {so_path.name} -- skipped"

            text_section = elf.get_section_by_name(".text")
            if text_section is None:
                return [], f"No .text section in {so_path.name} -- skipped"

            plt_targets = _resolve_plt_targets(elf)
            interesting_stub_addrs = {
                addr: name for addr, name in plt_targets.items()
                if name in NATIVE_INTERESTING_IMPORTS
            }
            if not interesting_stub_addrs:
                return [], None  # nothing interesting imported -- not an error

            funcs = _get_function_symbols(elf)

            md = capstone.Cs(*arch)
            md.detail = True
            code = text_section.data()
            base_addr = text_section["sh_addr"]

            for insn in md.disasm(code, base_addr):
                mnemonic = insn.mnemonic.lower()
                is_call = mnemonic in ("call", "bl", "blx") or mnemonic.startswith("bl")
                if not is_call:
                    continue
                # Branch/call instructions we care about take a single immediate target
                # operand across ARM/ARM64/x86 -- just read .imm off the first operand.
                target = None
                if insn.operands:
                    op = insn.operands[0]
                    if hasattr(op, "imm"):
                        target = op.imm
                if target in interesting_stub_addrs:
                    sym_name = interesting_stub_addrs[target]
                    cat, conf, desc = NATIVE_INTERESTING_IMPORTS[sym_name]
                    findings.append(NativeCallSiteFinding(
                        so_path=str(so_path),
                        imported_symbol=sym_name,
                        category=cat,
                        confidence=conf,
                        description=desc,
                        calling_function=_enclosing_function(insn.address, funcs),
                        call_instruction_address=insn.address,
                    ))
    except Exception as e:
        return [], f"Failed to analyze {so_path.name}: {e}"

    return findings, None


def count_so_files(native_dir) -> int:
    """Number of .so/.dylib/Mach-O files under native_dir (for progress bars)."""
    if native_dir is None or not Path(native_dir).exists():
        return 0
    count = sum(1 for _ in Path(native_dir).rglob("*.so"))
    count += sum(1 for _ in Path(native_dir).rglob("*.dylib"))
    for app_dir in Path(native_dir).rglob("Payload/*.app"):
        if (app_dir / app_dir.name[:-4]).is_file(): count += 1
    return count


def scan_native_dir(native_dir: Path, progress=None) -> tuple[list[NativeStringFinding], list[NativeCallSiteFinding], list[str]]:
    """Scan every native binary under native_dir (all ABIs). Returns (string_findings, callsite_findings, warnings).

    `progress`, if given, is called once per file with no arguments.
    """
    string_findings: list[NativeStringFinding] = []
    callsite_findings: list[NativeCallSiteFinding] = []
    warnings: list[str] = []

    if native_dir is None or not Path(native_dir).exists():
        return string_findings, callsite_findings, warnings

    so_files = list(Path(native_dir).rglob("*.so"))
    so_files.extend(Path(native_dir).rglob("*.dylib"))
    for app_dir in Path(native_dir).rglob("Payload/*.app"):
        main_bin = app_dir / app_dir.name[:-4]
        if main_bin.is_file():
            so_files.append(main_bin)
    so_files = sorted(list(set(so_files)))
    
    if not so_files:
        return string_findings, callsite_findings, warnings

    for so_path in so_files:
        if progress is not None:
            progress()
        string_findings.extend(scan_strings_in_so(so_path))
        cs_findings, warn = scan_callsites_in_so(so_path)
        callsite_findings.extend(cs_findings)
        if warn:
            warnings.append(warn)

    return string_findings, callsite_findings, warnings
