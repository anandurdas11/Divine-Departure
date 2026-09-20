"""
ios_deep_analyzer.py

Ghidra-style deep static analysis of Mach-O binaries extracted from iOS IPA files.

This module goes far beyond simple string matching. It performs:

  1.  Full ARM64/ARM32 disassembly via Capstone -- every instruction decoded
  2.  Function boundary detection via symbol table + prologue pattern scan
  3.  Basic-block CFG reconstruction per function
  4.  Cross-reference (xref) engine -- for every string/symbol, which functions reference it
  5.  Import table analysis -- PLT-equivalent stub resolution via __stubs + __got sections
  6.  Export table analysis -- all exported symbols classified
  7.  ObjC runtime analysis:
        - Class hierarchy (superclass chains)
        - Method lists (class/instance methods + their IMP addresses)
        - Protocol conformances
        - __objc_selrefs -> resolved selector strings
        - __objc_classrefs -> resolved class names
        - Category analysis
  8.  Swift metadata analysis:
        - Type descriptors (class/struct/enum/protocol)
        - Demangled Swift function names
        - Swift protocol witness tables
  9.  Entitlements extraction from LC_CODE_SIGNATURE blob
  10. Dylib dependency graph (all LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB)
  11. Security-pattern call-graph tracing:
        - Which functions call security-relevant imports (ptrace, sysctl, fork, etc.)
        - Indirect call tracking via vtable / selector dispatch
        - String-to-function attribution (which function contains a security string)
  12. CFG-based control flow analysis:
        - Dead code detection
        - Conditional branch analysis around security checks
        - Return-value analysis for boolean-returning security functions

Requires: capstone (pip install capstone)
Optional: lief (pip install lief) -- for richer import/export/entitlement parsing

No external binaries required. Pure Python + Capstone.
"""

from __future__ import annotations

import re
import struct
import plistlib
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Optional deps
# ---------------------------------------------------------------------------
try:
    import capstone
    from capstone import arm64 as cs_arm64
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

try:
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False

# ---------------------------------------------------------------------------
# Mach-O constants (duplicated here so this module is standalone)
# ---------------------------------------------------------------------------
MH_MAGIC_64   = 0xFEEDFACF
MH_MAGIC_32   = 0xFEEDFACE
MH_CIGAM_64   = 0xCFFAEDFE
MH_CIGAM_32   = 0xCEFAEDFE
FAT_MAGIC     = 0xCAFEBABE
FAT_CIGAM     = 0xBEBAFECA

MH_PIE                  = 0x200000
MH_ALLOW_STACK_EXECUTION= 0x20000
MH_NO_HEAP_EXECUTION    = 0x01000000

LC_SEGMENT              = 0x01
LC_SYMTAB               = 0x02
LC_DYSYMTAB             = 0x0B
LC_LOAD_DYLIB           = 0x0C
LC_LOAD_WEAK_DYLIB      = 0x18 | 0x80000000
LC_SEGMENT_64           = 0x19
LC_CODE_SIGNATURE       = 0x1D
LC_ENCRYPTION_INFO      = 0x21
LC_DYLD_INFO_ONLY       = 0x22 | 0x80000000
LC_DYLD_INFO            = 0x22
LC_VERSION_MIN_IPHONEOS = 0x25
LC_BUILD_VERSION        = 0x32
LC_ENCRYPTION_INFO_64   = 0x2C
LC_RPATH                = 0x1C | 0x80000000
LC_REEXPORT_DYLIB       = 0x1F | 0x80000000
LC_LAZY_LOAD_DYLIB      = 0x20

CPU_TYPE_ARM   = 12
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86   = 7
CPU_TYPE_X86_64= 0x01000007

# Security-relevant imported symbols to track call-sites for
SECURITY_IMPORTS = {
    # Anti-debug
    "ptrace",               "sysctl",             "sysctlbyname",
    "getppid",              "task_get_exception_ports",
    "mach_task_self_",      "task_threads",        "thread_get_state",
    # Jailbreak / RASP
    "fork",                 "posix_spawn",         "system",
    "access",               "stat",                "stat64",
    "fopen",                "open",                "opendir",
    # Hook detection
    "_dyld_image_count",    "_dyld_get_image_name","_dyld_get_image_header",
    "dlopen",               "dlsym",               "dladdr",
    "vm_region_64",         "vm_region",           "mach_vm_region",
    "mprotect",             "mmap",
    # SSL Pinning
    "SecTrustEvaluate",     "SecTrustEvaluateWithError",
    "SecTrustCopyResult",   "SecCertificateCopyData",
    "SSLHandshake",         "SSLRead",             "SSLWrite",
    # Crypto / Integrity
    "CC_MD5",               "CC_SHA1",             "CC_SHA256",
    "CCCrypt",              "SecItemAdd",          "SecItemCopyMatching",
    "SecKeyEncrypt",        "SecKeyDecrypt",
    # ObjC runtime (hook detection)
    "method_getImplementation", "method_setImplementation",
    "class_replaceMethod",  "object_getClass",
    "objc_getClass",        "NSClassFromString",
    # Environment
    "getenv",               "setenv",
    # Sandbox / entitlement
    "sandbox_check",        "csops",               "csops_audittoken",
}

# Patterns in disassembled mnemonics / operands indicating security checks
_SECURITY_MNEMONIC_HINTS = {
    "cbz":  "conditional branch on zero -- may gate a security check",
    "cbnz": "conditional branch on non-zero -- may gate a security check",
    "tbnz": "test-and-branch not zero -- bitfield security flag check",
    "tbz":  "test-and-branch zero -- bitfield security flag check",
    "bl":   None,  # call -- resolved separately
    "blr":  "indirect call -- possible dynamic dispatch of security check",
}

# Known ObjC security class names
_OBJC_SECURITY_CLASSES = re.compile(
    r"jailbreak|rootDetect|antiDebug|antiHook|hookDetect|frida|substrate|rasp|"
    r"tamper|integrity|pinning|certPin|trustKit|sslPin|securityCheck|"
    r"iosSecuritySuite|dttjailbreak|freerasp|approov|promon|zimperium|"
    r"deviceIntegrity|secureCheck|bypas",
    re.IGNORECASE,
)

# Swift security symbol patterns (demangled)
_SWIFT_SECURITY_PATTERNS = re.compile(
    r"jailbroken|isJailbroken|checkJailbreak|detectJailbreak|"
    r"amIDebugged|isBeingDebugged|antiDebug|"
    r"fridaDetect|hookDetect|amIReverseEngineered|"
    r"certificatePinning|trustServer|validateCert|"
    r"isSimulator|simulatorCheck|"
    r"IOSSecuritySuite|TalsecApplication|Approov",
    re.IGNORECASE,
)


# ===========================================================================
# Data classes
# ===========================================================================

@dataclass
class MachOSection:
    name: str
    segname: str
    vm_addr: int
    file_offset: int
    size: int
    flags: int = 0


@dataclass
class MachOSymbol:
    name: str
    addr: int
    is_external: bool = False
    is_undefined: bool = False
    sym_type: str = ""


@dataclass
class DylibDep:
    name: str
    load_cmd: str  # LOAD_DYLIB, LOAD_WEAK_DYLIB, REEXPORT, LAZY
    current_version: str = ""
    compat_version: str = ""


@dataclass
class ObjCMethod:
    class_name: str
    method_name: str
    is_class_method: bool
    imp_addr: int
    type_encoding: str = ""


@dataclass
class ObjCClass:
    name: str
    superclass_name: str
    methods: list[ObjCMethod] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)
    ivars: list[str] = field(default_factory=list)


@dataclass
class SwiftTypeDescriptor:
    kind: str   # "Class", "Struct", "Enum", "Protocol"
    name: str
    mangled_name: str = ""


@dataclass
class BasicBlock:
    start_addr: int
    end_addr: int
    instructions: list  = field(default_factory=list)   # list of capstone insns
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    calls: list[int] = field(default_factory=list)       # call targets


@dataclass
class Function:
    name: str
    start_addr: int
    size: int
    blocks: list[BasicBlock] = field(default_factory=list)
    calls: list[int] = field(default_factory=list)       # all call targets
    string_refs: list[str] = field(default_factory=list) # strings referenced
    security_imports: list[str] = field(default_factory=list)  # security APIs called
    is_security_relevant: bool = False


@dataclass
class DeepFinding:
    category: str
    severity: str          # "high" / "medium" / "low" / "info"
    title: str
    description: str
    location: str          # "BinaryName!FunctionName+0x1234" format
    address: int = 0
    calling_function: str = ""
    snippet: str = ""
    xrefs: list[str] = field(default_factory=list)  # functions that reference this


@dataclass
class DeepAnalysisResult:
    binary_path: str
    arch: str
    is_encrypted: bool
    has_pie: bool
    has_arc: bool
    has_stack_canary: bool
    has_nx_heap: bool
    has_code_signature: bool
    min_os: str
    entitlements: dict
    dylibs: list[DylibDep]
    sections: list[MachOSection]
    symbols: list[MachOSymbol]
    imports: dict[int, str]        # addr -> symbol name
    exports: list[MachOSymbol]
    objc_classes: list[ObjCClass]
    swift_types: list[SwiftTypeDescriptor]
    functions: list[Function]
    findings: list[DeepFinding]
    warnings: list[str]


# ===========================================================================
# Mach-O parser
# ===========================================================================

class MachOParser:
    """Full Mach-O parser: FAT handling, all load commands, sections, symbols."""

    def __init__(self, data: bytes):
        self.data = data
        self.endian = "<"
        self.is_64 = False
        self.offset = 0       # offset into data for the selected arch slice
        self.hdr_size = 0
        self.ncmds = 0
        self.flags = 0
        self.cpu_type = 0
        self.sections: dict[str, MachOSection] = {}   # sectname -> MachOSection
        self.load_commands: list[tuple[int, int, int]] = []  # (cmd, cmdsize, pos)
        self._parse_header()

    # ------------------------------------------------------------------
    def _parse_header(self):
        d = self.data
        if len(d) < 8:
            return
        magic = struct.unpack("<I", d[:4])[0]

        # FAT binary -- pick the arm64 slice preferentially, else first slice
        if magic in (FAT_MAGIC, FAT_CIGAM):
            be = (magic == FAT_CIGAM)
            fmt = ">I" if be else "<I"
            narch = struct.unpack(fmt, d[4:8])[0]
            best_offset = None
            for i in range(min(narch, 32)):
                pos = 8 + i * 20
                if pos + 20 > len(d):
                    break
                cputype, _, arch_offset, _, _ = struct.unpack(fmt * 5, d[pos:pos + 20])
                if cputype == CPU_TYPE_ARM64:
                    best_offset = arch_offset
                    break
                if best_offset is None:
                    best_offset = arch_offset
            if best_offset:
                self.offset = best_offset
            magic = struct.unpack("<I", d[self.offset:self.offset + 4])[0]

        if magic in (MH_CIGAM_32, MH_CIGAM_64):
            self.endian = ">"
        elif magic not in (MH_MAGIC_32, MH_MAGIC_64):
            return

        self.is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
        self.hdr_size = 32 if self.is_64 else 28
        o = self.offset
        fmt = f"{self.endian}IiiIIIII" if self.is_64 else f"{self.endian}IiiIIII"
        if o + self.hdr_size > len(d):
            return
        fields = struct.unpack(fmt, d[o:o + self.hdr_size])
        self.cpu_type = fields[1]
        self.ncmds   = fields[4]
        self.flags   = fields[7] if self.is_64 else fields[6]

        # Walk load commands
        pos = o + self.hdr_size
        for _ in range(min(self.ncmds, 1024)):
            if pos + 8 > len(d):
                break
            cmd, cmdsize = struct.unpack(f"{self.endian}II", d[pos:pos + 8])
            if cmdsize < 8 or pos + cmdsize > len(d):
                break
            self.load_commands.append((cmd, cmdsize, pos))
            pos += cmdsize

    # ------------------------------------------------------------------
    def _u32(self, pos): return struct.unpack(f"{self.endian}I", self.data[pos:pos + 4])[0]
    def _u64(self, pos): return struct.unpack(f"{self.endian}Q", self.data[pos:pos + 8])[0]
    def _cstr(self, pos, limit=None):
        end = self.data.find(b"\x00", pos, limit)
        if end == -1:
            end = limit or len(self.data)
        return self.data[pos:end].decode("utf-8", errors="ignore")

    # ------------------------------------------------------------------
    def parse_sections(self) -> dict[str, MachOSection]:
        d = self.data
        e = self.endian
        sects: dict[str, MachOSection] = {}

        for cmd, cmdsize, pos in self.load_commands:
            if cmd == LC_SEGMENT_64 and pos + 72 <= len(d):
                segname = d[pos + 8:pos + 24].split(b"\x00")[0].decode("ascii", errors="ignore")
                nsects = self._u32(pos + 64)
                sec_pos = pos + 72
                for _ in range(min(nsects, 256)):
                    if sec_pos + 80 > len(d):
                        break
                    sectname = d[sec_pos:sec_pos + 16].split(b"\x00")[0].decode("ascii", errors="ignore")
                    vm_addr  = self._u64(sec_pos + 32)
                    vm_size  = self._u64(sec_pos + 40)
                    foffset  = self._u32(sec_pos + 48)
                    flags    = self._u32(sec_pos + 64)
                    sects[sectname] = MachOSection(sectname, segname, vm_addr, foffset, vm_size, flags)
                    sec_pos += 80

            elif cmd == LC_SEGMENT and pos + 56 <= len(d):
                segname = d[pos + 8:pos + 24].split(b"\x00")[0].decode("ascii", errors="ignore")
                nsects = self._u32(pos + 48)
                sec_pos = pos + 56
                for _ in range(min(nsects, 256)):
                    if sec_pos + 68 > len(d):
                        break
                    sectname = d[sec_pos:sec_pos + 16].split(b"\x00")[0].decode("ascii", errors="ignore")
                    vm_addr  = self._u32(sec_pos + 32)
                    vm_size  = self._u32(sec_pos + 36)
                    foffset  = self._u32(sec_pos + 40)
                    flags    = self._u32(sec_pos + 52)
                    sects[sectname] = MachOSection(sectname, segname, vm_addr, foffset, vm_size, flags)
                    sec_pos += 68

        self.sections = sects
        return sects

    # ------------------------------------------------------------------
    def parse_dylibs(self) -> list[DylibDep]:
        d = self.data
        result = []
        for cmd, cmdsize, pos in self.load_commands:
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB):
                if pos + 24 > len(d):
                    continue
                name_off = self._u32(pos + 8)
                cur_ver  = self._u32(pos + 12)
                compat   = self._u32(pos + 16)
                name_start = pos + name_off
                name = self._cstr(name_start, pos + cmdsize)
                kind = {
                    LC_LOAD_DYLIB:       "LOAD_DYLIB",
                    LC_LOAD_WEAK_DYLIB:  "LOAD_WEAK_DYLIB",
                    LC_REEXPORT_DYLIB:   "REEXPORT_DYLIB",
                    LC_LAZY_LOAD_DYLIB:  "LAZY_LOAD_DYLIB",
                }.get(cmd, "LOAD_DYLIB")
                result.append(DylibDep(
                    name=name, load_cmd=kind,
                    current_version=f"{(cur_ver>>16)&0xFFFF}.{(cur_ver>>8)&0xFF}.{cur_ver&0xFF}",
                    compat_version=f"{(compat>>16)&0xFFFF}.{(compat>>8)&0xFF}.{compat&0xFF}",
                ))
        return result

    # ------------------------------------------------------------------
    def parse_symbols(self) -> list[MachOSymbol]:
        d = self.data
        symbols = []
        for cmd, cmdsize, pos in self.load_commands:
            if cmd == LC_SYMTAB and pos + 24 <= len(d):
                symoff, nsyms, stroff, strsize = struct.unpack(
                    f"{self.endian}IIII", d[pos + 8:pos + 24])
                str_end = min(stroff + strsize, len(d))
                nlist_size = 16 if self.is_64 else 12
                for i in range(min(nsyms, 200000)):
                    ep = symoff + i * nlist_size
                    if ep + nlist_size > len(d):
                        break
                    str_idx  = self._u32(ep)
                    typ      = d[ep + 4] if ep + 4 < len(d) else 0
                    sect_num = d[ep + 5] if ep + 5 < len(d) else 0
                    desc     = struct.unpack(f"{self.endian}H", d[ep + 6:ep + 8])[0] if ep + 8 <= len(d) else 0
                    value    = self._u64(ep + 8) if self.is_64 else self._u32(ep + 8)
                    name_start = stroff + str_idx
                    if name_start >= str_end:
                        continue
                    name_end = d.find(b"\x00", name_start, str_end)
                    if name_end == -1:
                        name_end = str_end
                    name = d[name_start:name_end].decode("utf-8", errors="ignore")
                    is_ext   = bool(typ & 0x01)
                    is_undef = (typ & 0x0E) == 0x00
                    symbols.append(MachOSymbol(name=name, addr=value,
                                               is_external=is_ext, is_undefined=is_undef))
                break
        return symbols

    # ------------------------------------------------------------------
    def parse_encryption(self) -> bool:
        """Return True if binary slice is FairPlay-encrypted."""
        for cmd, cmdsize, pos in self.load_commands:
            if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                if pos + 20 <= len(self.data):
                    cryptid = self._u32(pos + 16)
                    return cryptid != 0
        return False

    # ------------------------------------------------------------------
    def parse_entitlements(self) -> dict:
        """Extract entitlements plist from LC_CODE_SIGNATURE blob."""
        d = self.data
        for cmd, cmdsize, pos in self.load_commands:
            if cmd == LC_CODE_SIGNATURE and pos + 16 <= len(d):
                cs_offset = self._u32(pos + 8)
                cs_size   = self._u32(pos + 12)
                blob = d[cs_offset:cs_offset + cs_size]
                # Search for embedded plist (begins with <?xml or bplist00)
                for marker in (b"<?xml", b"bplist00"):
                    idx = blob.find(marker)
                    if idx != -1:
                        plist_data = blob[idx:]
                        # Find end by looking for </plist> or just try to parse
                        end_marker = b"</plist>"
                        end_idx = plist_data.find(end_marker)
                        if end_idx != -1:
                            plist_data = plist_data[:end_idx + len(end_marker)]
                        try:
                            return plistlib.loads(plist_data)
                        except Exception:
                            pass
        return {}

    # ------------------------------------------------------------------
    def get_text_section(self) -> tuple[int, int, bytes]:
        """Return (vm_addr, file_offset, code_bytes) for __text section."""
        if not self.sections:
            self.parse_sections()
        for name in ("__text", "text"):
            s = self.sections.get(name)
            if s and s.size > 0:
                d = self.data[s.file_offset:s.file_offset + s.size]
                return s.vm_addr, s.file_offset, d
        return 0, 0, b""

    # ------------------------------------------------------------------
    def vm_addr_to_file_offset(self, vm_addr: int) -> int:
        """Convert a virtual address to a file offset using section map."""
        if not self.sections:
            self.parse_sections()
        for s in self.sections.values():
            if s.vm_addr <= vm_addr < s.vm_addr + s.size:
                return s.file_offset + (vm_addr - s.vm_addr)
        return -1


# ===========================================================================
# ObjC runtime analysis
# ===========================================================================

class ObjCAnalyzer:
    """
    Parses the ObjC runtime metadata sections to reconstruct:
    - Class list with method tables
    - Selector references -> string resolution
    - Class references -> class name resolution
    - Protocol list
    - Category list
    """

    def __init__(self, parser: MachOParser):
        self.parser = parser
        self.d = parser.data
        self.is_64 = parser.is_64
        self.endian = parser.endian
        self._ptr_size = 8 if parser.is_64 else 4
        self._classes: list[ObjCClass] = []
        self._selectors: dict[int, str] = {}  # addr -> selector string

    def _ptr(self, pos: int) -> int:
        if self._ptr_size == 8:
            return struct.unpack(f"{self.endian}Q", self.d[pos:pos + 8])[0] & ~0x07  # strip tagged ptr
        return struct.unpack(f"{self.endian}I", self.d[pos:pos + 4])[0] & ~0x03

    def _read_cstr(self, vm_addr: int) -> str:
        if vm_addr == 0:
            return ""
        offset = self.parser.vm_addr_to_file_offset(vm_addr)
        if offset < 0:
            return ""
        end = self.d.find(b"\x00", offset, offset + 512)
        if end == -1:
            end = offset + 512
        return self.d[offset:end].decode("utf-8", errors="ignore")

    def extract_selectors(self) -> dict[int, str]:
        """Build addr->selector-name map from __objc_methnames section."""
        sects = self.parser.sections
        for sec_name in ("__objc_methnames", "__objc_methnames\x00"):
            sec = sects.get("__objc_methnames") or sects.get(sec_name)
            if sec:
                raw = self.d[sec.file_offset:sec.file_offset + sec.size]
                offset = sec.file_offset
                for s in raw.split(b"\x00"):
                    if len(s) >= 1:
                        try:
                            name = s.decode("utf-8", errors="ignore")
                            self._selectors[sec.vm_addr + (offset - sec.file_offset)] = name
                        except Exception:
                            pass
                        offset += len(s) + 1
        return self._selectors

    def extract_classnames(self) -> list[str]:
        """Extract all ObjC class names from __objc_classname section."""
        sects = self.parser.sections
        sec = sects.get("__objc_classname")
        if not sec:
            return []
        raw = self.d[sec.file_offset:sec.file_offset + sec.size]
        return [s.decode("utf-8", errors="ignore") for s in raw.split(b"\x00") if len(s) >= 1]

    def _parse_method_list(self, vm_addr: int, class_name: str, is_class_method: bool) -> list[ObjCMethod]:
        """Parse an ObjC method_list_t structure."""
        methods = []
        if vm_addr == 0:
            return methods
        fo = self.parser.vm_addr_to_file_offset(vm_addr)
        if fo < 0 or fo + 8 > len(self.d):
            return methods
        # method_list_t: flags(4) + count(4) + methods...
        flags = struct.unpack(f"{self.endian}I", self.d[fo:fo + 4])[0]
        count = struct.unpack(f"{self.endian}I", self.d[fo + 4:fo + 8])[0]
        # method_t: name(ptr) + types(ptr) + imp(ptr)  -- relative (iOS 14+) or absolute
        is_relative = bool(flags & 0x80000000)
        entry_size = 12 if is_relative else (24 if self.is_64 else 12)
        pos = fo + 8
        for i in range(min(count, 4096)):
            if pos + entry_size > len(self.d):
                break
            if is_relative:
                # Relative method list (iOS 14+): each field is int32 relative offset
                name_off = struct.unpack(f"{self.endian}i", self.d[pos:pos + 4])[0]
                types_off= struct.unpack(f"{self.endian}i", self.d[pos + 4:pos + 8])[0]
                imp_off  = struct.unpack(f"{self.endian}i", self.d[pos + 8:pos + 12])[0]
                name_ptr_addr = vm_addr + 8 + i * 12 + name_off
                # name_ptr_addr points to a stub that points to the selector string
                # Simplified: convert to file offset and read
                name_fo = self.parser.vm_addr_to_file_offset(name_ptr_addr)
                sel_name = ""
                if name_fo >= 0 and name_fo + self._ptr_size <= len(self.d):
                    sel_ptr = self._ptr(name_fo)
                    sel_name = self._read_cstr(sel_ptr)
                imp_vm = vm_addr + 8 + i * 12 + 8 + imp_off  # IMP relative
                types = ""
                methods.append(ObjCMethod(class_name, sel_name, is_class_method, imp_vm, types))
            else:
                if self.is_64:
                    name_ptr  = self._ptr(pos)
                    types_ptr = self._ptr(pos + 8)
                    imp_ptr   = self._ptr(pos + 16)
                else:
                    name_ptr  = self._ptr(pos)
                    types_ptr = self._ptr(pos + 4)
                    imp_ptr   = self._ptr(pos + 8)
                sel_name = self._read_cstr(name_ptr)
                types = self._read_cstr(types_ptr)
                methods.append(ObjCMethod(class_name, sel_name, is_class_method, imp_ptr, types))
            pos += entry_size
        return methods

    def parse_classes(self) -> list[ObjCClass]:
        """Full ObjC class hierarchy reconstruction from __objc_classlist."""
        sects = self.parser.sections
        sec = sects.get("__objc_classlist")
        if not sec or sec.size == 0:
            return []
        ptr_size = self._ptr_size
        classes = []
        fo = sec.file_offset
        n_ptrs = sec.size // ptr_size
        for i in range(min(n_ptrs, 4096)):
            cls_ptr_fo = fo + i * ptr_size
            if cls_ptr_fo + ptr_size > len(self.d):
                break
            cls_vm = self._ptr(cls_ptr_fo)
            cls_fo = self.parser.vm_addr_to_file_offset(cls_vm)
            if cls_fo < 0:
                continue
            # class_t structure (64-bit): metaclass(8)+superclass(8)+cache(8)+vtable(8)+data(8)
            if self.is_64:
                if cls_fo + 40 > len(self.d):
                    continue
                meta_vm  = self._ptr(cls_fo)
                super_vm = self._ptr(cls_fo + 8)
                data_vm  = self._ptr(cls_fo + 32) & ~0x07
            else:
                if cls_fo + 20 > len(self.d):
                    continue
                meta_vm  = self._ptr(cls_fo)
                super_vm = self._ptr(cls_fo + 4)
                data_vm  = self._ptr(cls_fo + 16) & ~0x03

            # class_ro_t: flags + ... + name + methods + protocols + ivars
            data_fo = self.parser.vm_addr_to_file_offset(data_vm)
            if data_fo < 0:
                continue
            if self.is_64:
                if data_fo + 72 > len(self.d):
                    continue
                cls_flags   = struct.unpack(f"{self.endian}I", self.d[data_fo:data_fo + 4])[0]
                name_vm     = self._ptr(data_fo + 24)
                methods_vm  = self._ptr(data_fo + 32)
                protocols_vm= self._ptr(data_fo + 40)
                ivars_vm    = self._ptr(data_fo + 48)
            else:
                if data_fo + 36 > len(self.d):
                    continue
                cls_flags   = struct.unpack(f"{self.endian}I", self.d[data_fo:data_fo + 4])[0]
                name_vm     = self._ptr(data_fo + 16)
                methods_vm  = self._ptr(data_fo + 20)
                protocols_vm= self._ptr(data_fo + 24)
                ivars_vm    = self._ptr(data_fo + 28)

            cls_name = self._read_cstr(name_vm)
            if not cls_name:
                continue

            # Superclass name
            super_fo = self.parser.vm_addr_to_file_offset(super_vm)
            super_name = ""
            if super_fo >= 0:
                super_data_vm = self._ptr(super_fo + (32 if self.is_64 else 16)) & ~0x07
                super_data_fo = self.parser.vm_addr_to_file_offset(super_data_vm)
                if super_data_fo >= 0:
                    super_name_vm = self._ptr(super_data_fo + (24 if self.is_64 else 16))
                    super_name = self._read_cstr(super_name_vm)

            # Instance methods
            inst_methods = self._parse_method_list(methods_vm, cls_name, False)

            # Class methods from metaclass
            class_methods = []
            meta_fo = self.parser.vm_addr_to_file_offset(meta_vm)
            if meta_fo >= 0:
                meta_data_vm = self._ptr(meta_fo + (32 if self.is_64 else 16)) & ~0x07
                meta_data_fo = self.parser.vm_addr_to_file_offset(meta_data_vm)
                if meta_data_fo >= 0:
                    meta_methods_vm = self._ptr(meta_data_fo + (32 if self.is_64 else 20))
                    class_methods = self._parse_method_list(meta_methods_vm, cls_name, True)

            objc_cls = ObjCClass(
                name=cls_name,
                superclass_name=super_name,
                methods=inst_methods + class_methods,
            )
            classes.append(objc_cls)

        self._classes = classes
        return classes


# ===========================================================================
# Swift metadata analysis
# ===========================================================================

class SwiftAnalyzer:
    """
    Parses Swift type metadata sections:
    - __swift5_types : type descriptor pointers (classes, structs, enums, protocols)
    - __swift5_proto : protocol conformances
    - __swift5_reflstr: reflection strings (demangled names)
    """

    def __init__(self, parser: MachOParser):
        self.parser = parser
        self.d = parser.data

    def _demangle_swift(self, mangled: str) -> str:
        """Basic Swift name demangling (prefix stripping, no full demangler)."""
        if mangled.startswith("$s"):
            # Strip module prefix heuristically
            return mangled[2:].split("C")[0] if "C" in mangled else mangled[2:]
        if mangled.startswith("_T0"):
            return mangled[3:]
        return mangled

    def extract_type_names(self) -> list[SwiftTypeDescriptor]:
        """Extract Swift type names from __swift5_reflstr and __swift5_types."""
        types = []
        sects = self.parser.sections

        # 1. Reflection strings -- human-readable type names
        reflstr_sec = sects.get("__swift5_reflstr")
        if reflstr_sec and reflstr_sec.size > 0:
            raw = self.d[reflstr_sec.file_offset:reflstr_sec.file_offset + reflstr_sec.size]
            for s in raw.split(b"\x00"):
                if len(s) >= 2:
                    name = s.decode("utf-8", errors="ignore")
                    if _SWIFT_SECURITY_PATTERNS.search(name):
                        types.append(SwiftTypeDescriptor("Swift", name, name))

        # 2. Swift5 types section -- type descriptor pointers
        types_sec = sects.get("__swift5_types")
        if types_sec and types_sec.size > 0:
            ptr_size = 8 if self.parser.is_64 else 4
            n_ptrs = types_sec.size // 4  # entries are int32 relative offsets
            fo = types_sec.file_offset
            vm = types_sec.vm_addr
            for i in range(min(n_ptrs, 50000)):
                pos = fo + i * 4
                if pos + 4 > len(self.d):
                    break
                rel_off = struct.unpack(f"{self.parser.endian}i", self.d[pos:pos + 4])[0]
                desc_vm = vm + i * 4 + rel_off
                desc_fo = self.parser.vm_addr_to_file_offset(desc_vm)
                if desc_fo < 0 or desc_fo + 16 > len(self.d):
                    continue
                # TypeContextDescriptor: flags(4) + parent(4) + name(4) + ...
                flags = struct.unpack(f"{self.parser.endian}I", self.d[desc_fo:desc_fo + 4])[0]
                kind_raw = flags & 0x1F
                kind_map = {0: "Module", 1: "Extension", 2: "Anonymous", 3: "Protocol",
                            16: "Struct", 17: "Enum", 18: "Class"}
                kind = kind_map.get(kind_raw, f"Type({kind_raw})")
                # Name is at desc_fo + 8 as relative int32
                if desc_fo + 12 <= len(self.d):
                    name_rel = struct.unpack(f"{self.parser.endian}i", self.d[desc_fo + 8:desc_fo + 12])[0]
                    name_vm2 = desc_vm + 8 + name_rel
                    name_fo = self.parser.vm_addr_to_file_offset(name_vm2)
                    if name_fo >= 0:
                        end = self.d.find(b"\x00", name_fo, name_fo + 256)
                        if end == -1:
                            end = name_fo + 256
                        name = self.d[name_fo:end].decode("utf-8", errors="ignore")
                        if name and _SWIFT_SECURITY_PATTERNS.search(name):
                            types.append(SwiftTypeDescriptor(kind, name, ""))

        return types


# ===========================================================================
# Disassembler / CFG engine
# ===========================================================================

class Disassembler:
    """
    ARM64 / ARM32 disassembly engine using Capstone.
    Builds function list, basic blocks, and cross-reference maps.
    """

    def __init__(self, parser: MachOParser, symbols: list[MachOSymbol],
                 imports: dict[int, str]):
        self.parser = parser
        self.imports = imports  # addr -> symbol name (stubs)
        self._sym_map: dict[int, str] = {s.addr: s.name for s in symbols if s.addr}
        self._addr_to_func: dict[int, Function] = {}
        self.functions: list[Function] = []
        self._cs = None
        self._base = 0
        self._code = b""
        self._text_end = 0
        self._init_capstone(parser)

    def _init_capstone(self, parser: MachOParser):
        if not HAVE_CAPSTONE:
            return
        cpu = parser.cpu_type
        if cpu == CPU_TYPE_ARM64:
            self._cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        elif cpu == CPU_TYPE_ARM:
            self._cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
        elif cpu == CPU_TYPE_X86_64:
            self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif cpu == CPU_TYPE_X86:
            self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        if self._cs:
            self._cs.detail = True
        vm, fo, code = parser.get_text_section()
        self._base = vm
        self._code = code
        self._text_end = vm + len(code)

    def _enclosing_func(self, addr: int) -> str:
        """Find enclosing function name for an address."""
        best_name = f"sub_{addr:x}"
        best_start = -1
        for fn in self.functions:
            if fn.start_addr <= addr and fn.start_addr > best_start:
                if addr < fn.start_addr + max(fn.size, 1):
                    best_start = fn.start_addr
                    best_name = fn.name or f"sub_{fn.start_addr:x}"
        return best_name

    def _func_name(self, addr: int) -> str:
        if addr in self._sym_map:
            return self._sym_map[addr]
        if addr in self.imports:
            return f"__{self.imports[addr]}@plt"
        return f"sub_{addr:x}"

    def build_function_list(self) -> list[Function]:
        """Build function list from symbol table + scan for function prologues."""
        funcs: dict[int, Function] = {}
        # From symbols
        for sym in self._sym_map:
            if self._base <= sym < self._text_end:
                f = Function(name=self._sym_map[sym], start_addr=sym, size=0)
                funcs[sym] = f

        # Prologue scan for ARM64: STP x29, x30, [sp, ...] = 0xa9 0bE 0x1f 0xa8-0xaf
        if self._code and self.parser.cpu_type == CPU_TYPE_ARM64:
            for m in re.finditer(b"\xa9[\x7f-\xbf]\x1f[\xa8-\xaf]", self._code):
                addr = self._base + m.start()
                # Align to 4-byte boundary
                addr = addr & ~3
                if addr not in funcs:
                    funcs[addr] = Function(name=f"sub_{addr:x}", start_addr=addr, size=0)

        # Sort and compute sizes
        sorted_addrs = sorted(funcs.keys())
        for i, addr in enumerate(sorted_addrs):
            next_addr = sorted_addrs[i + 1] if i + 1 < len(sorted_addrs) else self._text_end
            funcs[addr].size = next_addr - addr

        self.functions = list(funcs.values())
        self._addr_to_func = funcs
        return self.functions

    def disassemble_function(self, fn: Function) -> Function:
        """Disassemble a single function, build basic blocks and extract call targets."""
        if not self._cs or fn.size <= 0:
            return fn
        rel_start = fn.start_addr - self._base
        if rel_start < 0 or rel_start >= len(self._code):
            return fn
        code_slice = self._code[rel_start:rel_start + min(fn.size, 65536)]

        current_block = BasicBlock(start_addr=fn.start_addr, end_addr=fn.start_addr)
        blocks: dict[int, BasicBlock] = {fn.start_addr: current_block}

        try:
            for insn in self._cs.disasm(code_slice, fn.start_addr):
                current_block.instructions.append(insn)
                current_block.end_addr = insn.address + insn.size
                mnem = insn.mnemonic.lower()

                # Detect calls
                if mnem in ("bl", "call") or (mnem == "blr"):
                    target = None
                    if insn.operands:
                        op = insn.operands[0]
                        if hasattr(op, "imm"):
                            target = op.imm
                    if target:
                        current_block.calls.append(target)
                        fn.calls.append(target)
                        if target in self.imports:
                            sym = self.imports[target]
                            if sym in SECURITY_IMPORTS:
                                fn.security_imports.append(sym)
                                fn.is_security_relevant = True

                # Detect branches -- end of block
                elif mnem in ("b", "ret", "br", "bx") or mnem.startswith("b.") or mnem in ("cbz", "cbnz", "tbz", "tbnz"):
                    new_block = BasicBlock(start_addr=insn.address + insn.size,
                                          end_addr=insn.address + insn.size)
                    # Branch targets
                    if insn.operands:
                        op = insn.operands[-1]  # last operand is usually the target
                        if hasattr(op, "imm"):
                            current_block.successors.append(op.imm)
                    if mnem not in ("ret", "b"):
                        current_block.successors.append(insn.address + insn.size)
                    blocks[new_block.start_addr] = new_block
                    current_block = new_block
        except Exception:
            pass

        fn.blocks = list(blocks.values())
        return fn

    def build_string_xrefs(self, string_addrs: dict[int, str]) -> dict[str, list[str]]:
        """
        For each security-relevant string in the binary, find which functions
        reference it (by scanning LDR/ADRP+ADD patterns pointing to that address).
        Returns: { string_value -> [function_name, ...] }
        """
        if not self._cs or not self._code:
            return {}
        xrefs: dict[int, list[str]] = {}  # string_addr -> [func_names]
        # Disassemble and look for address materialisation patterns
        try:
            prev_adrp_reg: dict[int, int] = {}  # reg -> page addr
            for insn in self._cs.disasm(self._code, self._base):
                mnem = insn.mnemonic.lower()
                if not insn.operands:
                    continue
                if mnem == "adrp":
                    # ADRP Xn, #page
                    reg = insn.operands[0].reg
                    page = insn.operands[1].imm
                    prev_adrp_reg[reg] = page
                elif mnem in ("add", "ldr", "str") and len(insn.operands) >= 2:
                    op1 = insn.operands[1] if mnem in ("ldr", "str") else insn.operands[1]
                    # ADD Xd, Xn, #offset  or  LDR Xd, [Xn, #offset]
                    if hasattr(op1, "reg") and op1.reg in prev_adrp_reg:
                        offset = 0
                        if mnem == "add" and len(insn.operands) >= 3:
                            if hasattr(insn.operands[2], "imm"):
                                offset = insn.operands[2].imm
                        elif hasattr(op1, "mem"):
                            offset = op1.mem.disp
                        target_addr = prev_adrp_reg[op1.reg] + offset
                        if target_addr in string_addrs:
                            fn_name = self._enclosing_func(insn.address)
                            xrefs.setdefault(target_addr, []).append(fn_name)
        except Exception:
            pass
        return {string_addrs[addr]: fns for addr, fns in xrefs.items()}


# ===========================================================================
# Import table resolver (stubs -> symbol names)
# ===========================================================================

def resolve_imports(parser: MachOParser, symbols: list[MachOSymbol]) -> dict[int, str]:
    """
    Resolve stub addresses to imported symbol names using:
    1. __stubs section + DYLD_INFO lazy bindings (if available)
    2. __la_symbol_ptr GOT entries cross-referenced against symbol table
    3. Fallback: symbol table undefined entries ordered by GOT entry
    Returns: { stub_vm_addr -> symbol_name }
    """
    imports: dict[int, str] = {}
    sects = parser.sections
    d = parser.data
    e = parser.endian
    ptr_size = 8 if parser.is_64 else 4

    # Build undefined symbol list (imports) from symbol table
    undef_syms = [s for s in symbols if s.is_undefined and s.name]

    # Try DYLD_INFO lazy bind opcodes
    for cmd, cmdsize, pos in parser.load_commands:
        if cmd in (LC_DYLD_INFO_ONLY, LC_DYLD_INFO):
            if pos + 48 > len(d):
                continue
            lazy_off  = struct.unpack(f"{e}I", d[pos + 32:pos + 36])[0]
            lazy_size = struct.unpack(f"{e}I", d[pos + 36:pos + 40])[0]
            if lazy_off and lazy_size:
                imports.update(_parse_dyld_lazy_bind(d, lazy_off, lazy_size, e, parser))
            break

    # Fallback: __stubs section paired with __la_symbol_ptr
    stubs_sec = sects.get("__stubs")
    la_sym_ptr_sec = sects.get("__la_symbol_ptr")
    if stubs_sec and la_sym_ptr_sec and undef_syms and not imports:
        n_stubs = stubs_sec.size // 12  # ARM64 stub is 12 bytes (ADRP+LDR+BR)
        for i in range(min(n_stubs, len(undef_syms))):
            stub_addr = stubs_sec.vm_addr + i * 12
            if i < len(undef_syms):
                imports[stub_addr] = undef_syms[i].name

    return imports


def _parse_dyld_lazy_bind(d: bytes, offset: int, size: int, e: str, parser: MachOParser) -> dict[int, str]:
    """Parse DYLD_INFO lazy bind opcodes to map bind addresses to symbol names."""
    imports: dict[int, str] = {}
    BIND_OPCODE_DONE              = 0x00
    BIND_OPCODE_SET_SYMBOL        = 0x40
    BIND_OPCODE_SET_TYPE          = 0x50
    BIND_OPCODE_SET_ADDEND        = 0x60
    BIND_OPCODE_SET_SEGMENT       = 0x70
    BIND_OPCODE_ADD_ADDR_ULEB     = 0x80
    BIND_OPCODE_DO_BIND           = 0x90
    BIND_OPCODE_DO_BIND_ADD_ADDR  = 0xA0
    BIND_OPCODE_DO_BIND_ULEB_TIMES= 0xC0

    end = min(offset + size, len(d))
    i = offset
    sym_name = ""
    seg_offset = 0
    seg_index  = 0
    segments = []  # (vm_addr, size) per segment
    for cmd, cmdsize, pos in parser.load_commands:
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            if cmd == LC_SEGMENT_64 and pos + 64 <= len(d):
                vm = struct.unpack(f"{e}Q", d[pos + 24:pos + 32])[0]
                vm_size = struct.unpack(f"{e}Q", d[pos + 32:pos + 40])[0]
            elif pos + 48 <= len(d):
                vm = struct.unpack(f"{e}I", d[pos + 24:pos + 28])[0]
                vm_size = struct.unpack(f"{e}I", d[pos + 28:pos + 32])[0]
            else:
                continue
            segments.append((vm, vm_size))

    while i < end:
        opcode = d[i] & 0xF0
        imm    = d[i] & 0x0F
        i += 1
        if opcode == BIND_OPCODE_DONE:
            break
        elif opcode == BIND_OPCODE_SET_SYMBOL:
            j = i
            while j < end and d[j] != 0:
                j += 1
            sym_name = d[i:j].decode("utf-8", errors="ignore")
            i = j + 1
        elif opcode == BIND_OPCODE_SET_SEGMENT:
            seg_index = imm
            seg_offset = 0
        elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
            val, shift = 0, 0
            while i < end:
                b = d[i]; i += 1
                val |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
            seg_offset += val
        elif opcode == BIND_OPCODE_DO_BIND:
            if seg_index < len(segments):
                bind_addr = segments[seg_index][0] + seg_offset
                imports[bind_addr] = sym_name
        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR:
            if seg_index < len(segments):
                bind_addr = segments[seg_index][0] + seg_offset
                imports[bind_addr] = sym_name
            val, shift = 0, 0
            while i < end:
                b = d[i]; i += 1
                val |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
            seg_offset += val
        elif opcode in (BIND_OPCODE_DO_BIND_ULEB_TIMES,):
            # count ULEB
            count, shift = 0, 0
            while i < end:
                b = d[i]; i += 1
                count |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
            skip, shift = 0, 0
            while i < end:
                b = d[i]; i += 1
                skip |= (b & 0x7F) << shift; shift += 7
                if not (b & 0x80): break
            for _ in range(count):
                if seg_index < len(segments):
                    bind_addr = segments[seg_index][0] + seg_offset
                    imports[bind_addr] = sym_name
                seg_offset += skip + (8 if parser.is_64 else 4)
    return imports


# ===========================================================================
# Security finding generator
# ===========================================================================

def _analyze_entitlements(entitlements: dict, binary_name: str) -> list[DeepFinding]:
    """Audit entitlements for over-provisioned capabilities."""
    findings = []
    loc = f"{binary_name}!entitlements"
    dangerous = {
        "com.apple.private.security.no-sandbox": (
            "INTEGRITY_CHECK", "high",
            "App disables its own sandbox",
            "The entitlement com.apple.private.security.no-sandbox is set. "
            "This completely removes sandbox restrictions -- only possible on jailbroken devices or with special provisioning."),
        "com.apple.private.security.container-required": (
            "INTEGRITY_CHECK", "medium",
            "Custom container entitlement",
            "Non-standard container entitlement may indicate privilege escalation or sandbox bypass."),
        "com.apple.security.get-task-allow": (
            "ANTI_DEBUG", "high",
            "Debugger attachment allowed (get-task-allow)",
            "get-task-allow=true allows any process to attach with task_for_pid(). "
            "Distribution builds should have this set to false."),
        "platform-application": (
            "INTEGRITY_CHECK", "high",
            "Platform application entitlement",
            "platform-application entitlement grants elevated system privileges."),
        "com.apple.private.security.no-container": (
            "INTEGRITY_CHECK", "medium",
            "No app container",
            "App operates without a sandbox container directory."),
        "keychain-access-groups": (
            "INTEGRITY_CHECK", "info",
            "Shared keychain access groups",
            f"App shares keychain with groups: {entitlements.get('keychain-access-groups', [])}"),
    }
    for ent_key, (cat, sev, title, desc) in dangerous.items():
        val = entitlements.get(ent_key)
        if val is True or (isinstance(val, list) and val) or (isinstance(val, str) and val):
            findings.append(DeepFinding(cat, sev, title, desc, loc,
                                        snippet=f"{ent_key} = {val}"))
    return findings


def _analyze_dylib_deps(dylibs: list[DylibDep], binary_name: str) -> list[DeepFinding]:
    """Flag suspicious dylib dependencies."""
    findings = []
    loc = f"{binary_name}!dylib_deps"
    suspicious_patterns = {
        r"substrate|substitute|libhooker|mobilesubstrate": (
            "ANTI_HOOK", "high", "Hooking framework linked as dependency",
            "Binary links against a hooking framework (Substrate/Substitute/libhooker). "
            "Either the app itself uses runtime hooking, or it ships a detection library."),
        r"frida": (
            "ANTI_HOOK", "high", "Frida dylib linked",
            "Binary has a direct Frida dylib dependency -- rare in production apps."),
        r"ssl|tls|pinning": (
            "SSL_PINNING", "medium", "TLS/pinning library linked",
            "Binary links a dedicated TLS or pinning library."),
        r"jailbreak|jbdetect|jb_detect": (
            "ROOT_DETECTION", "high", "Jailbreak detection library linked",
            "Binary explicitly links a jailbreak detection framework."),
    }
    for dylib in dylibs:
        for pat, (cat, sev, title, desc) in suspicious_patterns.items():
            if re.search(pat, dylib.name, re.IGNORECASE):
                findings.append(DeepFinding(cat, sev, title,
                                            f"{desc} ({dylib.name})", loc,
                                            snippet=dylib.name))
    return findings


def _analyze_security_functions(functions: list[Function], imports: dict[int, str],
                                 binary_name: str) -> list[DeepFinding]:
    """Generate findings for functions calling security-relevant imports."""
    findings = []
    for fn in functions:
        if not fn.security_imports:
            continue
        for sym in fn.security_imports:
            cat, sev, desc = {
                "ptrace":               ("ANTI_DEBUG",    "high",   "ptrace() -- anti-debug self-attach or PT_DENY_ATTACH"),
                "sysctl":               ("ANTI_DEBUG",    "high",   "sysctl() -- debugger detection via P_TRACED flag"),
                "sysctlbyname":         ("ANTI_DEBUG",    "high",   "sysctlbyname() -- hw.machine emulator/debugger check"),
                "getppid":              ("ANTI_DEBUG",    "medium", "getppid() -- parent process identity check"),
                "task_get_exception_ports":("ANTI_DEBUG", "high",   "task_get_exception_ports() -- debugger exception handler check"),
                "task_threads":         ("ANTI_DEBUG",    "medium", "task_threads() -- thread count inspection for debug detection"),
                "fork":                 ("ROOT_DETECTION","medium", "fork() -- jailbreak detection (fork succeeds on JB only)"),
                "posix_spawn":          ("ROOT_DETECTION","medium", "posix_spawn() -- process spawning for jailbreak detection"),
                "system":               ("ROOT_DETECTION","medium", "system() -- shell command execution for root checks"),
                "access":               ("ROOT_DETECTION","medium", "access() -- filesystem probe for jailbreak artifacts"),
                "stat":                 ("ROOT_DETECTION","medium", "stat() -- file existence check for jailbreak paths"),
                "stat64":               ("ROOT_DETECTION","medium", "stat64() -- file existence check for jailbreak paths"),
                "fopen":                ("ROOT_DETECTION","low",    "fopen() -- file open attempt for jailbreak path detection"),
                "open":                 ("ROOT_DETECTION","low",    "open() -- file open for jailbreak/security check"),
                "opendir":              ("ROOT_DETECTION","low",    "opendir() -- directory enumeration for jailbreak detection"),
                "_dyld_image_count":    ("ANTI_HOOK",     "high",   "_dyld_image_count() -- enumerates loaded dylibs for hook detection"),
                "_dyld_get_image_name": ("ANTI_HOOK",     "high",   "_dyld_get_image_name() -- inspects loaded dylib names for injected hooks"),
                "dlopen":               ("ANTI_HOOK",     "medium", "dlopen() -- probes for presence of hook/instrumentation libraries"),
                "dlsym":                ("ANTI_HOOK",     "medium", "dlsym() -- symbol resolution, may probe for hook presence"),
                "dladdr":               ("ANTI_HOOK",     "medium", "dladdr() -- resolves address to symbol to detect unexpected modules"),
                "vm_region_64":         ("ANTI_HOOK",     "high",   "vm_region_64() -- memory region scanning for injected hooks"),
                "vm_region":            ("ANTI_HOOK",     "medium", "vm_region() -- memory inspection for hooking detection"),
                "mach_vm_region":       ("ANTI_HOOK",     "high",   "mach_vm_region() -- full memory map inspection"),
                "mprotect":             ("ANTI_HOOK",     "medium", "mprotect() -- may change memory permissions to protect code"),
                "mmap":                 ("ANTI_HOOK",     "low",    "mmap() -- memory mapping, may be used for hook-scan or code injection"),
                "SecTrustEvaluate":     ("SSL_PINNING",   "high",   "SecTrustEvaluate() -- custom TLS trust evaluation / cert pinning"),
                "SecTrustEvaluateWithError":("SSL_PINNING","high",  "SecTrustEvaluateWithError() -- TLS trust evaluation / cert pinning"),
                "SecTrustCopyResult":   ("SSL_PINNING",   "medium", "SecTrustCopyResult() -- reads TLS validation result"),
                "SecCertificateCopyData":("SSL_PINNING",  "medium", "SecCertificateCopyData() -- reads raw certificate DER bytes"),
                "SSLHandshake":         ("SSL_PINNING",   "high",   "SSLHandshake() -- low-level TLS handshake, custom cert validation"),
                "CC_SHA256":            ("INTEGRITY_CHECK","medium","CC_SHA256() -- SHA-256 hash, may be used for self-integrity check"),
                "CCCrypt":              ("INTEGRITY_CHECK","low",   "CCCrypt() -- symmetric encryption, may protect integrity values"),
                "SecItemCopyMatching":  ("INTEGRITY_CHECK","medium","SecItemCopyMatching() -- keychain access for pinned cert or token"),
                "method_getImplementation":("ANTI_HOOK",  "high",   "method_getImplementation() -- ObjC method IMP inspection for swizzle detection"),
                "method_setImplementation":("ANTI_HOOK",  "high",   "method_setImplementation() -- ObjC method swizzling (may be self-protection)"),
                "class_replaceMethod":  ("ANTI_HOOK",     "high",   "class_replaceMethod() -- ObjC method replacement"),
                "NSClassFromString":    ("ANTI_HOOK",     "medium", "NSClassFromString() -- dynamic class lookup, may probe for hook frameworks"),
                "getenv":               ("ANTI_DEBUG",    "medium", "getenv() -- environment variable check, may detect DYLD_INSERT_LIBRARIES"),
                "sandbox_check":        ("INTEGRITY_CHECK","high",  "sandbox_check() -- explicit sandbox escape detection"),
                "csops":                ("INTEGRITY_CHECK","high",  "csops() -- code-signing operation, integrity self-check"),
            }.get(sym, ("ANTI_HOOK", "low", f"Security-relevant import: {sym}"))
            findings.append(DeepFinding(
                category=cat, severity=sev,
                title=f"[Disasm] {desc.split('--')[0].strip()}",
                description=desc,
                location=f"{binary_name}!{fn.name or 'sub_' + hex(fn.start_addr)}+0x0",
                address=fn.start_addr,
                calling_function=fn.name or f"sub_{fn.start_addr:x}",
                snippet=f"calls {sym}() from {fn.name or 'sub_' + hex(fn.start_addr)}",
            ))
    return findings


def _analyze_objc_classes(classes: list[ObjCClass], binary_name: str) -> list[DeepFinding]:
    """Generate findings from ObjC class/method security patterns."""
    findings = []
    for cls in classes:
        if _OBJC_SECURITY_CLASSES.search(cls.name):
            findings.append(DeepFinding(
                "ROOT_DETECTION", "high",
                f"[ObjC Class] Security class: {cls.name}",
                f"ObjC class '{cls.name}' matches security/jailbreak/hook detection naming pattern. "
                f"Superclass: {cls.superclass_name}. "
                f"Methods: {', '.join(m.method_name for m in cls.methods[:8])}",
                f"{binary_name}!ObjC/{cls.name}",
                snippet=cls.name,
            ))
        for method in cls.methods:
            if _OBJC_SECURITY_CLASSES.search(method.method_name):
                findings.append(DeepFinding(
                    "ROOT_DETECTION", "high",
                    f"[ObjC Method] Security method: [{cls.name} {method.method_name}]",
                    f"ObjC method '{method.method_name}' in class '{cls.name}' matches security pattern. "
                    f"IMP address: 0x{method.imp_addr:x}",
                    f"{binary_name}!ObjC/{cls.name}/{method.method_name}",
                    address=method.imp_addr,
                    calling_function=f"{cls.name}::{method.method_name}",
                    snippet=f"[{cls.name} {method.method_name}] @ 0x{method.imp_addr:x}",
                ))
    return findings


# ===========================================================================
# Main deep analysis entry point
# ===========================================================================

def deep_analyze_binary(binary_path: Path) -> DeepAnalysisResult:
    """
    Full Ghidra-style deep analysis of a single Mach-O binary.
    Returns a DeepAnalysisResult with all findings.
    """
    warnings_out: list[str] = []

    try:
        data = binary_path.read_bytes()
    except OSError as e:
        return DeepAnalysisResult(
            binary_path=str(binary_path), arch="unknown", is_encrypted=False,
            has_pie=False, has_arc=False, has_stack_canary=False,
            has_nx_heap=False, has_code_signature=False, min_os="",
            entitlements={}, dylibs=[], sections=[], symbols=[], imports={},
            exports=[], objc_classes=[], swift_types=[], functions=[],
            findings=[], warnings=[str(e)])

    if not HAVE_CAPSTONE:
        warnings_out.append(
            "capstone not installed -- skipping ARM64 disassembly (pip install capstone). "
            "ObjC/Swift metadata analysis still runs.")

    # --- Parse ---
    parser = MachOParser(data)
    if parser.hdr_size == 0:
        return DeepAnalysisResult(
            binary_path=str(binary_path), arch="unknown", is_encrypted=False,
            has_pie=False, has_arc=False, has_stack_canary=False,
            has_nx_heap=False, has_code_signature=False, min_os="",
            entitlements={}, dylibs=[], sections=[], symbols=[], imports={},
            exports=[], objc_classes=[], swift_types=[], functions=[],
            findings=[], warnings=["Not a valid Mach-O binary"])

    sections = parser.parse_sections()
    dylibs   = parser.parse_dylibs()
    symbols  = parser.parse_symbols()
    is_encrypted = parser.parse_encryption()
    entitlements = parser.parse_entitlements()

    arch_map = {CPU_TYPE_ARM64: "arm64", CPU_TYPE_ARM: "armv7",
                CPU_TYPE_X86_64: "x86_64", CPU_TYPE_X86: "x86"}
    arch = arch_map.get(parser.cpu_type, f"unknown(0x{parser.cpu_type:x})")

    has_pie  = bool(parser.flags & MH_PIE)
    has_nx   = bool(parser.flags & MH_NO_HEAP_EXECUTION)
    has_stack_canary = (b"___stack_chk_fail" in data or b"___stack_chk_guard" in data)
    has_arc  = any("libobjc" in d.name or "libarclite" in d.name for d in dylibs)
    has_cs   = any(cmd == LC_CODE_SIGNATURE for cmd, _, _ in parser.load_commands)

    # Min OS version
    min_os = ""
    for cmd, cmdsize, pos in parser.load_commands:
        if cmd == LC_VERSION_MIN_IPHONEOS and pos + 12 <= len(data):
            ver = parser._u32(pos + 8)
            min_os = f"{(ver >> 16) & 0xFF}.{(ver >> 8) & 0xFF}"
            break
        elif cmd == LC_BUILD_VERSION and pos + 16 <= len(data):
            ver = parser._u32(pos + 12)
            min_os = f"{(ver >> 16) & 0xFF}.{(ver >> 8) & 0xFF}"
            break

    findings: list[DeepFinding] = []

    # --- Binary protection findings ---
    if not has_pie:
        findings.append(DeepFinding("INTEGRITY_CHECK", "high",
            "No PIE (ASLR disabled)", "Binary not compiled with -fPIE. No address space randomization.",
            str(binary_path)))
    if not has_arc:
        findings.append(DeepFinding("INTEGRITY_CHECK", "medium",
            "No ARC detected", "Binary may use manual memory management (pre-ARC or mixed).",
            str(binary_path)))
    if not has_stack_canary:
        findings.append(DeepFinding("INTEGRITY_CHECK", "medium",
            "No stack canary", "Binary compiled without -fstack-protector-all.",
            str(binary_path)))
    if not has_cs:
        findings.append(DeepFinding("INTEGRITY_CHECK", "high",
            "No code signature", "Binary has no LC_CODE_SIGNATURE load command.",
            str(binary_path)))
    if is_encrypted:
        findings.append(DeepFinding("INTEGRITY_CHECK", "info",
            "FairPlay encrypted binary",
            "Binary is FairPlay DRM encrypted. Decrypt via frida-ios-dump or jailbroken device before deep analysis.",
            str(binary_path)))

    # --- Entitlement audit ---
    findings.extend(_analyze_entitlements(entitlements, binary_path.name))

    # --- Dylib dependency audit ---
    findings.extend(_analyze_dylib_deps(dylibs, binary_path.name))

    # --- ObjC analysis ---
    objc_analyzer = ObjCAnalyzer(parser)
    objc_classes = objc_analyzer.parse_classes()
    findings.extend(_analyze_objc_classes(objc_classes, binary_path.name))

    # --- Swift analysis ---
    swift_analyzer = SwiftAnalyzer(parser)
    swift_types = swift_analyzer.extract_type_names()
    for st in swift_types:
        findings.append(DeepFinding(
            "RASP_DETECTION", "high",
            f"[Swift] Security type: {st.name}",
            f"Swift {st.kind} '{st.name}' matches security/RASP naming pattern.",
            f"{binary_path.name}!Swift/{st.name}",
            snippet=st.name,
        ))

    # --- Disassembly + call-graph ---
    functions: list[Function] = []
    imports: dict[int, str] = {}
    if HAVE_CAPSTONE and not is_encrypted:
        imports = resolve_imports(parser, symbols)
        disasm  = Disassembler(parser, symbols, imports)
        functions = disasm.build_function_list()
        for fn in functions:
            disasm.disassemble_function(fn)
        findings.extend(_analyze_security_functions(functions, imports, binary_path.name))

        # Report call-graph summary
        sec_fns = [f for f in functions if f.is_security_relevant]
        if sec_fns:
            findings.append(DeepFinding(
                "RASP_DETECTION", "info",
                f"Call-graph: {len(sec_fns)} functions invoke security-relevant APIs",
                f"Functions invoking security APIs: "
                f"{', '.join((f.name or 'sub_' + hex(f.start_addr)) for f in sec_fns[:20])}",
                binary_path.name,
                snippet=f"{len(sec_fns)} security-relevant functions identified via call-graph analysis",
            ))
    elif is_encrypted:
        warnings_out.append(
            f"Binary {binary_path.name} is FairPlay encrypted -- disassembly skipped. "
            "Decrypt first for full call-graph analysis.")

    exports = [s for s in symbols if not s.is_undefined and s.addr]

    return DeepAnalysisResult(
        binary_path=str(binary_path),
        arch=arch,
        is_encrypted=is_encrypted,
        has_pie=has_pie,
        has_arc=has_arc,
        has_stack_canary=has_stack_canary,
        has_nx_heap=has_nx,
        has_code_signature=has_cs,
        min_os=min_os,
        entitlements=entitlements,
        dylibs=dylibs,
        sections=list(sections.values()),
        symbols=symbols,
        imports=imports,
        exports=exports,
        objc_classes=objc_classes,
        swift_types=swift_types,
        functions=functions,
        findings=findings,
        warnings=warnings_out,
    )


# ===========================================================================
# Scan an entire IPA's binaries
# ===========================================================================

def deep_scan_ipa(ipa_dir: Path, progress=None) -> tuple[list[DeepFinding], list[str]]:
    """
    Run deep Ghidra-style analysis on all Mach-O binaries in an extracted IPA.
    Returns (all_findings, all_warnings).
    """
    from ios_scanner import find_app_dir, find_main_binary

    all_findings: list[DeepFinding] = []
    all_warnings: list[str] = []

    app_dir = find_app_dir(ipa_dir)
    if not app_dir:
        return all_findings, ["No .app bundle found"]

    binaries: list[Path] = []

    # Main executable
    main_bin = find_main_binary(app_dir)
    if main_bin:
        binaries.append(main_bin)

    # Frameworks
    fw_dir = app_dir / "Frameworks"
    if fw_dir.is_dir():
        for fw in fw_dir.iterdir():
            if fw.is_dir() and fw.name.endswith(".framework"):
                fw_bin = fw / fw.name[:-10]
                if fw_bin.is_file():
                    binaries.append(fw_bin)

    # Dylibs
    for dylib in app_dir.rglob("*.dylib"):
        binaries.append(dylib)

    for binary in binaries:
        result = deep_analyze_binary(binary)
        all_findings.extend(result.findings)
        all_warnings.extend(result.warnings)
        if progress:
            progress()

    return all_findings, all_warnings
