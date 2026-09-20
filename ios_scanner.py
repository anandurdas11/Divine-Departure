"""
ios_scanner.py

Static analysis of iOS IPA files, modeled after MobSF's iOS analysis pipeline.

Covers:
    1. Info.plist parsing: ATS exceptions, permissions, URL schemes, bundle metadata
    2. Mach-O binary analysis: PIE, ARC, stack canaries, encryption, code signing
    3. String extraction from Mach-O binaries (main executable + embedded frameworks)
    4. Insecure API detection (NSLog, UIPasteboard, _objc_msgSend patterns)
    5. Jailbreak / RASP detection patterns specific to iOS
    6. Embedded framework scanning
    7. Transport security (ATS) configuration audit

No external tools required -- pure Python analysis using struct-level Mach-O parsing
and plistlib for Info.plist.
"""

import os
import plistlib
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from patterns import NATIVE_STRING_PATTERNS, build_prefilter

_NATIVE_GATE, _NATIVE_GATED, _NATIVE_ALWAYS_RUN = build_prefilter(NATIVE_STRING_PATTERNS)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class IOSBinaryInfo:
    name: str
    path: str
    is_encrypted: bool = False
    has_pie: bool = False
    has_arc: bool = False
    has_stack_canary: bool = False
    has_code_signature: bool = False
    min_os_version: str = ""
    architectures: list = field(default_factory=list)


@dataclass
class IOSPlistInfo:
    bundle_id: str = ""
    bundle_name: str = ""
    version: str = ""
    min_os: str = ""
    ats_settings: dict = field(default_factory=dict)
    ats_findings: list = field(default_factory=list)
    permissions: list = field(default_factory=list)
    url_schemes: list = field(default_factory=list)
    exported_utis: list = field(default_factory=list)
    background_modes: list = field(default_factory=list)


@dataclass
class IOSFinding:
    category: str
    severity: str          # "high", "medium", "low", "info"
    title: str
    description: str
    location: str          # file path or binary name
    snippet: str = ""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Mach-O magic numbers
MH_MAGIC_64 = 0xFEEDFACF
MH_MAGIC_32 = 0xFEEDFACE
MH_CIGAM_64 = 0xCFFAEDFE
MH_CIGAM_32 = 0xCEFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

# Mach-O flags
MH_PIE = 0x200000
MH_ALLOW_STACK_EXECUTION = 0x20000

# Mach-O load commands
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_CODE_SIGNATURE = 0x1D
LC_VERSION_MIN_IPHONEOS = 0x25
LC_BUILD_VERSION = 0x32
LC_LOAD_DYLIB = 0x0C

# CPU types
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 0x01000007

CPU_NAMES = {
    CPU_TYPE_ARM: "armv7",
    CPU_TYPE_ARM64: "arm64",
    CPU_TYPE_X86: "x86",
    CPU_TYPE_X86_64: "x86_64",
}

# iOS permission purpose strings (Info.plist keys)
IOS_PERMISSIONS = {
    "NSCameraUsageDescription": "Camera",
    "NSMicrophoneUsageDescription": "Microphone",
    "NSPhotoLibraryUsageDescription": "Photo Library",
    "NSPhotoLibraryAddUsageDescription": "Photo Library (Add)",
    "NSLocationWhenInUseUsageDescription": "Location (In Use)",
    "NSLocationAlwaysUsageDescription": "Location (Always)",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Location (Always & In Use)",
    "NSContactsUsageDescription": "Contacts",
    "NSCalendarsUsageDescription": "Calendars",
    "NSRemindersUsageDescription": "Reminders",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth",
    "NSBluetoothPeripheralUsageDescription": "Bluetooth Peripheral",
    "NSMotionUsageDescription": "Motion & Fitness",
    "NSHealthShareUsageDescription": "Health (Read)",
    "NSHealthUpdateUsageDescription": "Health (Write)",
    "NSAppleMusicUsageDescription": "Media Library",
    "NSSpeechRecognitionUsageDescription": "Speech Recognition",
    "NSSiriUsageDescription": "Siri",
    "NSFaceIDUsageDescription": "Face ID",
    "NSLocalNetworkUsageDescription": "Local Network",
    "NSTrackingUsageDescription": "App Tracking Transparency",
    "NSUserTrackingUsageDescription": "User Tracking",
}

# iOS insecure API patterns
IOS_INSECURE_APIS = [
    # ---- Core insecure APIs ----
    (r"\b_NSLog\b", "ANTI_DEBUG", "medium",
     "NSLog() usage -- logs may leak sensitive data and are visible to debuggers."),
    (r"\bUIPasteboard\b", "INTEGRITY_CHECK", "medium",
     "UIPasteboard usage -- clipboard data can be read by other apps."),
    (r"\b_malloc\b(?!_zone)", "INTEGRITY_CHECK", "low",
     "Direct malloc() usage -- manual memory management, potential for use-after-free."),
    (r"\b_memcpy\b", "INTEGRITY_CHECK", "low",
     "memcpy() usage -- potential buffer overflow if length is not validated."),
    (r"\bCCCrypt\b", "SSL_PINNING", "low",
     "CommonCrypto CCCrypt usage -- verify correct mode/padding."),
    (r"\bkSecAttrAccessibleAlways\b", "INTEGRITY_CHECK", "high",
     "Keychain item accessible when device is locked -- data at risk if device is stolen."),
    (r"\bkSecAttrAccessibleAlwaysThisDeviceOnly\b", "INTEGRITY_CHECK", "medium",
     "Keychain item accessible when device is locked (this device only)."),

    # ---- Classic jailbreak path checks ----
    (r"\bcanOpenURL\b.*cydia", "ROOT_DETECTION", "high",
     "Jailbreak detection via canOpenURL for Cydia."),
    (r"/Applications/Cydia\.app", "ROOT_DETECTION", "high",
     "Jailbreak detection -- checking for Cydia.app path."),
    (r"/Library/MobileSubstrate", "ROOT_DETECTION", "high",
     "Jailbreak detection -- checking for MobileSubstrate path."),
    (r"/usr/sbin/sshd|/usr/bin/ssh", "ROOT_DETECTION", "medium",
     "Jailbreak detection -- checking for SSH daemon."),
    (r"/bin/bash|/bin/sh", "ROOT_DETECTION", "medium",
     "Jailbreak detection -- checking for shell binaries."),
    (r"/etc/apt|/var/lib/apt", "ROOT_DETECTION", "medium",
     "Jailbreak detection -- checking for APT package manager."),
    (r"/private/var/lib/apt", "ROOT_DETECTION", "high",
     "Jailbreak detection -- checking for APT on jailbroken device."),

    # ---- Modern jailbreak tools ----
    (r"unc0ver|checkra1n|palera1n|Dopamine|Fugu15|XinaA15|Taurine|Odyssey|Chimera|Phoenix|Electra|Meridian",
     "ROOT_DETECTION", "high",
     "Modern iOS jailbreak tool name detected in binary strings or source."),
    (r"/var/jb\b|/var/LIB\b|/usr/lib/TweakInject|/usr/lib/tweaks|"
     r"/var/containers/Bundle/DispatcherApp|/Library/TweakInject",
     "ROOT_DETECTION", "high",
     "Modern jailbreak filesystem path check (Dopamine/unc0ver/palera1n paths)."),
    (r"\bSileo\b|\bZebra\b|\bInstaller5\b", "ROOT_DETECTION", "high",
     "Alternative iOS package manager (Sileo/Zebra/Installer5) reference -- jailbreak indicator."),
    (r"bootstrapURL|jailbreakd|\bamfid\b", "ROOT_DETECTION", "high",
     "Jailbreak daemon reference: jailbreakd, amfid bypass, or bootstrapURL."),
    (r"DYLD_INSERT_LIBRARIES", "ROOT_DETECTION", "high",
     "DYLD_INSERT_LIBRARIES environment variable -- dynamic library injection (jailbreak)."),
    (r"SandboxIOSChecker|/etc/fstab.*writ|sandbox.*escape", "ROOT_DETECTION", "high",
     "iOS sandbox escape detection: fstab writable check or sandbox escape attempt."),
    (r'access\("/usr/bin/ssh"\)|access\("/bin/bash"\)', "ROOT_DETECTION", "high",
     "Native access() call probing SSH/bash paths -- jailbreak detection."),
    (r"FileManager\.fileExists\(atPath:\s*[\"']/(?:var/jb|Library/TweakInject|"
     r"usr/lib/TweakInject|var/LIB)", "ROOT_DETECTION", "high",
     "Swift FileManager.fileExists(atPath:) checking known jailbreak paths."),
    (r"Darwin\.fork\(\)|syscall\(SYS_fork\)|syscall\(SYS_ptrace\)", "ROOT_DETECTION", "high",
     "fork()/ptrace() raw syscall -- non-sandboxed processes can fork on jailbroken devices."),
    (r"SandboxIOSChecker|DTTJailbreakDetection|IOSSecuritySuite", "ROOT_DETECTION", "high",
     "iOS jailbreak detection library reference (IOSSecuritySuite, DTTJailbreakDetection)."),

    # ---- Anti-hook ----
    (r"substrate|SubstrateLoader|MobileSubstrate", "ANTI_HOOK", "high",
     "Cydia Substrate / MobileSubstrate hooking framework detection."),
    (r"\bfrida\b|frida-server|frida-agent|gum-js-loop|FridaGadget|frida-agent\.dylib",
     "ANTI_HOOK", "high",
     "Frida instrumentation framework detection."),
    (r"_dyld_image_count|_dyld_get_image_name", "ANTI_HOOK", "high",
     "dyld image enumeration -- scanning loaded dylibs to detect injected frameworks."),
    (r"\bfishhook\b|\blibffi\b|___interpose", "ANTI_HOOK", "high",
     "fishhook / libffi / __interpose section -- iOS symbol interposing hooks."),
    (r"MSHookFunction|MSGetImageByName", "ANTI_HOOK", "high",
     "MobileSubstrate hooking API: MSHookFunction / MSGetImageByName."),
    (r"\bdladdr\b", "ANTI_HOOK", "medium",
     "dladdr() -- resolves address to symbol/library, used to detect unexpected modules."),
    (r"vm_region_64|vm_region\b", "ANTI_HOOK", "medium",
     "vm_region_64() memory region scanning for injected code/hooks."),
    (r"__DATA\.__la_symbol_ptr|la_symbol_ptr", "ANTI_HOOK", "high",
     "Reading __DATA.__la_symbol_ptr to detect PLT-level symbol swizzling."),
    (r"method_getImplementation|method_setImplementation|method_exchangeImplementations",
     "ANTI_HOOK", "medium",
     "ObjC method implementation comparison to detect runtime swizzling (hook detection)."),
    (r"\b27042\b|\b27043\b", "ANTI_HOOK", "medium",
     "Frida default port number -- network-based Frida detection."),

    # ---- Anti-debug ----
    (r"ptrace\(|PT_DENY_ATTACH", "ANTI_DEBUG", "high",
     "ptrace(PT_DENY_ATTACH) -- prevents debugger attachment."),
    (r"sysctl\b.*P_TRACED", "ANTI_DEBUG", "high",
     "sysctl-based debugger detection (P_TRACED flag check)."),
    (r"getppid\(\)", "ANTI_DEBUG", "medium",
     "getppid() check -- may be used to detect debugger parent process."),
    (r"AmIBeingDebugged|isDebugged\b|debuggerAttached", "ANTI_DEBUG", "high",
     "iOS anti-debug function: AmIBeingDebugged / isDebugged check."),
    (r"task_get_exception_ports", "ANTI_DEBUG", "high",
     "task_get_exception_ports() -- detects debugger-installed exception handlers."),
    (r'__asm__\s*\(\s*"svc\s+0x80"\s*\)|asm.*svc.*0x80', "ANTI_DEBUG", "high",
     "Raw ARM64 SVC 0x80 syscall in inline assembly -- anti-debug technique."),
    (r"mach_absolute_time.*delta|delta.*mach_absolute_time", "ANTI_DEBUG", "medium",
     "mach_absolute_time() timing delta check -- detects single-step debugging."),
    (r"CTL_KERN|KERN_PROC\b|KERN_PROC_PID|kinfo_proc\b", "ANTI_DEBUG", "high",
     "sysctl kern.proc.pid -- reads kinfo_proc struct to check P_TRACED flag."),

    # ---- SSL Pinning ----
    (r"SSLPinningDelegate|TrustKit|AFSecurityPolicy", "SSL_PINNING", "high",
     "SSL pinning implementation detected."),
    (r"URLSession\(_:didReceive:completionHandler:\)|urlSession.*didReceive.*challenge",
     "SSL_PINNING", "high",
     "NSURLSession TLS challenge delegate -- implements certificate pinning."),
    (r"SecTrustEvaluateWithError|SecTrustCopyResult", "SSL_PINNING", "high",
     "SecTrustEvaluateWithError / SecTrustCopyResult -- custom TLS trust evaluation."),
    (r"AFSSLPinningMode|AFSecurityPolicy", "SSL_PINNING", "high",
     "AFNetworking SSL pinning mode / security policy configuration."),
    (r"ServerTrustPolicy|ServerTrustEvaluating", "SSL_PINNING", "high",
     "Alamofire ServerTrustPolicy / ServerTrustEvaluating for certificate pinning."),
    (r"TSKSPKIHashCache|kTSKSwizzleNetworkDelegates", "SSL_PINNING", "high",
     "TrustKit iOS SDK: SPKI hash cache and network delegate swizzling."),
    (r"URLCredential\(trust:\)|URLSession\.AuthChallengeDisposition", "SSL_PINNING", "medium",
     "URLCredential(trust:) / AuthChallengeDisposition -- TLS challenge handling."),
    (r"GRPCCall\.setTLSPEMRootCerts", "SSL_PINNING", "high",
     "gRPC iOS TLS PEM root cert pinning via GRPCCall."),
    (r"\.cer\b|\.der\b|\.crt\b", "SSL_PINNING", "medium",
     "Embedded DER/CRT/CER certificate file reference -- bundled pinning cert."),

    # ---- MDM ----
    (r"MDMProfile|com\.apple\.mdm|com\.apple\.configurator", "MDM_CHECK", "high",
     "iOS MDM profile payload type or Apple Configurator reference."),
    (r"NEProfileManager|MDMEnrollment", "MDM_CHECK", "high",
     "NetworkExtension profile manager or MDM enrollment API."),
    (r"CMSupervisedDeviceEnrollment", "MDM_CHECK", "high",
     "Supervised device enrollment API -- corporate MDM provisioning."),
    (r"MGCopyAnswer.*kMGQIsSupervised|isSupervised\b", "MDM_CHECK", "high",
     "Device supervision check: MGCopyAnswer(kMGQIsSupervised) or isSupervised."),
    (r"SCEPCertificateEnrollment", "MDM_CHECK", "high",
     "SCEP certificate enrollment -- MDM certificate provisioning."),
    (r"\bjamf\b|\bkandji\b|\bmosyle\b|\baddigy\b", "MDM_CHECK", "high",
     "iOS MDM vendor SDK reference: Jamf, Kandji, Mosyle, or Addigy."),

    # ---- RASP ----
    (r"IOSSecuritySuite\.amIJailbroken\(\)|IOSSecuritySuite\.amIDebugged\(\)|"
     r"IOSSecuritySuite\.amIReverseEngineered\(\)", "RASP_DETECTION", "high",
     "IOSSecuritySuite RASP API: jailbreak, debug, and reverse engineering detection."),
    (r"TalsecApplication|freeRASP", "RASP_DETECTION", "high",
     "freeRASP / Talsec iOS application RASP protection."),
    (r"Approov\.fetchApproovToken", "RASP_DETECTION", "high",
     "Approov iOS SDK: runtime app attestation token fetch."),
    (r"\bixguard\b|GuardSquare.*iOS|AppProtect", "RASP_DETECTION", "high",
     "GuardSquare iXGuard / AppProtect iOS code protection reference."),
    (r"PromonShield", "RASP_DETECTION", "high",
     "Promon SHIELD iOS app protection SDK."),

    # ---- Simulator / Emulator ----
    (r"TARGET_OS_SIMULATOR|TARGET_IPHONE_SIMULATOR", "EMULATOR_DETECT", "medium",
     "Compile-time simulator target macros -- code path for simulator detection."),
    (r'ProcessInfo\.processInfo\.environment\[.SIMULATOR_DEVICE_NAME.\]',
     "EMULATOR_DETECT", "high",
     "Swift ProcessInfo SIMULATOR_DEVICE_NAME check -- running in Xcode Simulator."),
    (r'UIDevice\.current\.model\s*==\s*["\']iPhone Simulator["\']|'
     r'UIDevice\.current\.model.*Simulator', "EMULATOR_DETECT", "high",
     "UIDevice.current.model == 'iPhone Simulator' runtime simulator check."),
    (r'sysctlbyname\s*\(\s*"hw\.machine"', "EMULATOR_DETECT", "medium",
     "sysctlbyname('hw.machine') -- checks arch; x86_64/arm64 may indicate simulator."),
    (r'NSClassFromString\s*\(\s*["\']XCTestCase["\']', "EMULATOR_DETECT", "medium",
     "NSClassFromString('XCTestCase') -- detects if running under XCTest harness."),

    # ---- Jailbreak generic (kept last as catch-all) ----
    (r"\bisJailbroken\b|\bcheckJailbreak\b|\bjailbreakDetect", "ROOT_DETECTION", "high",
     "Explicit jailbreak detection method."),
    (r"IOKit|IOService", "ROOT_DETECTION", "low",
     "IOKit framework usage -- may be used for hardware-level jailbreak checks."),
]

# Compile iOS patterns once
_IOS_API_PATTERNS = [(re.compile(p, re.IGNORECASE), cat, sev, desc)
                     for p, cat, sev, desc in IOS_INSECURE_APIS]


# ---------------------------------------------------------------------------
# IPA extraction helpers
# ---------------------------------------------------------------------------
def find_app_dir(ipa_dir: Path) -> Path | None:
    """Locate the Payload/*.app directory inside an extracted IPA."""
    payload = ipa_dir / "Payload"
    if not payload.is_dir():
        for d in ipa_dir.rglob("Payload"):
            if d.is_dir():
                payload = d
                break
    if payload.is_dir():
        for item in payload.iterdir():
            if item.is_dir() and item.name.endswith(".app"):
                return item
    return None


def find_main_binary(app_dir: Path) -> Path | None:
    """Find the main executable Mach-O binary inside a .app bundle."""
    plist_path = app_dir / "Info.plist"
    if plist_path.is_file():
        try:
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
            exe_name = plist.get("CFBundleExecutable")
            if exe_name:
                candidate = app_dir / exe_name
                if candidate.is_file():
                    return candidate
        except Exception:
            pass
    stem = app_dir.name[:-4]
    candidate = app_dir / stem
    if candidate.is_file():
        return candidate
    return None


# ---------------------------------------------------------------------------
# Mach-O binary analysis (MobSF-style)
# ---------------------------------------------------------------------------
def analyze_macho(binary_path: Path) -> IOSBinaryInfo:
    """Analyze a Mach-O binary for security protections."""
    info = IOSBinaryInfo(name=binary_path.name, path=str(binary_path))
    try:
        data = binary_path.read_bytes()
    except OSError:
        return info

    if len(data) < 28:
        return info

    magic = struct.unpack("<I", data[:4])[0]
    offset = 0
    endian = "<"

    # Handle FAT binaries -- skip to first slice
    if magic in (FAT_MAGIC, FAT_CIGAM):
        be = magic == FAT_CIGAM
        fmt = ">I" if be else "<I"
        narch = struct.unpack(fmt, data[4:8])[0]
        if narch > 0 and len(data) >= 20:
            offset = struct.unpack(fmt, data[16:20])[0]

    if offset + 28 > len(data):
        return info

    magic = struct.unpack("<I", data[offset:offset + 4])[0]
    if magic in (MH_CIGAM_32, MH_CIGAM_64):
        endian = ">"
    elif magic not in (MH_MAGIC_32, MH_MAGIC_64):
        return info

    is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    hdr_size = 32 if is_64 else 28

    if offset + hdr_size > len(data):
        return info

    fmt = f"{endian}IiiIIIII" if is_64 else f"{endian}IiiIIII"
    try:
        fields = struct.unpack(fmt, data[offset:offset + hdr_size])
    except struct.error:
        return info

    cputype = fields[1]
    flags = fields[7] if is_64 else fields[6]

    info.architectures = [CPU_NAMES.get(cputype, f"unknown({cputype})")]
    info.has_pie = bool(flags & MH_PIE)

    # Walk load commands
    ncmds = fields[4]
    pos = offset + hdr_size
    dylibs = []

    for _ in range(min(ncmds, 512)):
        if pos + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", data[pos:pos + 8])
        if cmdsize < 8 or pos + cmdsize > len(data):
            break

        if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            if pos + 20 <= len(data):
                cryptid = struct.unpack(f"{endian}I", data[pos + 16:pos + 20])[0]
                info.is_encrypted = cryptid != 0

        elif cmd == LC_CODE_SIGNATURE:
            info.has_code_signature = True

        elif cmd == LC_VERSION_MIN_IPHONEOS:
            if pos + 12 <= len(data):
                ver = struct.unpack(f"{endian}I", data[pos + 8:pos + 12])[0]
                major = (ver >> 16) & 0xFF
                minor = (ver >> 8) & 0xFF
                info.min_os_version = f"{major}.{minor}"

        elif cmd == LC_BUILD_VERSION:
            if pos + 16 <= len(data):
                ver = struct.unpack(f"{endian}I", data[pos + 12:pos + 16])[0]
                major = (ver >> 16) & 0xFF
                minor = (ver >> 8) & 0xFF
                info.min_os_version = f"{major}.{minor}"

        elif cmd == LC_LOAD_DYLIB:
            if pos + 12 <= len(data):
                name_offset = struct.unpack(f"{endian}I", data[pos + 8:pos + 12])[0]
                name_start = pos + name_offset
                if name_start < pos + cmdsize:
                    name_end = data.find(b"\x00", name_start, pos + cmdsize)
                    if name_end == -1:
                        name_end = pos + cmdsize
                    dylib_name = data[name_start:name_end].decode("utf-8", errors="ignore")
                    dylibs.append(dylib_name)

        pos += cmdsize

    info.has_arc = any("libobjc" in d or "libarclite" in d for d in dylibs)
    info.has_stack_canary = b"___stack_chk_fail" in data or b"___stack_chk_guard" in data

    return info


def binary_findings(info: IOSBinaryInfo) -> list[IOSFinding]:
    """Generate security findings from Mach-O analysis results."""
    findings = []
    loc = info.path

    if not info.has_pie:
        findings.append(IOSFinding(
            "INTEGRITY_CHECK", "high",
            "Binary not compiled with PIE (Position Independent Executable)",
            "The binary lacks ASLR protection. Compile with -fPIE to mitigate memory corruption attacks.",
            loc))

    if not info.has_arc:
        findings.append(IOSFinding(
            "INTEGRITY_CHECK", "medium",
            "Binary may not use ARC (Automatic Reference Counting)",
            "Manual memory management increases risk of use-after-free and double-free vulnerabilities.",
            loc))

    if not info.has_stack_canary:
        findings.append(IOSFinding(
            "INTEGRITY_CHECK", "medium",
            "No stack canary detected",
            "Binary may be vulnerable to stack buffer overflows. Compile with -fstack-protector-all.",
            loc))

    if not info.has_code_signature:
        findings.append(IOSFinding(
            "INTEGRITY_CHECK", "high",
            "No code signature detected",
            "Binary lacks code signing. This is unusual for iOS apps and may indicate tampering.",
            loc))

    if info.is_encrypted:
        findings.append(IOSFinding(
            "INTEGRITY_CHECK", "info",
            "Binary is encrypted (FairPlay DRM)",
            "Encrypted binary detected. Decryption is needed before deeper static analysis.",
            loc))

    return findings


# ---------------------------------------------------------------------------
# Info.plist analysis (MobSF-style)
# ---------------------------------------------------------------------------
def analyze_plist(app_dir: Path) -> tuple[IOSPlistInfo, list[IOSFinding]]:
    """Parse Info.plist and audit ATS, permissions, URL schemes."""
    plist_info = IOSPlistInfo()
    findings = []

    plist_path = app_dir / "Info.plist"
    if not plist_path.is_file():
        return plist_info, findings

    try:
        with open(plist_path, "rb") as f:
            plist = plistlib.load(f)
    except Exception:
        return plist_info, findings

    plist_info.bundle_id = plist.get("CFBundleIdentifier", "")
    plist_info.bundle_name = plist.get("CFBundleDisplayName", plist.get("CFBundleName", ""))
    plist_info.version = plist.get("CFBundleShortVersionString", plist.get("CFBundleVersion", ""))
    plist_info.min_os = plist.get("MinimumOSVersion", "")

    # Permissions
    for key, label in IOS_PERMISSIONS.items():
        if key in plist:
            purpose = plist[key] if isinstance(plist[key], str) else str(plist[key])
            plist_info.permissions.append({"permission": label, "purpose": purpose})

    # URL Schemes
    url_types = plist.get("CFBundleURLTypes", [])
    for ut in url_types:
        schemes = ut.get("CFBundleURLSchemes", [])
        plist_info.url_schemes.extend(schemes)

    if plist_info.url_schemes:
        findings.append(IOSFinding(
            "INTEGRITY_CHECK", "info",
            f"App registers {len(plist_info.url_schemes)} custom URL scheme(s)",
            f"URL schemes: {', '.join(plist_info.url_schemes[:10])}. "
            "Custom URL schemes can be hijacked by malicious apps if not properly validated.",
            str(plist_path)))

    # Background modes
    plist_info.background_modes = plist.get("UIBackgroundModes", [])

    # --- ATS (App Transport Security) analysis ---
    ats = plist.get("NSAppTransportSecurity", {})
    plist_info.ats_settings = ats

    if not ats:
        findings.append(IOSFinding(
            "SSL_PINNING", "info",
            "App Transport Security uses default settings",
            "No NSAppTransportSecurity key found. Default ATS enforces HTTPS with TLS 1.2+.",
            str(plist_path)))
    else:
        if ats.get("NSAllowsArbitraryLoads", False):
            findings.append(IOSFinding(
                "SSL_PINNING", "high",
                "ATS globally disabled -- NSAllowsArbitraryLoads = YES",
                "All HTTP connections are allowed. This completely disables App Transport Security.",
                str(plist_path)))
            plist_info.ats_findings.append("NSAllowsArbitraryLoads = YES (ATS disabled globally)")

        if ats.get("NSAllowsArbitraryLoadsInWebContent", False):
            findings.append(IOSFinding(
                "SSL_PINNING", "medium",
                "ATS disabled for web content -- NSAllowsArbitraryLoadsInWebContent = YES",
                "WebView content can load over insecure HTTP.",
                str(plist_path)))

        if ats.get("NSAllowsArbitraryLoadsForMedia", False):
            findings.append(IOSFinding(
                "SSL_PINNING", "medium",
                "ATS disabled for media -- NSAllowsArbitraryLoadsForMedia = YES",
                "Media content (AV Foundation) can be loaded over insecure HTTP.",
                str(plist_path)))

        if ats.get("NSAllowsLocalNetworking", False):
            findings.append(IOSFinding(
                "SSL_PINNING", "low",
                "ATS allows local networking",
                "NSAllowsLocalNetworking = YES. Local network connections bypass ATS.",
                str(plist_path)))

        # Per-domain exceptions
        exceptions = ats.get("NSExceptionDomains", {})
        for domain, settings in exceptions.items():
            if settings.get("NSExceptionAllowsInsecureHTTPLoads", False) or \
               settings.get("NSTemporaryExceptionAllowsInsecureHTTPLoads", False):
                findings.append(IOSFinding(
                    "SSL_PINNING", "high",
                    f"ATS exception: insecure HTTP allowed for {domain}",
                    f"Domain '{domain}' allows insecure HTTP loads, bypassing TLS requirements.",
                    str(plist_path)))

            min_tls = settings.get("NSExceptionMinimumTLSVersion",
                                   settings.get("NSTemporaryExceptionMinimumTLSVersion", ""))
            if min_tls and min_tls < "TLSv1.2":
                findings.append(IOSFinding(
                    "SSL_PINNING", "medium",
                    f"ATS exception: weak TLS ({min_tls}) for {domain}",
                    f"Domain '{domain}' allows connections with {min_tls}, which is considered weak.",
                    str(plist_path)))

            if settings.get("NSIncludesSubdomains", False):
                findings.append(IOSFinding(
                    "SSL_PINNING", "low",
                    f"ATS exception for {domain} includes all subdomains",
                    f"The ATS exception for '{domain}' applies to all subdomains.",
                    str(plist_path)))

    return plist_info, findings


# ---------------------------------------------------------------------------
# String-based scanning of Mach-O binaries
# ---------------------------------------------------------------------------
def scan_binary_strings(binary_path: Path) -> list[IOSFinding]:
    """Extract strings from a Mach-O binary and scan for security-relevant patterns."""
    findings = []
    try:
        data = binary_path.read_bytes()
    except OSError:
        return findings

    loc = str(binary_path)

    for match in re.finditer(b"[ -~]{5,}", data):
        s = match.group().decode("ascii", errors="ignore")
        if len(s) > 4000:
            continue

        # iOS-specific insecure API patterns
        for pat_re, cat, sev, desc in _IOS_API_PATTERNS:
            if pat_re.search(s):
                findings.append(IOSFinding(
                    category=cat, severity=sev,
                    title=desc.split("--")[0].strip() if "--" in desc else desc[:60],
                    description=desc, location=loc, snippet=s[:150]))

        # Shared native string patterns (root, hook, debug, RASP, etc.)
        if _NATIVE_GATE is not None and _NATIVE_GATE.search(s):
            candidates = _NATIVE_GATED + _NATIVE_ALWAYS_RUN
        else:
            candidates = _NATIVE_ALWAYS_RUN
        for pat in candidates:
            if pat["regex"].search(s):
                findings.append(IOSFinding(
                    category=pat["category"], severity=pat["confidence"],
                    title=pat["name"], description=pat["description"],
                    location=loc, snippet=s[:150]))

    return findings


# ---------------------------------------------------------------------------
# Scan embedded frameworks
# ---------------------------------------------------------------------------
def scan_embedded_frameworks(app_dir: Path) -> list[IOSFinding]:
    """Scan all embedded .framework bundles for security patterns."""
    findings = []
    frameworks_dir = app_dir / "Frameworks"
    if not frameworks_dir.is_dir():
        return findings

    for fw_dir in frameworks_dir.iterdir():
        if not fw_dir.is_dir() or not fw_dir.name.endswith(".framework"):
            continue

        fw_name = fw_dir.name[:-10]  # strip .framework

        rasp_indicators = [
            "Promon", "Shield", "DexGuard", "Arxan", "Appdome", "Zimperium",
            "Approov", "iVerify", "AppSealing", "LIAPP", "Guardsquare",
            "IOSSecuritySuite", "DTTJailbreakDetection", "FreeRASP",
        ]
        for indicator in rasp_indicators:
            if indicator.lower() in fw_name.lower():
                findings.append(IOSFinding(
                    "RASP_DETECTION", "high",
                    f"RASP framework detected: {fw_name}",
                    f"Embedded framework '{fw_name}' matches known RASP/app-shielding vendor.",
                    str(fw_dir)))

        fw_binary = fw_dir / fw_name
        if fw_binary.is_file():
            findings.extend(scan_binary_strings(fw_binary))

    return findings


# ---------------------------------------------------------------------------
# Ghidra-like deep Mach-O decompilation (class-dump / symbol extraction)
# ---------------------------------------------------------------------------
LC_SYMTAB = 0x02
LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19

# Jailbreak / security-related ObjC patterns to match against extracted class/method names
_OBJC_SECURITY_PATTERNS = [
    # ---- Jailbreak / Root detection ----
    (re.compile(r"jailbr(?:eak|oken)", re.IGNORECASE), "ROOT_DETECTION", "high",
     "Jailbreak detection method/class in ObjC metadata."),
    (re.compile(r"isJailbroken|checkJailbreak|detectJailbreak|jailbreakCheck", re.IGNORECASE),
     "ROOT_DETECTION", "high",
     "Explicit jailbreak detection method found in ObjC class dump."),
    (re.compile(r"cydia|sileo|zebra|unc0ver|checkra1n|palera1n|dopamine|taurine|odyssey|"
                r"chimera|phoenix|electra|meridian|fugu15|xinaa15", re.IGNORECASE),
     "ROOT_DETECTION", "high",
     "Jailbreak tool/app reference found in ObjC metadata."),
    (re.compile(r"canOpenURL.*cydia|UIApplication.*openURL.*cydia", re.IGNORECASE),
     "ROOT_DETECTION", "high",
     "Jailbreak detection via URL scheme check."),
    (re.compile(r"/var/jb|TweakInject|/usr/lib/tweaks|jailbreakd|amfid|bootstrapURL",
                re.IGNORECASE), "ROOT_DETECTION", "high",
     "Modern jailbreak path or daemon reference in ObjC metadata."),
    (re.compile(r"DYLD_INSERT_LIBRARIES|dyldInsert", re.IGNORECASE), "ROOT_DETECTION", "high",
     "DYLD library injection path found in ObjC metadata."),
    (re.compile(r"fileExistsAtPath|fileExists.*jailbreak|jailbreak.*fileExists",
                re.IGNORECASE), "ROOT_DETECTION", "medium",
     "File existence check targeting jailbreak paths in ObjC metadata."),
    (re.compile(r"SandboxIOSChecker|sandboxEscape|fstabWritable", re.IGNORECASE),
     "ROOT_DETECTION", "high",
     "Sandbox escape detection found in ObjC class dump."),

    # ---- Anti-debug ----
    (re.compile(r"isDebugged|antiDebug|debuggerAttached|ptrace|PT_DENY_ATTACH|sysctl.*P_TRACED",
                re.IGNORECASE), "ANTI_DEBUG", "high",
     "Anti-debug mechanism found in ObjC metadata."),
    (re.compile(r"AmIBeingDebugged|amIBeingDebugged", re.IGNORECASE), "ANTI_DEBUG", "high",
     "AmIBeingDebugged anti-debug function in ObjC metadata."),
    (re.compile(r"task_get_exception_ports|exceptionPorts", re.IGNORECASE), "ANTI_DEBUG", "high",
     "Exception port check (anti-debug) in ObjC metadata."),
    (re.compile(r"machAbsoluteTime|mach_absolute_time|timingAntiDebug", re.IGNORECASE),
     "ANTI_DEBUG", "medium",
     "Timing-based anti-debug mechanism in ObjC metadata."),
    (re.compile(r"kinfo_proc|P_TRACED|CTL_KERN|KERN_PROC", re.IGNORECASE), "ANTI_DEBUG", "high",
     "sysctl kinfo_proc P_TRACED check in ObjC metadata."),
    (re.compile(r"getppid|parentProcessID|ppidCheck", re.IGNORECASE), "ANTI_DEBUG", "medium",
     "Parent process ID check (anti-debug heuristic) in ObjC metadata."),

    # ---- Anti-hook ----
    (re.compile(r"fridaDetect|antiFrida|hookDetect|antiHook|detectHook|checkFrida|isFridaRunning",
                re.IGNORECASE), "ANTI_HOOK", "high",
     "Anti-hooking / anti-Frida mechanism in ObjC metadata."),
    (re.compile(r"MobileSubstrate|substrate|SubstrateLoader|CydiaSubstrate", re.IGNORECASE),
     "ANTI_HOOK", "high",
     "Cydia Substrate hooking framework reference in ObjC metadata."),
    (re.compile(r"_dyld_image_count|_dyld_get_image_name|dyldImageScan|injectedDylib",
                re.IGNORECASE), "ANTI_HOOK", "high",
     "dyld image enumeration for injected library detection in ObjC metadata."),
    (re.compile(r"fishhook|libffi|___interpose|interposeSection", re.IGNORECASE),
     "ANTI_HOOK", "high",
     "fishhook / libffi / interpose hooking in ObjC metadata."),
    (re.compile(r"MSHookFunction|MSGetImageByName|hookFunction|mobileSubstrateHook",
                re.IGNORECASE), "ANTI_HOOK", "high",
     "MobileSubstrate hook API in ObjC metadata."),
    (re.compile(r"vm_region_64|vmRegionScan|memoryRegion", re.IGNORECASE),
     "ANTI_HOOK", "medium",
     "Memory region scanning for hook detection in ObjC metadata."),
    (re.compile(r"method_getImplementation|methodSwizzle|swizzleDetect|swizzled",
                re.IGNORECASE), "ANTI_HOOK", "medium",
     "ObjC method swizzle detection in class dump."),
    (re.compile(r"la_symbol_ptr|symbolPtrCheck|pltHook", re.IGNORECASE), "ANTI_HOOK", "high",
     "PLT/symbol pointer integrity check in ObjC metadata."),

    # ---- SSL pinning ----
    (re.compile(r"SSLPinning|certificatePinning|pinnedCertificate|TrustKit|AFSecurityPolicy|"
                r"evaluateServerTrust|SecTrustEvaluate", re.IGNORECASE), "SSL_PINNING", "high",
     "SSL/Certificate pinning implementation found in ObjC metadata."),
    (re.compile(r"AFSSLPinningMode|AFSecurityPolicy|AFNetworking.*pin", re.IGNORECASE),
     "SSL_PINNING", "high",
     "AFNetworking SSL pinning configuration in ObjC metadata."),
    (re.compile(r"ServerTrustPolicy|ServerTrustEvaluating|alamofire.*trust", re.IGNORECASE),
     "SSL_PINNING", "high",
     "Alamofire server trust policy in ObjC metadata."),
    (re.compile(r"TSKSPKIHashCache|kTSKSwizzleNetworkDelegates|TrustKit.*pin", re.IGNORECASE),
     "SSL_PINNING", "high",
     "TrustKit iOS SDK in ObjC metadata."),
    (re.compile(r"GRPCCall.*TLS|setTLSPEMRootCerts", re.IGNORECASE), "SSL_PINNING", "high",
     "gRPC TLS certificate pinning in ObjC metadata."),
    (re.compile(r"URLCredential.*trust|AuthChallengeDisposition", re.IGNORECASE),
     "SSL_PINNING", "medium",
     "URLCredential trust challenge handling in ObjC metadata."),

    # ---- RASP ----
    (re.compile(r"IOSSecuritySuite|DTTJailbreakDetection|FreeRASP|AppProtection|TalsecApp",
                re.IGNORECASE), "RASP_DETECTION", "high",
     "RASP / security suite framework detected in ObjC class dump."),
    (re.compile(r"amIJailbroken|amIDebugged|amIReverseEngineered", re.IGNORECASE),
     "RASP_DETECTION", "high",
     "IOSSecuritySuite RASP check method in ObjC metadata."),
    (re.compile(r"Approov|fetchApproovToken|approovToken", re.IGNORECASE),
     "RASP_DETECTION", "high",
     "Approov app attestation SDK in ObjC metadata."),
    (re.compile(r"PromonShield|promon.*shield", re.IGNORECASE), "RASP_DETECTION", "high",
     "Promon SHIELD iOS app protection in ObjC metadata."),

    # ---- Integrity ----
    (re.compile(r"IntegrityCheck|tamperDetect|signatureVerif|codeSignCheck", re.IGNORECASE),
     "INTEGRITY_CHECK", "high",
     "Integrity/tamper detection mechanism in ObjC metadata."),
    (re.compile(r"codesign|codeSignature|signingCert|bundleIntegrity", re.IGNORECASE),
     "INTEGRITY_CHECK", "medium",
     "Code signing / bundle integrity check in ObjC metadata."),

    # ---- Simulator detection ----
    (re.compile(r"isSimulator|simulatorCheck|detectSimulator|TARGET_OS_SIMULATOR|"
                r"TARGET_IPHONE_SIMULATOR|SIMULATOR_DEVICE_NAME", re.IGNORECASE),
     "EMULATOR_DETECT", "high",
     "Simulator detection method found in ObjC metadata."),
    (re.compile(r"hw\.machine|sysctlbyname.*machine|archCheck", re.IGNORECASE),
     "EMULATOR_DETECT", "medium",
     "Hardware machine name check (simulator detection) in ObjC metadata."),
    (re.compile(r"XCTestCase|XCTestBundle|xctest", re.IGNORECASE), "EMULATOR_DETECT", "medium",
     "XCTest framework reference -- running under test harness."),

    # ---- MDM ----
    (re.compile(r"MDMProfile|com\.apple\.mdm|isSupervised|supervisedDevice|"
                r"NEProfileManager|MDMEnrollment|SCEPEnrollment", re.IGNORECASE),
     "MDM_CHECK", "high",
     "MDM profile / supervision detection in ObjC metadata."),
    (re.compile(r"MGCopyAnswer|MobileGestalt|kMGQIsSupervised", re.IGNORECASE),
     "MDM_CHECK", "high",
     "MobileGestalt supervision query in ObjC metadata."),
    (re.compile(r"jamf|kandji|mosyle|addigy", re.IGNORECASE), "MDM_CHECK", "high",
     "iOS MDM vendor SDK (Jamf/Kandji/Mosyle/Addigy) in ObjC metadata."),

    # ---- Known RASP vendors ----
    (re.compile(r"Promon|Arxan|Appdome|Zimperium|Guardsquare|iXGuard|Approov|"
                r"DexGuard|ixGuard", re.IGNORECASE), "RASP_DETECTION", "high",
     "Known RASP vendor class/symbol detected in ObjC metadata."),
]



def _extract_macho_sections(data: bytes, offset: int = 0) -> dict[str, tuple[int, int]]:
    """Extract section name -> (file_offset, size) map from a Mach-O binary."""
    sections = {}
    if offset + 28 > len(data):
        return sections

    magic = struct.unpack("<I", data[offset:offset + 4])[0]
    endian = ">"  if magic in (MH_CIGAM_32, MH_CIGAM_64) else "<"
    is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    hdr_size = 32 if is_64 else 28

    if offset + hdr_size > len(data):
        return sections

    fmt = f"{endian}IiiIIIII" if is_64 else f"{endian}IiiIIII"
    try:
        fields = struct.unpack(fmt, data[offset:offset + hdr_size])
    except struct.error:
        return sections

    ncmds = fields[4]
    pos = offset + hdr_size

    for _ in range(min(ncmds, 512)):
        if pos + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", data[pos:pos + 8])
        if cmdsize < 8 or pos + cmdsize > len(data):
            break

        if cmd == LC_SEGMENT_64 and pos + 72 <= len(data):
            segname = data[pos + 8:pos + 24].split(b"\x00")[0].decode("ascii", errors="ignore")
            nsects = struct.unpack(f"{endian}I", data[pos + 64:pos + 68])[0]
            sec_pos = pos + 72
            for _ in range(min(nsects, 256)):
                if sec_pos + 80 > len(data):
                    break
                sectname = data[sec_pos:sec_pos + 16].split(b"\x00")[0].decode("ascii", errors="ignore")
                sec_offset = struct.unpack(f"{endian}I", data[sec_pos + 48:sec_pos + 52])[0]
                sec_size = struct.unpack(f"{endian}Q", data[sec_pos + 32:sec_pos + 40])[0]
                sections[sectname] = (sec_offset, sec_size)
                sec_pos += 80

        elif cmd == LC_SEGMENT and pos + 56 <= len(data):
            segname = data[pos + 8:pos + 24].split(b"\x00")[0].decode("ascii", errors="ignore")
            nsects = struct.unpack(f"{endian}I", data[pos + 48:pos + 52])[0]
            sec_pos = pos + 56
            for _ in range(min(nsects, 256)):
                if sec_pos + 68 > len(data):
                    break
                sectname = data[sec_pos:sec_pos + 16].split(b"\x00")[0].decode("ascii", errors="ignore")
                sec_offset = struct.unpack(f"{endian}I", data[sec_pos + 40:sec_pos + 44])[0]
                sec_size = struct.unpack(f"{endian}I", data[sec_pos + 32:sec_pos + 36])[0]
                sections[sectname] = (sec_offset, sec_size)
                sec_pos += 68

        pos += cmdsize

    return sections


def _extract_cstrings_from_section(data: bytes, sec_offset: int, sec_size: int) -> list[str]:
    """Extract null-terminated C strings from a binary section."""
    strings = []
    end = min(sec_offset + sec_size, len(data))
    if sec_offset >= len(data):
        return strings
    raw = data[sec_offset:end]
    for s in raw.split(b"\x00"):
        if len(s) >= 3:
            try:
                txt = s.decode("utf-8", errors="ignore").strip()
                if txt and all(32 <= ord(c) < 127 for c in txt[:50]):
                    strings.append(txt)
            except Exception:
                continue
    return strings


def _extract_nlist_symbols(data: bytes, offset: int = 0) -> list[str]:
    """Extract function/class names from the Mach-O nlist symbol table (LC_SYMTAB)."""
    symbols = []
    if offset + 28 > len(data):
        return symbols

    magic = struct.unpack("<I", data[offset:offset + 4])[0]
    endian = ">" if magic in (MH_CIGAM_32, MH_CIGAM_64) else "<"
    is_64 = magic in (MH_MAGIC_64, MH_CIGAM_64)
    hdr_size = 32 if is_64 else 28

    if offset + hdr_size > len(data):
        return symbols

    fmt = f"{endian}IiiIIIII" if is_64 else f"{endian}IiiIIII"
    try:
        fields = struct.unpack(fmt, data[offset:offset + hdr_size])
    except struct.error:
        return symbols

    ncmds = fields[4]
    pos = offset + hdr_size

    for _ in range(min(ncmds, 512)):
        if pos + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", data[pos:pos + 8])
        if cmdsize < 8 or pos + cmdsize > len(data):
            break

        if cmd == LC_SYMTAB and pos + 24 <= len(data):
            symoff, nsyms, stroff, strsize = struct.unpack(
                f"{endian}IIII", data[pos + 8:pos + 24])
            nlist_size = 16 if is_64 else 12
            str_end = min(stroff + strsize, len(data))

            for i in range(min(nsyms, 100000)):
                entry_pos = symoff + i * nlist_size
                if entry_pos + 4 > len(data):
                    break
                str_idx = struct.unpack(f"{endian}I", data[entry_pos:entry_pos + 4])[0]
                name_start = stroff + str_idx
                if name_start >= str_end:
                    continue
                name_end = data.find(b"\x00", name_start, str_end)
                if name_end == -1:
                    name_end = str_end
                name = data[name_start:name_end].decode("utf-8", errors="ignore")
                if len(name) >= 3:
                    symbols.append(name)
            break  # only one LC_SYMTAB

        pos += cmdsize

    return symbols


def deep_decompile_binary(binary_path: Path) -> list[IOSFinding]:
    """
    Ghidra-like deep decompilation of a Mach-O binary:
    - Extract ObjC class names from __objc_classname section
    - Extract ObjC method selectors from __objc_methnames and __objc_selrefs
    - Extract all nlist symbol table entries
    - Scan all extracted metadata against security patterns
    """
    findings = []
    try:
        data = binary_path.read_bytes()
    except OSError:
        return findings

    if len(data) < 28:
        return findings

    # Handle FAT binary
    magic = struct.unpack("<I", data[:4])[0]
    offset = 0
    if magic in (FAT_MAGIC, FAT_CIGAM):
        be = magic == FAT_CIGAM
        fmt = ">I" if be else "<I"
        narch = struct.unpack(fmt, data[4:8])[0]
        if narch > 0 and len(data) >= 20:
            offset = struct.unpack(fmt, data[16:20])[0]

    loc = str(binary_path)

    # 1. Extract ObjC metadata sections
    sections = _extract_macho_sections(data, offset)
    all_metadata_strings = set()

    for sec_name in ("__objc_classname", "__objc_methnames", "__objc_selrefs",
                     "__objc_classrefs", "__cstring"):
        if sec_name in sections:
            sec_off, sec_size = sections[sec_name]
            strings = _extract_cstrings_from_section(data, sec_off, sec_size)
            all_metadata_strings.update(strings)

    # 2. Extract nlist symbol table
    nlist_syms = _extract_nlist_symbols(data, offset)
    all_metadata_strings.update(nlist_syms)

    # 3. Scan all extracted metadata against security patterns
    for s in all_metadata_strings:
        for pat_re, cat, sev, desc in _OBJC_SECURITY_PATTERNS:
            if pat_re.search(s):
                findings.append(IOSFinding(
                    category=cat, severity=sev,
                    title=f"[ObjC Decompile] {desc.split('.')[0]}",
                    description=desc,
                    location=loc,
                    snippet=s[:200]))

        # Also run iOS API patterns against class/method names
        for pat_re, cat, sev, desc in _IOS_API_PATTERNS:
            if pat_re.search(s):
                findings.append(IOSFinding(
                    category=cat, severity=sev,
                    title=f"[ObjC Decompile] {desc.split('--')[0].strip() if '--' in desc else desc[:60]}",
                    description=desc,
                    location=loc,
                    snippet=s[:200]))

    # 4. Report extracted ObjC class count as info finding
    class_names = []
    if "__objc_classname" in sections:
        sec_off, sec_size = sections["__objc_classname"]
        class_names = _extract_cstrings_from_section(data, sec_off, sec_size)

    method_names = []
    if "__objc_methnames" in sections:
        sec_off, sec_size = sections["__objc_methnames"]
        method_names = _extract_cstrings_from_section(data, sec_off, sec_size)

    if class_names or method_names:
        findings.append(IOSFinding(
            "INTEGRITY_CHECK", "info",
            f"Binary decompiled: {len(class_names)} ObjC classes, "
            f"{len(method_names)} methods, {len(nlist_syms)} symbols extracted",
            f"Deep Mach-O analysis extracted Objective-C metadata. "
            f"Sample classes: {', '.join(class_names[:8])}",
            loc,
            snippet=f"symbols: {', '.join(nlist_syms[:10])}"))

    return findings


# ---------------------------------------------------------------------------
# MDM profile / configuration scanning
# ---------------------------------------------------------------------------

# MDM-related plist keys to flag in Info.plist or mobileconfig payloads
IOS_MDM_PATTERNS = [
    # Payload type identifiers
    "com.apple.mdm",
    "com.apple.configurator",
    "com.apple.certificate",
    "com.apple.vpn.managed",
    "com.apple.wifi.managed",
    "com.apple.email.managed",
    "com.apple.webClip.managed",
    "com.apple.app-sandbox",
    "com.apple.security.scep",
    "com.apple.security.pkcs1",
    "com.apple.security.pem",
    "com.apple.proxy.managed",
    "com.apple.globalhttp.managed",
    "com.apple.caldav.account",
    "com.apple.carddav.account",
    "com.apple.fonts",
    "com.apple.applicationaccess",
    "com.apple.applicationaccess.new",
    "com.apple.restrictions",
    # Keys
    "PayloadType",
    "PayloadOrganization",
    "PayloadDisplayName",
    "PayloadIdentifier",
    "PayloadContent",
    "IsSupervised",
    "IsMDMEnrollmentRequired",
    "IsDeviceEnrollmentEnabled",
    "MDMOptions",
    "CheckInURL",
    "ServerURL",
    "EnrollmentURL",
    "TopicIdentifier",
    "ServerCapabilities",
    "SignMessage",
    "AccessRights",
]

_MDM_CERT_EXTS = {".cer", ".der", ".crt", ".pem", ".p12", ".pfx", ".p7b"}


def scan_mdm_config(app_dir: Path) -> list[IOSFinding]:
    """
    Scan the app bundle for MDM enrollment profiles and SCEP/MDM certificate files.

    Checks:
    1. Payload/*.mobileconfig files -- MDM enrollment profiles
    2. Info.plist and any embedded *.plist for MDM-related keys
    3. Embedded certificate files (.cer/.der/.crt/.pem/.p12) -- MDM/SCEP cert pinning
    """
    findings: list[IOSFinding] = []
    app_parent = app_dir.parent  # Payload/

    # ------------------------------------------------------------------ #
    # 1. Scan Payload directory and app bundle for *.mobileconfig files   #
    # ------------------------------------------------------------------ #
    search_roots = [app_parent, app_dir]
    mobileconfig_files: list[Path] = []
    for root in search_roots:
        if root.is_dir():
            mobileconfig_files.extend(root.rglob("*.mobileconfig"))

    for mc_path in mobileconfig_files:
        try:
            with open(mc_path, "rb") as f:
                profile = plistlib.load(f)
        except Exception:
            # Might be XML or binary plist; try text read for pattern matching
            try:
                raw = mc_path.read_text(encoding="utf-8", errors="ignore")
                matched_keys = [k for k in IOS_MDM_PATTERNS if k.lower() in raw.lower()]
                if matched_keys:
                    findings.append(IOSFinding(
                        "MDM_CHECK", "high",
                        f"MDM profile found: {mc_path.name}",
                        f"Mobileconfig profile contains MDM-related keys: {', '.join(matched_keys[:8])}",
                        str(mc_path),
                        snippet=raw[:300]))
            except OSError:
                pass
            continue

        # Extract metadata
        org = profile.get("PayloadOrganization", "")
        display = profile.get("PayloadDisplayName", "")
        payload_type = profile.get("PayloadType", "")
        payloads = profile.get("PayloadContent", [])

        findings.append(IOSFinding(
            "MDM_CHECK", "high",
            f"MDM enrollment profile: {display or mc_path.name}",
            f"Organization: '{org}' | PayloadType: '{payload_type}' | "
            f"Payload count: {len(payloads)}. "
            "MDM enrollment profile bundled with app -- device management enforced.",
            str(mc_path),
            snippet=f"PayloadOrganization={org!r}, PayloadType={payload_type!r}"))

        # Sub-payload analysis
        for sub in payloads if isinstance(payloads, list) else []:
            if not isinstance(sub, dict):
                continue
            sub_type = sub.get("PayloadType", "")
            sub_display = sub.get("PayloadDisplayName", "")
            if sub_type:
                sev = "high" if "mdm" in sub_type.lower() or "scep" in sub_type.lower() else "medium"
                findings.append(IOSFinding(
                    "MDM_CHECK", sev,
                    f"MDM sub-payload: {sub_type}",
                    f"Payload type '{sub_type}' ({sub_display}) found inside MDM profile.",
                    str(mc_path),
                    snippet=f"PayloadType={sub_type!r}"))

    # ------------------------------------------------------------------ #
    # 2. Scan Info.plist and all *.plist files for MDM keys               #
    # ------------------------------------------------------------------ #
    for plist_path in app_dir.rglob("*.plist"):
        try:
            with open(plist_path, "rb") as f:
                pdata = plistlib.load(f)
        except Exception:
            continue
        if not isinstance(pdata, dict):
            continue

        matched_keys = [k for k in IOS_MDM_PATTERNS if k in pdata]
        if matched_keys:
            findings.append(IOSFinding(
                "MDM_CHECK", "medium",
                f"MDM-related plist keys in {plist_path.name}",
                f"Plist '{plist_path.name}' contains MDM-related keys: "
                f"{', '.join(matched_keys[:10])}",
                str(plist_path),
                snippet=str(matched_keys[:10])))

    # ------------------------------------------------------------------ #
    # 3. Detect embedded certificate files (SCEP / MDM cert pinning)      #
    # ------------------------------------------------------------------ #
    for cert_path in app_dir.rglob("*"):
        if cert_path.suffix.lower() not in _MDM_CERT_EXTS:
            continue
        if not cert_path.is_file():
            continue
        sev = "high" if cert_path.suffix.lower() in {".p12", ".pfx"} else "medium"
        findings.append(IOSFinding(
            "MDM_CHECK", sev,
            f"Embedded certificate file: {cert_path.name}",
            f"Certificate/key file '{cert_path.name}' ({cert_path.suffix}) found in app bundle. "
            "May be used for SCEP enrollment, MDM trust anchor, or SSL certificate pinning.",
            str(cert_path),
            snippet=f"size={cert_path.stat().st_size} bytes"))

    return findings


# ---------------------------------------------------------------------------
# Swift source file scanning (dSYM-extracted or bundled sources)
# ---------------------------------------------------------------------------

def scan_swift_source(app_dir: Path, ipa_dir: Path) -> list[IOSFinding]:
    """
    Scan any .swift source files found inside the IPA bundle.

    Some IPAs ship Swift source files (e.g. React Native with Swift bridges,
    or dSYM-adjacent sources bundled by accident). This function scans them
    with all IOS_INSECURE_APIS patterns and the NATIVE_STRING_PATTERNS from
    patterns.py for comprehensive coverage.
    """
    findings: list[IOSFinding] = []

    swift_files = list(app_dir.rglob("*.swift"))
    # Also look one level up (e.g. dSYM bundles alongside Payload/)
    ipa_parent = ipa_dir
    swift_files.extend(p for p in ipa_parent.rglob("*.swift") if p not in swift_files)

    for swift_path in swift_files:
        try:
            if swift_path.stat().st_size > 10_000_000:
                continue  # skip files > 10 MB
            text = swift_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        rel = str(swift_path.relative_to(ipa_dir)) if ipa_dir in swift_path.parents else str(swift_path)

        # Run iOS API patterns
        for pat_re, cat, sev, desc in _IOS_API_PATTERNS:
            for m in pat_re.finditer(text):
                line_no = text[:m.start()].count("\n") + 1
                findings.append(IOSFinding(
                    category=cat, severity=sev,
                    title=f"[Swift] {desc.split('--')[0].strip() if '--' in desc else desc[:60]}",
                    description=desc,
                    location=f"{rel}:{line_no}",
                    snippet=text[max(0, m.start() - 30):m.end() + 60].strip()[:200]))

        # Run shared native/source patterns (root, hook, debug, emulator, etc.)
        for line_no, line in enumerate(text.splitlines(), 1):
            line_lower = line.lower()
            if _NATIVE_GATE is not None and not _NATIVE_GATE.search(line_lower):
                candidates = _NATIVE_ALWAYS_RUN
            else:
                candidates = _NATIVE_GATED + _NATIVE_ALWAYS_RUN
            for pat in candidates:
                if pat["regex"].search(line):
                    findings.append(IOSFinding(
                        category=pat["category"], severity=pat["confidence"],
                        title=f"[Swift] {pat['name']}",
                        description=pat["description"],
                        location=f"{rel}:{line_no}",
                        snippet=line.strip()[:200]))

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def scan_ipa(ipa_dir: Path, progress=None) -> tuple[list[IOSFinding], IOSPlistInfo | None, IOSBinaryInfo | None]:
    """
    Full MobSF-style + Ghidra-like static analysis of an extracted IPA.
    Returns (findings, plist_info, binary_info).
    """
    findings: list[IOSFinding] = []

    app_dir = find_app_dir(ipa_dir)
    if app_dir is None:
        findings.append(IOSFinding(
            "INTEGRITY_CHECK", "high",
            "No .app bundle found in IPA",
            "Could not locate a Payload/*.app directory in the extracted IPA.",
            str(ipa_dir)))
        return findings, None, None

    # 1. Info.plist analysis
    plist_info, plist_findings = analyze_plist(app_dir)
    findings.extend(plist_findings)
    if progress: progress()

    # 2. Main binary Mach-O analysis
    main_binary = find_main_binary(app_dir)
    binary_info = None
    if main_binary:
        binary_info = analyze_macho(main_binary)
        findings.extend(binary_findings(binary_info))
        # 3. String extraction from main binary
        findings.extend(scan_binary_strings(main_binary))
        # 4. Deep Ghidra-like ObjC decompilation
        findings.extend(deep_decompile_binary(main_binary))
    if progress: progress()

    # 5. Embedded frameworks
    findings.extend(scan_embedded_frameworks(app_dir))
    # Also deep-decompile framework binaries
    frameworks_dir = app_dir / "Frameworks"
    if frameworks_dir.is_dir():
        for fw_dir in frameworks_dir.iterdir():
            if fw_dir.is_dir() and fw_dir.name.endswith(".framework"):
                fw_bin = fw_dir / fw_dir.name[:-10]
                if fw_bin.is_file():
                    findings.extend(deep_decompile_binary(fw_bin))
    if progress: progress()

    # 6. Scan .dylib files
    for dylib in app_dir.rglob("*.dylib"):
        findings.extend(scan_binary_strings(dylib))
        findings.extend(deep_decompile_binary(dylib))
    if progress: progress()

    # 7. Scan .js bundles (React Native / Cordova)
    for js_file in app_dir.rglob("*.js"):
        try:
            if js_file.stat().st_size > 5_000_000:
                continue
            text = js_file.read_text(encoding="utf-8", errors="ignore")
            for pat_re, cat, sev, desc in _IOS_API_PATTERNS:
                for m in pat_re.finditer(text):
                    line_no = text[:m.start()].count("\n") + 1
                    findings.append(IOSFinding(
                        category=cat, severity=sev,
                        title=desc.split("--")[0].strip() if "--" in desc else desc[:60],
                        description=desc,
                        location=f"{js_file.relative_to(ipa_dir)}:{line_no}",
                        snippet=text[max(0, m.start() - 20):m.end() + 30].strip()[:150]))
        except OSError:
            continue
    if progress: progress()

    # 8. MDM profile / mobileconfig / embedded certificate scan
    findings.extend(scan_mdm_config(app_dir))
    if progress: progress()

    # 9. Swift source file scanning (dSYM-adjacent or bundled sources)
    findings.extend(scan_swift_source(app_dir, ipa_dir))
    if progress: progress()

    return findings, plist_info, binary_info

