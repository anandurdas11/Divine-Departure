"""
ios_security_model.py

iOS-aware counterpart to security_model.py. Takes the SourceFinding records
emitted by the IPA pipeline (ios_scanner + ios_deep_analyzer, converted by
_run_ipa_pipeline in main.py) and distils them into a security model whose
hook hints are shaped for iOS, not for Android:

  * ObjC selectors and Swift-mangled class names (demangled where possible)
  * SecTrust / BoringSSL / CFNetwork / AFNetworking / Alamofire / TrustKit
    pinning stacks
  * NSURLSession and WKWebView auth-challenge handlers
  * UIApplication / UIScene lifecycle exit chokepoints
  * Code-signing (SecCodeCheckValidity, csops) and biometric
    (LocalAuthentication) gates
  * MDM/EMM vendor hooks (Intune, AirWatch/Workspace ONE, MobileIron/Ivanti,
    MaaS360, Jamf/Kandji/Mosyle, BlackBerry Dynamics, Hexnode, SOTI)
  * Commercial RASP SDKs (Appdome, Promon SHIELD, GuardSquare iXGuard,
    Verimatrix/WhiteCryption, OneSpan, Zimperium zIAP, Approov,
    IBM Trusteer, Lookout, Pradeo, V-Key, Shape/F5, Jscrambler, Build38,
    Talsec freeRASP, AppProtecttXC, Mobeix Mx_*, IOSSecuritySuite,
    DTTJailbreakDetection, RSADJailbreakDetector, RN jail-monkey, …)

The Android build_security_model lives in security_model.py; this file does
the same job for IPA targets. Both share the mind-map renderer in
security_model.py (it only reads generic fields like runtime_class /
method_hint / frida_use, which we fill in with iOS-appropriate values).

The chokepoint signatures and hints are universal: they fire on any iOS
target that uses one of the recognised stacks, regardless of the app. The
model does not assume a specific banking app.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from report import CATEGORY_LABELS, ALL_CATEGORIES
# Reuse the Android mind-map renderer -- it reads generic fields we populate.
from security_model import build_security_mindmap_data

_CONF_RANK = {"high": 3, "medium": 2, "low": 1, "": 0, None: 0}
_MAX_CANDIDATES_PER_CATEGORY = 25


# ---------------------------------------------------------------------------
# iOS-specific Frida hints
# ---------------------------------------------------------------------------
# These are the generic recipes an LLM should apply when it has NO precise hook
# candidate for a category. They cover the layers that actually matter on iOS:
# AFNetworking, SecTrust, BoringSSL (gRPC/HTTP2), NSURLSession challenge
# delegate, hand-rolled trust evaluation, dyld image hiding, SDK-level exit.
IOS_GENERIC_FRIDA_HINTS = {
    "ROOT_DETECTION": [
        "Any @objc 'is this device bad?' predicate (isJailbroken, isJailBroken, "
        "isDeviceJailBroken, amIJailbroken, isRooted, isCompromised, "
        "isDeviceCompromised) -> force NO. Enumerate with new ApiResolver('objc') "
        "patterns like '-[* isJailbroken]'.",
        "Known detection libraries -- hook their public entry: "
        "+[IOSSecuritySuite amIJailbroken] / +[JailbreakDetection isJailbroken] / "
        "-[DTTJailbreakDetection isJailbroken] / -[RSADJailbreakDetector "
        "isJailbroken] / -[JailbreakChecker amIJailbroken] -> NO.",
        "React-Native plugins: -[RNJailMonkey isJailBroken] / "
        "-[RNJailbreakDetection isJailBroken] / -[RNDeviceInfo isEmulator / "
        "isEmulatorSync] -> NO.",
        "Hand-rolled 'block' / 'should-block' booleans found in the app's own "
        "classes (e.g. getApplicationShouldBlockRootedDevices, "
        "shouldBlockJailbrokenDevices, blockRootedDevice:) -> force NO / no-op the "
        "setter.",
        "'createJailBreakErrorView' / 'buildJailbreakView' selectors return a UI "
        "the app overlays on top of its own window -- replace with a fresh empty "
        "UIView (NOT nil, addSubview:nil raises).",
        "canOpenURL: for cydia:// / sileo:// / zbra:// / undecimus:// / filza:// "
        "/ activator:// -- hook -[UIApplication canOpenURL:] and return NO for "
        "those schemes.",
        "fork() / vfork() / posix_spawn() returning a valid pid proves sandbox "
        "escape -- hook them to return -1 (errno=EACCES).",
        "Hide suspect dyld images (frida, gadget, substrate, substitute, "
        "ellekit, libinjector, libhooker, roothide, choicy, /var/jb, "
        "libtweakinject, /Library/MobileSubstrate) by replacing "
        "_dyld_image_count / _dyld_get_image_name with filtered variants.",
        "Classic libc path hiding (open/stat/access/fopen for /Applications/"
        "Cydia.app, /private/var/lib/apt, /bin/bash, /usr/sbin/sshd, /var/jb) "
        "can CRASH at dyld-init time on real apps (CFBundle inlines a file open "
        "and jumps the libc trampoline before Frida's runtime is settled). "
        "Prefer the ObjC-method hooks above; only fall back to libc hooks "
        "per-detector if one slips through.",
    ],
    "ANTI_HOOK": [
        "Commercial RASP SDKs (Appdome, Promon SHIELD, GuardSquare iXGuard, "
        "Zimperium zIAP, Verimatrix, OneSpan, V-Key, IBM Trusteer, Lookout, "
        "Pradeo, Shape/F5, AppProtecttXC) typically carry their detectors in "
        "**pure Swift with ZERO @objc methods** -- ObjC Interceptor cannot reach "
        "them. The only reliable kill is to pin the verdict pipeline (see "
        "ENFORCEMENT) and/or a static framework patch + re-sign.",
        "Replace _dyld_image_count / _dyld_get_image_name to hide injected "
        "tweaks and defeat DylibInjectionDetector-style scans.",
        "fishhook / libffi / __interpose symbol-table integrity scans: either "
        "stop the scan entrypoint (-[* checkInterpose], -[* laSymbolPtrScan]) or "
        "pin its result to 0.",
        "Frida port scans (27042 / 27043): hook socket connect() and drop "
        "connections to those ports if the app probes them.",
    ],
    "ANTI_DEBUG": [
        "Hook sysctl() and when the request is {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid} "
        "clear kp_proc.p_flag's P_TRACED bit on return.",
        "Hook ptrace() -> return 0 and attach to its dynamic resolver "
        "(dlsym(RTLD_DEFAULT, \"ptrace\")) because iOS apps often resolve it that way.",
        "AmIBeingDebugged / isDebuggerAttached ObjC predicates -> NO.",
    ],
    "EMULATOR_DETECT": [
        "Hook -[UIDevice name/model/systemName] only if a detector explicitly reads them.",
        "Simulator detection on a real device is usually dead code -- verify a call "
        "exists before hooking.",
    ],
    "SSL_PINNING": [
        "AFNetworking: -[AFSecurityPolicy evaluateServerTrust:forDomain:] -> YES; "
        "-[AFSecurityPolicy setSSLPinningMode:] -> no-op.",
        "NSURLSession delegate: replace "
        "-[<Delegate> URLSession:didReceiveChallenge:completionHandler:] with a version "
        "that, for NSURLAuthenticationMethodServerTrust, calls the completion block with "
        "disposition **0 (NSURLSessionAuthChallengeUseCredential)** and "
        "+[NSURLCredential credentialForTrust:ps.serverTrust]. "
        "DO NOT pass 1 (PerformDefaultHandling) -- that re-runs the app's own pinning "
        "and the connection then fails with -1202.",
        "Hand-rolled trust check: force -[* shouldTrustProtectionSpace:] and "
        "-[* shouldTrustProtectionSpace:CertificateInformation:] -> YES across every "
        "class that implements them (ApiResolver enumerateMatches).",
        "SecTrust global backstop: SecTrustEvaluateWithError -> true + clear error; "
        "SecTrustGetTrustResult / SecTrustEvaluate -> write kSecTrustResultProceed (1), "
        "return errSecSuccess.",
        "BoringSSL (gRPC / HTTP2, bypasses SecTrust*): the REAL fix for -1202 is to "
        "**REPLACE** the custom_verify callback with one that returns ssl_verify_ok (0). "
        "Do NOT no-op SSL_CTX_set_custom_verify / SSL_set_custom_verify -- dropping the "
        "callback makes BoringSSL fall back to DEFAULT validation and the proxy CA is "
        "rejected. Keep a global JS reference to the NativeCallback so it isn't GC'd.",
        "Legacy BoringSSL verify API: SSL_CTX_set_verify / SSL_set_verify -- force mode "
        "arg to 0 (SSL_VERIFY_NONE); SSL_get_verify_result -> 0.",
        "TrustKit: -[TSKPinningValidator evaluateTrust:forHostname:] -> return 0 "
        "(TSKTrustEvaluationSuccess). Also stub -[TSKPinningValidator "
        "handleChallenge:completionHandler:] to invoke the completion with "
        "disposition 0 (UseCredential) and the proxy credential.",
        "Alamofire 5+: force -[PinnedCertificatesTrustEvaluator "
        "evaluate:forHost:] / -[PublicKeysTrustEvaluator evaluate:forHost:] / "
        "-[CompositeTrustEvaluator evaluate:forHost:] -> no throw. Easiest is to "
        "replace the whole class's evaluateWithTrust: method to return without "
        "throwing an error.",
        "WKWebView in-app browser: -[<Delegate> webView:didReceiveAuthentication"
        "Challenge:completionHandler:] -> same disposition-0 recipe as "
        "NSURLSession.",
        "gRPC: replace grpc_ssl_verify_peer_options.verify_peer_callback with "
        "one that returns 0 (ok); keep the NativeCallback globally referenced.",
        "CFNetwork low-level: set kCFStreamSSLValidatesCertificateChain = "
        "kCFBooleanFalse in any CFReadStreamSetProperty / kCFStreamPropertySSL"
        "Settings call -- hook CFReadStreamSetProperty and swap the dict.",
    ],
    "ENFORCEMENT": [
        "Hook consequences, not checks. Any @objc method whose name contains "
        "'closeVulnerability', 'forceExit', 'enforceVerdict', 'reactToThreat', "
        "'applyRule', 'blockApp', 'terminateApp' is a top-rank chokepoint -- "
        "swallow it and every upstream detector becomes moot.",
        "Verdict DTOs: any @objc getter named vulnerabilityForceAccept, "
        "shouldRemoveVulnerability, vulnerabilityActionRequired, isCompromised, "
        "status, severity, threatLevel, threatDetectedFlag -> force to the "
        "'clean / proceed' value and no-op the setter. CAVEAT: Swift->Swift "
        "reads bypass the ObjC getter, so these only affect callers using "
        "objc_msgSend.",
        "libc exit family: Interceptor.replace exit / _exit / _Exit / "
        "exit_group / abort -> log + no-op. Attach to kill / tgkill / "
        "pthread_kill / raise as trace-only first to prove the real gate.",
        "UIKit scene lifecycle: block -[UIApplication terminateWithSuccess / "
        "_terminateWithStatus: / terminate / workspaceShouldExit:"
        "withTransitionContext:] AND -[_UISceneLifecycleMultiplexer "
        "forceExitWithTransitionContext:scene:]. Do NOT touch "
        "_evalTransitionToSettings:fromSettings:forceExit:withTransitionStore: "
        "-- a blanket block wedges UIKit (black screen); a replaceFast gated "
        "passthrough crashes on normal transitions.",
        "RASP popup entry points: suppress any @objc selector like "
        "displayErrorViewWithTitle:message:, showJailbreakAlert, "
        "presentSecurityWarning, createJailBreakErrorView; route button handlers "
        "(skip / back / close / dismiss / handleCloseAppAction / "
        "overAllSkipVulnerabilityButtonTapped:) to "
        "dismissViewControllerAnimated:completion:.",
        "Pure-Swift detectors (classes with zero @objc methods, typical of "
        "commercial RASP) cannot be reached by ObjC Interceptor. A reliable "
        "kill of the detectors themselves requires a static binary patch of the "
        "framework + re-sign. Note this limitation; do not pretend ObjC hooks "
        "neutralise Swift internals.",
    ],
    "RASP_DETECTION": [
        "Treat any commercial RASP SDK as a verdict pipeline, not a set of "
        "detectors: find its ObjC-bridged dispatch entry (names typically contain "
        "'close', 'enforce', 'handle', 'react', 'apply', 'Rule', 'Verdict', "
        "'Threat') and neutralise it before chasing per-detector methods.",
        "Known-SDK shortcuts (hook if the class is present): "
        "+[IOSSecuritySuite amIJailbroken / amIDebugged / amIReverseEngineered / "
        "amIProxied / amIRunInEmulator] -> false; "
        "+[Approov fetchApproovToken:] -> return a valid token verdict; "
        "+[AppdomeShield verifyRuntime] -> true; "
        "-[PromonShieldRuntime isTampered] -> false; "
        "-[iXGuardRuntime check] -> ok; "
        "-[ZimperiumZIAP isDeviceCompromised] -> false; "
        "-[TrusteerMobile detectThreat] -> none; "
        "-[LookoutClient getThreatStatus] -> clean; "
        "-[VKeyVOS isVOSSafe] -> true.",
        "If the framework is fully Swift with no @objc methods (symtab has zero "
        "Swift-mangled function symbols -- common for high-end commercial RASP "
        "builds), ObjC hooks only reach the UI / dispatch wrapper. Flag this in "
        "the model so the operator knows a static patch may be required.",
        "Install hooks EARLY (frida -f <bundle> spawn + resume) and keep the "
        "script LEAN -- many RASP SDKs run a timer-driven watchdog that fires "
        "if script init takes too long.",
    ],
    "HARDCODED_SECRETS": [
        "Audit any API key / token found in __TEXT,__cstring, __TEXT,__objc_methname, "
        "or Info.plist. Verify validity against staging before reporting.",
        "Hook -[NSURLRequest allHTTPHeaderFields] / RCTNetworking sendRequest:... to "
        "inspect whether hardcoded keys travel in Authorization headers.",
    ],
    "INTEGRITY_CHECK": [
        "Hook SecCodeCheckValidity / SecStaticCodeCheckValidity / SecCodeCopySigningInformation "
        "to return errSecSuccess with a synthetic signing dict.",
        "ObjC-level codesign checks (CodeSignatureChecker, isAdHocSigned, "
        "verifyCodeSignature) -> return the 'genuine' value when the method name clearly "
        "indicates polarity.",
    ],
    "MDM_CHECK": [
        "Supervision / managed-config queries: hook "
        "+[MobileGestalt MGCopyAnswer:] and return NO for kMGQIsSupervised; "
        "stub -[UIDevice _detailedDeviceProperties] / -[UIDevice isSupervised] "
        "-> NO; return an empty NSDictionary from NSUserDefaults.standard."
        "dictionaryForKey_('com.apple.configuration.managed').",
        "Intune App SDK: force -[IntuneMAMPolicyManager instance] policies to "
        "benign (-[IntuneMAMPolicy isManagementEnabled] -> NO, "
        "-[IntuneMAMPolicy isSaveToAllowedForLocation:] -> YES, "
        "allowedAccounts -> all). Replace +[IntuneMAMEnrollmentManager "
        "instance].enrollmentStatusForAccountId: -> enrolled.",
        "AirWatch / Workspace ONE: -[AWController isEnrolled] -> YES; "
        "-[AWController startWithLaunchOptions:] -> no-op; "
        "-[AWTunnelService isTunnelEnabled] -> NO.",
        "MobileIron AppConnect: -[AppConnectInterface authState] -> Authorized; "
        "-[AppConnectInterface policy] -> permissive.",
        "BlackBerry Dynamics (Good): -[GDiOS authorize:] completion -> success; "
        "-[GDiOS state] -> GDAppStateAuthorized.",
        "Jamf / Kandji / Mosyle / Addigy / Hexnode / SOTI / Scalefusion: "
        "enumerate the vendor's status/isEnrolled/isCompliant/isCompromised "
        "selectors and force them to the compliant value.",
    ],
}


# AppProtecttXC / Mobeix / AU-style selectors that we KNOW are chokepoints,
# discovered during the AU 0101 runtime bypass. If an ios_scanner finding mentions
# one of these, we promote it to a top-ranked enforcement chokepoint even if the
# pattern catalog didn't label it ENFORCEMENT.
IOS_CHOKEPOINT_SIGNATURES = {
    # +[... closeVulnerabilityWithUpdatedRuleId:updateRuleTitle:] -- SDK exit entry
    "closeVulnerabilityWithUpdatedRuleId":    ("terminal_action", 1),
    "closeVulnerability":                     ("terminal_action", 1),
    # -[ATSRuleForwardPayload threatDetectedFlag] / setter -- verdict ivar
    "threatDetectedFlag":                     ("boolean_gate", 1),
    "setThreatDetectedFlag":                  ("boolean_gate", 1),
    # -[AppProtecttResponseObject *] -- verdict getters
    "vulnerabilityForceAccept":               ("boolean_gate", 1),
    "shouldRemoveVulnerability":              ("boolean_gate", 1),
    "vulnerabilityActionRequired":            ("boolean_gate", 1),
    # UIKit exit chokepoints
    "terminateWithSuccess":                   ("terminal_action", 1),
    "_terminateWithStatus:":                  ("terminal_action", 1),
    "workspaceShouldExit":                    ("terminal_action", 1),
    "forceExitWithTransitionContext":         ("terminal_action", 1),
    # RASP popup / sheet dispatcher
    "displayErrorViewWithTitle":              ("reaction_dispatch", 2),
    "createJailBreakErrorView":               ("reaction_dispatch", 2),
    "handleCloseAppAction":                   ("terminal_action", 1),
    "overAllSkipVulnerabilityButtonTapped":   ("reaction_dispatch", 2),
    "infoviewSkipButtonTapped":               ("reaction_dispatch", 2),
    "infoViewBackButtonTapped":               ("reaction_dispatch", 2),
    # Mobeix boolean gates
    "isJailbroken":                           ("boolean_gate", 3),
    "isRootedDevice":                         ("boolean_gate", 3),
    "blockRootedDevice":                      ("reaction_dispatch", 2),
    "blockDebugModeDevices":                  ("reaction_dispatch", 2),
    "isDebugModeEnable":                      ("boolean_gate", 3),
    "getApplicationShouldBlockRootedDevices": ("boolean_gate", 3),
    "getApplicationShouldBlockDebugModeDevices": ("boolean_gate", 3),
    "getApplicationShouldBlockNonPhysicalDevices": ("boolean_gate", 3),
    # SSL pinning entries
    "shouldTrustProtectionSpace":             ("boolean_gate", 3),
    "URLSession:didReceiveChallenge":         ("reaction_dispatch", 2),
    "evaluateServerTrust":                    ("boolean_gate", 3),
    # BoringSSL / SecTrust (reach them via Module.findExportByName)
    "SSL_CTX_set_custom_verify":              ("terminal_action", 1),
    "SSL_set_custom_verify":                  ("terminal_action", 1),
    "SSL_CTX_set_verify":                     ("terminal_action", 1),
    "SSL_set_verify":                         ("terminal_action", 1),
    "SSL_CTX_set_cert_verify_callback":       ("terminal_action", 1),
    "SSL_get_verify_result":                  ("boolean_gate", 3),
    "SecTrustEvaluateWithError":              ("boolean_gate", 3),
    "SecTrustGetTrustResult":                 ("boolean_gate", 3),
    "SecTrustEvaluate":                       ("boolean_gate", 3),
    "SecTrustSetAnchorCertificates":          ("boolean_gate", 3),
    "SecTrustSetAnchorCertificatesOnly":      ("boolean_gate", 3),
    # Alamofire 5+ trust evaluators
    "PinnedCertificatesTrustEvaluator":       ("boolean_gate", 3),
    "PublicKeysTrustEvaluator":               ("boolean_gate", 3),
    "DisabledTrustEvaluator":                 ("boolean_gate", 3),
    # TrustKit
    "TSKPinningValidator":                    ("boolean_gate", 3),
    "evaluateTrust:forHostname:":             ("boolean_gate", 3),
    # AFNetworking
    "AFSecurityPolicy":                       ("boolean_gate", 3),
    "evaluateServerTrust:forDomain:":         ("boolean_gate", 3),
    "AFSSLPinningMode":                       ("boolean_gate", 3),
    # WKWebView auth challenge
    "webView:didReceiveAuthenticationChallenge:completionHandler:": ("reaction_dispatch", 2),
    # gRPC
    "GRPC_SSL_CERT_VERIFY_CALLBACK":          ("terminal_action", 1),
    "grpc_ssl_verify_peer_options":           ("terminal_action", 1),
    # Code-signing APIs (reach via Module.findExportByName)
    "SecCodeCheckValidity":                   ("boolean_gate", 3),
    "SecStaticCodeCheckValidity":             ("boolean_gate", 3),
    "SecCodeCopySigningInformation":          ("boolean_gate", 3),
    # LocalAuthentication (biometric gate)
    "evaluatePolicy":                         ("boolean_gate", 3),
    "deviceOwnerAuthentication":              ("boolean_gate", 3),
    "deviceOwnerAuthenticationWithBiometrics": ("boolean_gate", 3),
    # Debug detection (reach via Module.findExportByName / inline svc)
    "ptrace":                                 ("boolean_gate", 3),
    "PT_DENY_ATTACH":                         ("boolean_gate", 3),
    "sysctl":                                 ("boolean_gate", 3),
    "AmIBeingDebugged":                       ("boolean_gate", 3),
    # IOSSecuritySuite (open-source RASP)
    "amIJailbroken":                          ("boolean_gate", 3),
    "amIDebugged":                            ("boolean_gate", 3),
    "amIReverseEngineered":                   ("boolean_gate", 3),
    "amIProxied":                             ("boolean_gate", 3),
    "amIRunInEmulator":                       ("boolean_gate", 3),
    # Approov
    "fetchApproovToken":                      ("terminal_action", 1),
    "ApproovTokenFetchResult":                ("terminal_action", 1),
    # TrollStore / rootless marker
    "/var/jb":                                ("detector", 4),
    # Intune MAM policy enforcement
    "IntuneMAMPolicyManager":                 ("terminal_action", 1),
    "isManaged":                              ("boolean_gate", 3),
    "isSupervised":                           ("boolean_gate", 3),
    "kMGQIsSupervised":                       ("boolean_gate", 3),
    # AirWatch
    "AWController":                           ("terminal_action", 1),
    # BlackBerry Dynamics
    "GDiOS":                                  ("terminal_action", 1),
    "GDAuthenticate":                         ("boolean_gate", 3),
}

# libc / system exports that are terminal actions when seen in iOS findings.
IOS_NATIVE_TERMINAL_SYMS = {
    "exit", "_exit", "_Exit", "exit_group", "abort", "tgkill", "pthread_kill",
    "raise", "kill",
}


# ---------------------------------------------------------------------------
# Name parsing -- extract the ObjC class / selector / Swift module from a
# finding's `file_path` / `snippet` / enclosing `calling_function` field.
# ---------------------------------------------------------------------------
# Swift name-mangled class: _TtC13AppProtecttXC25ATSRuleForwardPayload
#   -> module length 13 = "AppProtecttXC", class length 25 = "ATSRuleForwardPayload"
_SWIFT_MANGLED_RE = re.compile(r"_TtC(\d+)([A-Za-z0-9_]+)")
# "ClassName::selectorName" (produced by _analyze_objc_classes in ios_deep_analyzer)
_CLASS_METHOD_RE = re.compile(r"^([_A-Za-z][\w.]*)::(.+)$")
# "+ selector" or "- selector" bare
_SELECTOR_RE = re.compile(r"^[+-]\s*[\w:]+$")
# "BinaryName!FunctionName+0xADDR"
_BINLOC_RE = re.compile(r"^([^!]+)!([^+]+)(?:\+0x[0-9a-fA-F]+)?$")


def _demangle_swift_class(name: str) -> str:
    """`_TtC13AppProtecttXC25ATSRuleForwardPayload` -> `AppProtecttXC.ATSRuleForwardPayload`."""
    s = name.strip()
    if not s.startswith("_TtC"):
        return s
    pos = 4
    out_parts = []
    while pos < len(s):
        # read length prefix
        n = 0
        while pos < len(s) and s[pos].isdigit():
            n = n * 10 + (ord(s[pos]) - ord('0'))
            pos += 1
        if n == 0 or pos + n > len(s):
            return s
        out_parts.append(s[pos:pos + n])
        pos += n
    return ".".join(out_parts) if out_parts else s


def _runtime_name(raw: str) -> str:
    """Normalise a class name to what ObjC.classes[...] would accept at runtime."""
    if not raw:
        return raw
    if raw.startswith("_TtC"):
        return _demangle_swift_class(raw)
    return raw


def _is_pure_swift(name: str) -> bool:
    """A `_TtC` prefix means pure Swift class -- @objc bridges are reachable only
    via its demangled dotted name if the author added `@objc`."""
    return name.startswith("_TtC")


def _extract_class_selector(finding) -> tuple[str, str]:
    """
    Pull (class, selector) out of a SourceFinding. The IPA pipeline packs iOS
    data into pattern_name / snippet / file_path, so we look everywhere:

      1. snippet like "ClassName::selectorName"   (ios_deep_analyzer._analyze_objc_classes)
      2. snippet like "+ selector" / "- selector" (raw __objc_methnames hit)
      3. file_path like "BinaryName!FunctionName+0x1234"
      4. a bare class name string in snippet
    """
    cls = ""
    sel = ""
    snip = (getattr(finding, "snippet", "") or "").strip()
    path = (getattr(finding, "file_path", "") or "").strip()

    # 1. Class::selector
    m = _CLASS_METHOD_RE.match(snip)
    if m:
        cls = _runtime_name(m.group(1))
        sel = m.group(2).strip()
        return cls, sel

    # 2. bare selector
    if _SELECTOR_RE.match(snip):
        return "", snip

    # 3. ObjC-shaped selector token inside snippet (ends with ':' or starts with -/+)
    #    pick a chokepoint signature out of either snippet or path.
    for signature in IOS_CHOKEPOINT_SIGNATURES:
        if signature in snip or signature in path:
            sel = signature
            break

    # 4. find a class name in snippet / path
    #    Prefer well-known prefixes we care about -- Mx_, AppProtectt, AU_0101,
    #    Mobeix, _TtC..., AFSecurityPolicy, SSLPinningDelegate, etc.
    _CLASS_HINT_RE = re.compile(
        r"\b(_TtC\d+[A-Za-z0-9_]+|Mx_[A-Za-z0-9_]+|AppProtectt[A-Za-z0-9_]+|"
        r"ATSRuleForwardPayload|AppProtecttResponseObject|AU_0101\.[A-Za-z0-9_]+|"
        r"AFSecurityPolicy|TrustKit[A-Za-z0-9_]*|SSLPinning[A-Za-z0-9_]*|"
        r"RNDeviceInfo|RCTNetworking|RCT[A-Z][A-Za-z0-9_]*)\b"
    )
    for src in (snip, path):
        m = _CLASS_HINT_RE.search(src)
        if m:
            cls = _runtime_name(m.group(1))
            break

    # 5. BinaryName!FunctionName+0xADDR  ->  cls="", sel=FunctionName
    if not cls and not sel:
        m = _BINLOC_RE.match(path)
        if m and "::" in m.group(2):
            fn = m.group(2)
            cm = _CLASS_METHOD_RE.match(fn)
            if cm:
                cls = _runtime_name(cm.group(1))
                sel = cm.group(2)

    return cls, sel


def _frida_hook_snippet(cls: str, sel: str, role: str) -> str:
    """One-line Frida JS snippet appropriate for an iOS hook candidate."""
    if cls.startswith("SSL_") or cls in IOS_NATIVE_TERMINAL_SYMS or sel in IOS_NATIVE_TERMINAL_SYMS:
        sym = cls or sel
        return (f'Interceptor.attach(Module.findExportByName(null, "{sym}"), '
                f'{{ onEnter(args) {{ /* ... */ }} }})')
    if cls and sel:
        prefix = "+" if sel.startswith("+") or "class method" in role else "-"
        bare = sel.lstrip("+- ")
        return (f'const c = ObjC.classes["{cls}"]; '
                f'if (c && c["{prefix} {bare}"]) Interceptor.replace('
                f'c["{prefix} {bare}"].implementation, '
                f'new NativeCallback(() => /* return value */, "bool", '
                f'["pointer","pointer"]));')
    if cls:
        return f'ObjC.classes["{cls}"]  // enumerate $ownMethods and hook predicates'
    if sel:
        return (f'new ApiResolver("objc").enumerateMatches("-[* {sel}]").forEach('
                f'm => Interceptor.replace(m.address, ...))')
    return "// no class/selector extracted -- see snippet"


def _classify(finding) -> tuple[str, int]:
    """Return (role, enforcement_rank) for an iOS finding using signature table."""
    for key in (getattr(finding, "snippet", "") or "",
                getattr(finding, "pattern_name", "") or "",
                getattr(finding, "file_path", "") or ""):
        for sig, (role, rank) in IOS_CHOKEPOINT_SIGNATURES.items():
            if sig in key:
                return role, rank
    cat = getattr(finding, "category", "")
    if cat == "ENFORCEMENT":
        return "terminal_action", 1
    if cat == "SSL_PINNING":
        return "boolean_gate", 3
    if cat == "HARDCODED_SECRETS":
        return "credential_secret", 5
    return "detector", 4


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def build_ios_security_model(apk_name, source_findings, native_string_findings,
                             native_callsite_findings, warnings, out_dir,
                             ipa_dir=None, patch_records=None):
    """
    iOS-aware model builder. Returns (json_path, prompt_path, model) with the
    same shape as security_model.build_security_model so the HTML report and
    mind-map renderer don't need to know which platform produced the model.
    """
    out_dir = Path(out_dir)

    by_cat = defaultdict(list)
    for f in source_findings:
        by_cat[f.category].append(f)

    mechanisms = []
    for cat in ALL_CATEGORIES:
        items = by_cat.get(cat, [])
        if not items:
            continue
        seen = {}
        for f in items:
            cls, sel = _extract_class_selector(f)
            role, rank = _classify(f)
            key = (cls, sel, f.pattern_name)
            cand = seen.get(key)
            if cand is not None and _CONF_RANK[f.confidence] <= _CONF_RANK[cand["confidence"]]:
                continue
            is_swift = _is_pure_swift((f.snippet or "").split("::", 1)[0] or "")
            entry = dict(
                objc_class=cls,
                runtime_class=cls,            # same field name as Android model for the mind-map
                selector=sel,
                method_hint=sel,              # same field name as Android for the mind-map
                is_pure_swift=is_swift,
                swift_reachable_via_objc=(bool(cls) and not is_swift),
                frida_use=_frida_hook_snippet(cls, sel, role),
                role=role,
                enforcement_rank=rank,
                source=f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path,
                evidence=f"{f.file_path}:{f.line_number} -> {f.pattern_name}",
                signature=f.pattern_name,
                confidence=f.confidence,
                snippet=(f.snippet or "")[:160],
            )
            if role in ("boolean_gate",):
                # "is bad?" -> false; "is clean/valid?" -> true. Default false; the
                # LLM should flip based on name polarity (we annotate hint only).
                entry["return_to_force"] = False
            seen[key] = entry
        candidates = sorted(
            seen.values(),
            key=lambda c: (c["enforcement_rank"],
                           0 if c["swift_reachable_via_objc"] or not c["is_pure_swift"] else 1,
                           -_CONF_RANK[c["confidence"]],
                           c["objc_class"]),
        )
        conf_max = max((c["confidence"] for c in candidates),
                       key=lambda c: _CONF_RANK[c], default="low")
        shown = candidates[:_MAX_CANDIDATES_PER_CATEGORY]
        mechanisms.append(dict(
            category=cat,
            label=CATEGORY_LABELS[cat],
            finding_count=len(items),
            confidence_max=conf_max,
            hook_candidates=shown,
            hook_candidates_omitted=max(len(candidates) - len(shown), 0),
            generic_frida_hints=IOS_GENERIC_FRIDA_HINTS.get(cat, []),
        ))

    # ---- Enforcement chokepoints -----------------------------------------
    chokepoints = []
    for mech in mechanisms:
        for c in mech["hook_candidates"]:
            if c["role"] in ("launch_gate", "terminal_action", "reaction_dispatch",
                             "boolean_gate", "dynamic_loader"):
                chokepoints.append(dict(
                    role=c["role"], enforcement_rank=c["enforcement_rank"],
                    runtime_class=c["objc_class"],
                    method_hint=c["selector"],
                    is_pure_swift=c["is_pure_swift"],
                    swift_reachable_via_objc=c["swift_reachable_via_objc"],
                    frida_hook=c["frida_use"],
                    return_to_force=c.get("return_to_force"),
                    confidence=c["confidence"], source=c["source"],
                    evidence=c["evidence"],
                    category=mech["category"]))

    # libc / BoringSSL / SecTrust terminal actions seen in native findings
    native = []
    for f in native_callsite_findings or []:
        entry = dict(kind="callsite", library=Path(f.so_path).name,
                     category=f.category, symbol=f.imported_symbol,
                     function=f.calling_function,
                     address=f"0x{f.call_instruction_address:x}",
                     confidence=f.confidence, description=f.description)
        if f.imported_symbol in IOS_NATIVE_TERMINAL_SYMS or f.category == "ENFORCEMENT":
            entry["role"] = "terminal_action"
            entry["enforcement_rank"] = 1
            entry["frida_hook"] = (
                f'Interceptor.replace(Module.findExportByName(null, "{f.imported_symbol}"), '
                f'new NativeCallback(() => {{ /* log + no-op */ }}, "void", ["int"]))'
            )
            chokepoints.append(dict(
                role="terminal_action", enforcement_rank=1,
                symbol=f.imported_symbol, library=Path(f.so_path).name,
                frida_hook=entry["frida_hook"], confidence=f.confidence,
                source=f'{Path(f.so_path).name}@{entry["address"]}',
                category="ENFORCEMENT"))
        native.append(entry)
    for f in native_string_findings or []:
        native.append(dict(kind="string", library=Path(f.so_path).name,
                           category=f.category, signature=f.pattern_name,
                           offset=f"0x{f.file_offset:x}", matched=f.matched_string,
                           confidence=f.confidence))

    chokepoints.sort(key=lambda c: (c["enforcement_rank"],
                                    -_CONF_RANK.get(c.get("confidence"), 0)))

    # Detect pure-Swift RASP (no @objc) and surface it as a top-level signal.
    pure_swift_rasp = any(
        c.get("is_pure_swift") and not c.get("swift_reachable_via_objc")
        for mech in mechanisms for c in mech["hook_candidates"]
    )

    by_category_counts = {CATEGORY_LABELS[c]: len(by_cat.get(c, [])) for c in ALL_CATEGORIES
                          if by_cat.get(c)}
    native_cats = {d["category"] for d in native if d.get("category")}
    categories_present = [CATEGORY_LABELS[c] for c in ALL_CATEGORIES
                          if by_cat.get(c) or c in native_cats]

    model = dict(
        target=dict(apk=apk_name, platform="ios",
                    generated=datetime.now().isoformat(timespec="seconds")),
        summary=dict(
            total_source_findings=len(source_findings),
            total_native_findings=len(native_string_findings or []) + len(native_callsite_findings or []),
            categories_present=categories_present,
            by_category=by_category_counts,
            pure_swift_rasp_detected=pure_swift_rasp,
        ),
        enforcement_chokepoints=chokepoints,
        defense_mechanisms=mechanisms,
        native_libraries=native,
        patched=bool(patch_records),
        patch_log=patch_records or [],
        tool_warnings=warnings,
        disclaimer=(
            "iOS static model. `runtime_class` is the ObjC runtime name (Swift "
            "mangled classes are demangled where recognisable: `_TtC<N>Module<M>Name` "
            "-> `Module.Name`); verify with ObjC.classes[name] at runtime before "
            "hooking. `is_pure_swift: true` + `swift_reachable_via_objc: false` means "
            "the class has no @objc methods -- an ObjC Interceptor cannot reach it and a "
            "static binary patch of the framework may be required. Prefer the ranked "
            "`enforcement_chokepoints` over per-detector hooks."
        ),
    )

    json_path = out_dir / "security_model.json"
    json_path.write_text(json.dumps(model, indent=2), encoding="utf-8")

    prompt_path = out_dir / "frida_prompt.md"
    prompt_path.write_text(_render_ios_prompt(model), encoding="utf-8")

    mindmap_data = build_security_mindmap_data(model, source_findings,
                                               native_string_findings or [],
                                               native_callsite_findings or [])
    mindmap_json_path = out_dir / "security_mind_map.json"
    mindmap_json_path.write_text(json.dumps(mindmap_data, indent=2), encoding="utf-8")

    model["mindmap_data"] = mindmap_data
    model["mindmap_json_name"] = "security_mind_map.json"
    return json_path, prompt_path, model


def _render_ios_prompt(model) -> str:
    cats = ", ".join(model["summary"]["categories_present"]) or "none detected"
    n_choke = len(model.get("enforcement_chokepoints", []))
    pure_swift = model["summary"].get("pure_swift_rasp_detected", False)
    swift_note = (
        "\n\n**Pure-Swift RASP detected.** At least one chokepoint candidate is a "
        "`_TtC...` class with no @objc methods. ObjC Interceptor cannot reach the "
        "Swift internals; the model's `_pure_swift` candidates are useful only for "
        "callers that cross the ObjC boundary (verdict DTO getters, UI wrappers). "
        "For a reliable kill of the Swift detectors themselves, the operator will "
        "need a static binary patch of the framework (NOP the detector bodies / pin "
        "the verdict) + re-sign."
    ) if pure_swift else ""
    return f"""# Frida bypass script generation -- iOS task brief

You are a senior iOS application security engineer performing an **authorised**
penetration test. Using the static security model below, write **one consolidated
Frida script** (JavaScript) that disables the defensive mechanisms it describes
so the app can be dynamically analysed on a jailbroken device behind an
intercepting proxy. Load it at spawn:

```
frida -U -f <bundle.id> -l bypass.js
```

## Strategy -- hook consequences, not checks

This model ranks **{n_choke} enforcement chokepoints** in
`enforcement_chokepoints` (sorted by `enforcement_rank`, 1 = highest value). On
iOS the few points where a failed verdict becomes an action are:

1. **`enforcement_rank: 1`** -- SDK verdict dispatchers (any @objc selector
   whose name contains `closeVulnerability` / `forceExit` / `enforceVerdict` /
   `reactToThreat` / `applyRule`), the libc exit family, UIKit scene exit
   (`-[UIApplication terminate*]`, `-[_UISceneLifecycleMultiplexer
   forceExitWithTransitionContext:scene:]`), and BoringSSL `custom_verify`.
2. **`enforcement_rank: 2`** -- reaction dispatchers (popup / sheet /
   jailbreak-error view builders, button handlers routed to dismiss instead
   of exit).
3. **`enforcement_rank: 3`** -- boolean gates: `shouldTrustProtectionSpace:`,
   `isJailbroken` / `amIJailbroken` / `isCompromised`, verdict getters
   (`vulnerabilityForceAccept`, `threatDetectedFlag`, `status`), app-local
   `shouldBlock*` config booleans. Force them to the clean / proceed value.
4. **`enforcement_rank: 4+`** -- individual detectors (`defense_mechanisms[]`).

## iOS-specific pitfalls (apply all)

1. **Keep the process alive at spawn.** On rootless jailbreaks, ellekit's
   `libinjector.dylib!injection_init` can PAC-fault in its own dyld-init
   constructor. If present, stub it to a no-op *before resume*.
2. **Replace, do not no-op, `SSL_CTX_set_custom_verify` /
   `SSL_set_custom_verify`.** Dropping the callback makes BoringSSL fall back
   to DEFAULT chain validation and the proxy CA is rejected -> `-1202`. Replace
   the callback with one that returns `0` (`ssl_verify_ok`) and keep a global
   JS reference so the NativeCallback isn't GC'd.
3. **NSURLSession challenge disposition is `0` (UseCredential), not `1`.**
   Passing `PerformDefaultHandling` re-runs the app's own pinning. Build the
   credential with `+[NSURLCredential credentialForTrust:ps.serverTrust]` and
   call the completion block with disposition `0`.
4. **Do NOT blanket-hook
   `_evalTransitionToSettings:fromSettings:forceExit:withTransitionStore:`.**
   It drives every scene transition; a block wedges UIKit (black screen) and a
   replaceFast passthrough crashes on normal transitions. Stop exits at the
   specific chokepoints: `-[UIApplication terminate*/workspaceShouldExit:]` and
   `-[_UISceneLifecycleMultiplexer forceExitWithTransitionContext:scene:]`.
5. **Avoid libc path hiding at script top.** Hooking
   `open`/`stat`/`access`/`fopen` can crash the app at dyld-init time because
   `_CFBundleGetBundleVersionForURL` inlines a file open and jumps the libc
   trampoline before Frida's runtime is settled. Hook per-detector methods
   instead; add path hiding only if a specific detector slips through.
6. **Hide suspect dyld images** by replacing `_dyld_image_count` and
   `_dyld_get_image_name` with filtered variants that elide `frida`, `gadget`,
   `substrate`, `substitute`, `ellekit`, `libinjector`, `libhooker`, `/var/jb`.
7. **Keep the script lean.** Many RASP SDKs run a timer-driven watchdog that
   fires if script init takes too long. Prefer direct `ObjC.classes[name][sel]`
   lookups over broad `enumerateMatches` scans where the owning class is known.

## Requirements

1. Wrap all ObjC hooks in a top-level IIFE guarded by `ObjC.available`. Guard
   every `ObjC.classes[...]` lookup -- a missing class must not abort the rest.
2. Use `runtime_class` (already demangled). For `is_pure_swift: true` /
   `swift_reachable_via_objc: false` candidates, note in the log that the hook
   only affects objc_msgSend callers; do not pretend it neutralises the Swift
   internals.
3. For each `enforcement_chokepoints` entry, apply the rank-ordered strategy
   above. For `defense_mechanisms[].hook_candidates`, hook `runtime_class`
   with `method_hint`.
4. Apply every `generic_frida_hints` block for the categories present.
5. **Install a termination tracer first.** Before neutralising anything,
   `Interceptor.attach(Module.findExportByName(null, sym), ...)` for `exit`,
   `_exit`, `_Exit`, `exit_group`, `abort`, `kill`, `tgkill`, `pthread_kill`,
   `raise`; write a backtrace (`Thread.backtrace(ctx, Backtracer.ACCURATE)
   .map(DebugSymbol.fromAddress)`) to a `$TMPDIR/<app>_frida.log` file with
   `fflush` + `fsync` so it survives abrupt termination. Then replace the exit
   family with no-ops.
6. Cover SSL pinning end-to-end: AFSecurityPolicy, NSURLSession challenge
   handlers (for every app delegate class in `defense_mechanisms`), SecTrust*
   backstops, `-[* shouldTrustProtectionSpace:]`, and BoringSSL `custom_verify`
   (replace, not no-op).
7. For every neutralised hook, `console.log("[bypass] <what was neutralised>")`
   so the operator can see coverage.
8. No placeholders -- produce runnable code.
{swift_note}

## Detected categories

{cats}

## Static security model

```json
{json.dumps(model, indent=2)}
```

Return only the Frida script, preceded by a one-paragraph summary of what it does.
"""
