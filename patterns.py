"""
patterns.py

Central signature database for the APK Tamper/Root-Detection Locator.

Each entry:
    name        : short identifier
    category    : one of ROOT_DETECTION, INTEGRITY_CHECK, ANTI_DEBUG, ANTI_HOOK,
                  EMULATOR_DETECT, MDM_CHECK, SSL_PINNING, RASP_DETECTION,
                  JAILBREAK_DETECT (iOS alias for ROOT_DETECTION)
    regex       : compiled regex used against source lines / extracted strings
    description : human-readable explanation shown in the report
    confidence  : "high" | "medium" | "low" -- how strongly a hit implies the real mechanism
                  vs. an incidental string match.

These patterns are intentionally broad (they are meant to CATCH candidate locations for a
human reviewer to confirm, not to be a 100%-precision oracle). The scanner reports every hit
with file + line/offset so the pentester can go verify manually.
"""

import re

CATEGORIES = [
    "ROOT_DETECTION",
    "INTEGRITY_CHECK",
    "ANTI_DEBUG",
    "ANTI_HOOK",
    "EMULATOR_DETECT",
    "MDM_CHECK",
    "SSL_PINNING",
    "RASP_DETECTION",
    "JAILBREAK_DETECT",   # iOS alias; treated identically to ROOT_DETECTION
]


def _c(pattern):
    return re.compile(pattern, re.IGNORECASE)


# -----------------------------------------------------------------------
# Patterns applied to decompiled Java / Kotlin / Smali source text
# -----------------------------------------------------------------------
SOURCE_PATTERNS = [
    # ====================================================================
    # ROOT DETECTION — Android
    # ====================================================================
    dict(name="su_binary_path", category="ROOT_DETECTION",
         regex=_c(r"/(system/(bin|xbin)|sbin|su/bin)/su\b"),
         description="Hardcoded path to the `su` binary, typically checked with File.exists().",
         confidence="high"),
    dict(name="su_command_exec", category="ROOT_DETECTION",
         regex=_c(r"\bwhich\s+su\b|Runtime\.getRuntime\(\)\.exec\(\s*[\"']su"),
         description="Attempts to execute `su` (or `which su`) to detect root access.",
         confidence="high"),
    dict(name="busybox_ref", category="ROOT_DETECTION",
         regex=_c(r"\bbusybox\b"),
         description="Reference to busybox, commonly bundled on rooted devices.",
         confidence="medium"),
    dict(name="root_management_pkg", category="ROOT_DETECTION",
         regex=_c(
             r"com\.noshufou\.android\.su|eu\.chainfire\.supersu|com\.koushikdutta\.superuser|"
             r"com\.thirdparty\.superuser|com\.topjohnwu\.magisk|com\.kingroot\.kinguser|"
             r"com\.kingo\.root|com\.smedialink\.oneclickroot|com\.zhiqupk\.root\.global|"
             r"com\.alephzain\.framaroot|com\.yellowes\.su"
         ),
         description="Package name of a known root-management / rooting app, checked via PackageManager.",
         confidence="high"),
    dict(name="rootbeer_lib", category="ROOT_DETECTION",
         regex=_c(r"com\.scottyab\.rootbeer|RootBeer\b"),
         description="Use of the RootBeer root-detection library.",
         confidence="high"),
    dict(name="build_tags_test_keys", category="ROOT_DETECTION",
         regex=_c(r"test-keys|Build\.TAGS"),
         description="Checks Build.TAGS for 'test-keys', indicating a custom/non-official ROM build.",
         confidence="medium"),
    dict(name="dangerous_root_paths", category="ROOT_DETECTION",
         regex=_c(r"/system/app/Superuser\.apk|/system/etc/init\.d/|Superuser\.apk"),
         description="Checks for filesystem artifacts associated with rooted devices.",
         confidence="medium"),
    dict(name="root_props_check", category="ROOT_DETECTION",
         regex=_c(r"ro\.build\.tags|ro\.debuggable|ro\.secure"),
         description="Reads build/system properties often inspected as part of root checks.",
         confidence="low"),

    # --- Magisk / MagiskHide / Zygisk / DenyList ---
    dict(name="magisk_indicators", category="ROOT_DETECTION",
         regex=_c(
             r"com\.topjohnwu\.magisk|MagiskManager|MagiskHide|ZygiskModule|ZygiskApi|"
             r"resetprop|magiskpolicy|MagiskSU"
         ),
         description="Magisk / MagiskHide / Zygisk indicators: package name, manager app, or API strings.",
         confidence="high"),
    dict(name="magisk_paths", category="ROOT_DETECTION",
         regex=_c(r"/data/adb/magisk|/sbin/\.magisk|/dev/pts.*magisk"),
         description="Magisk-specific filesystem paths checked to detect Magisk installation.",
         confidence="high"),

    # --- LSPosed / EdXposed ---
    dict(name="lsposed_edxposed", category="ROOT_DETECTION",
         regex=_c(
             r"org\.lsposed|io\.github\.lsposed|EdXposed|LSPosedManager|"
             r"LSPosed|io\.github\.lsposed\.manager"
         ),
         description="LSPosed / EdXposed Xposed-based hook framework package references.",
         confidence="high"),

    # --- KernelSU ---
    dict(name="kernelsu_indicators", category="ROOT_DETECTION",
         regex=_c(
             r"com\.github\.usmanjutt84\.kernelsu|kernelsu|KernelSU|/data/adb/ksu"
         ),
         description="KernelSU root solution: package name, keyword, or filesystem path.",
         confidence="high"),

    # --- APatch ---
    dict(name="apatch_indicators", category="ROOT_DETECTION",
         regex=_c(r"\bapatch\b|/data/adb/apatch"),
         description="APatch kernel-level root solution reference or path check.",
         confidence="high"),

    # --- Native root via su null-byte string ---
    dict(name="su_native_string", category="ROOT_DETECTION",
         regex=_c(r"su\\x00|/data/adb/(?:magisk|ksu|apatch)"),
         description="Native-level null-terminated 'su' string or /data/adb/* path, probing root via JNI.",
         confidence="high"),

    # --- SuperSU legacy paths ---
    dict(name="supersu_legacy_paths", category="ROOT_DETECTION",
         regex=_c(r"/system/xbin/daemonsu|/system/xbin/sugote"),
         description="SuperSU legacy daemon paths checked as root indicators.",
         confidence="high"),

    # --- RootCloak ---
    dict(name="rootcloak_ref", category="ROOT_DETECTION",
         regex=_c(r"com\.devadvance\.rootcloak|RootCloak"),
         description="RootCloak root-hiding app detected — may be used to evade root checks.",
         confidence="medium"),

    # --- Root prop values ---
    dict(name="root_prop_values", category="ROOT_DETECTION",
         regex=_c(r"ro\.build\.type\s*=\s*eng|ro\.debuggable\s*=\s*1"),
         description="System property values indicating an engineering/debug build (rooted ROM indicator).",
         confidence="medium"),

    # --- Knox Guard bypass ---
    dict(name="knoxguard_ref", category="ROOT_DETECTION",
         regex=_c(r"KnoxGuard|TIMA"),
         description="Samsung KnoxGuard / TIMA (Trusted Integrity Measurement Architecture) reference.",
         confidence="medium"),

    # --- System property introspection ---
    dict(name="system_properties_get", category="ROOT_DETECTION",
         regex=_c(r"SystemProperties\.get|getProperty.*ro\."),
         description="Runtime system-property introspection used to read ro.* build props for root detection.",
         confidence="low"),

    # --- Additional dangerous root/ADB paths ---
    dict(name="adb_root_paths", category="ROOT_DETECTION",
         regex=_c(r"/data/adb/|/sbin/\.magisk|/dev/pts|/proc/mounts.*\bsu\b"),
         description="Additional root-indicator paths: /data/adb/, Magisk mount points, or su in /proc/mounts.",
         confidence="medium"),

    # --- SafetyNet bypass detection ---
    dict(name="safetynet_bypass_detect", category="ROOT_DETECTION",
         regex=_c(r"com\.scottyab\.safetynet|DroidGuard"),
         description="SafetyNet bypass tool reference or DroidGuard string (SafetyNet internals detector).",
         confidence="high"),

    # ====================================================================
    # INTEGRITY / ATTESTATION — Android
    # ====================================================================
    dict(name="safetynet_api", category="INTEGRITY_CHECK",
         regex=_c(r"com\.google\.android\.gms\.safetynet|SafetyNetApi|SafetyNetClient"),
         description="Google SafetyNet Attestation API usage (device/app integrity check).",
         confidence="high"),
    dict(name="play_integrity_api", category="INTEGRITY_CHECK",
         regex=_c(r"com\.google\.android\.play\.core\.integrity|IntegrityManager|requestIntegrityToken"),
         description="Google Play Integrity API usage (successor to SafetyNet).",
         confidence="high"),
    dict(name="signature_verification", category="INTEGRITY_CHECK",
         regex=_c(r"getPackageInfo\([^)]*GET_SIGNATURES|checkSignatures\(|PackageInfo\.signatures|"
                   r"GET_SIGNING_CERTIFICATES"),
         description="Reads/validates the APK's own signing certificate at runtime (anti-repackaging check).",
         confidence="high"),
    dict(name="apk_hash_selfcheck", category="INTEGRITY_CHECK",
         regex=_c(r"MessageDigest\.getInstance\(\s*[\"'](SHA|MD5)|getPackageCodePath\(\)|"
                   r"SourceDir\b"),
         description="Computes a hash of its own APK/DEX/classes as a tamper-detection self-check.",
         confidence="medium"),
    dict(name="installer_package_check", category="INTEGRITY_CHECK",
         regex=_c(r"getInstallerPackageName\("),
         description="Verifies the app was installed via an expected store (e.g. Play Store), flags sideloading.",
         confidence="medium"),

    # --- Play Integrity verdict tokens ---
    dict(name="play_integrity_verdict", category="INTEGRITY_CHECK",
         regex=_c(
             r"MEETS_DEVICE_INTEGRITY|MEETS_STRONG_INTEGRITY|MEETS_BASIC_INTEGRITY|"
             r"getIntegrityToken|VERDICT_OPT_OUT"
         ),
         description="Play Integrity API verdict strings indicating device/app integrity evaluation.",
         confidence="high"),

    # --- Self-signature SHA-256 comparison ---
    dict(name="signature_sha256_compare", category="INTEGRITY_CHECK",
         regex=_c(r"MessageDigest.*SHA-256|SHA-256.*signature|byte.*\[\].*signature"),
         description="SHA-256 self-signature comparison: anti-repackaging check via digest of own cert.",
         confidence="high"),

    # --- DEX tamper / dynamic loading ---
    dict(name="dex_tamper_load", category="INTEGRITY_CHECK",
         regex=_c(r"DexClassLoader|InMemoryDexClassLoader|dalvik\.system\.DexFile"),
         description="Dynamic DEX loading — potential tamper indicator or code-injection vector.",
         confidence="medium"),

    # --- Native library hash / CRC check ---
    dict(name="native_lib_hash_check", category="INTEGRITY_CHECK",
         regex=_c(r"\bCRC32\b|\bAdler32\b"),
         description="CRC32/Adler32 integrity check over self (native library or DEX verification).",
         confidence="medium"),

    # --- Smali signature checks ---
    dict(name="smali_signature_check", category="INTEGRITY_CHECK",
         regex=_c(r"check-cast.*PackageInfo|iget-object.*signatures"),
         description="Smali-level signature field access — direct bytecode signature tamper check.",
         confidence="high"),

    # --- APK V2/V3 scheme verification ---
    dict(name="apk_signing_scheme_verify", category="INTEGRITY_CHECK",
         regex=_c(r"v2.*sign|sign.*v2|apkVerif|SignatureSchemeVerifier"),
         description="APK V2/V3 signature scheme verification, often used in anti-repackaging checks.",
         confidence="high"),

    # ====================================================================
    # ANTI-DEBUG — Android
    # ====================================================================
    dict(name="debugger_connected", category="ANTI_DEBUG",
         regex=_c(r"Debug\.isDebuggerConnected\(|Debug\.waitingForDebugger\("),
         description="Checks whether a Java-level debugger is currently attached.",
         confidence="high"),
    dict(name="debuggable_flag", category="ANTI_DEBUG",
         regex=_c(r"ApplicationInfo\.FLAG_DEBUGGABLE|android:debuggable"),
         description="Inspects its own ApplicationInfo debuggable flag.",
         confidence="medium"),
    dict(name="tracerpid_check", category="ANTI_DEBUG",
         regex=_c(r"TracerPid|/proc/self/status"),
         description="Reads /proc/self/status TracerPid to detect an attached native debugger/ptrace.",
         confidence="high"),
    dict(name="ptrace_self", category="ANTI_DEBUG",
         regex=_c(r"\bptrace\s*\(|PTRACE_TRACEME|PTRACE_ATTACH"),
         description="Native ptrace() usage, commonly used for self-attach anti-debug tricks.",
         confidence="high"),

    # --- Additional anti-debug probes ---
    dict(name="debug_native_heap_probe", category="ANTI_DEBUG",
         regex=_c(r"android\.os\.Debug\.getNativeHeapSize|Debug\.getNativeHeapSize"),
         description="getNativeHeapSize() used as a debugger probe (heap size differs under debugger).",
         confidence="medium"),
    dict(name="singleton_process_debug", category="ANTI_DEBUG",
         regex=_c(r"singletonProcessName|isBeingDebugged"),
         description="Process singleton / isBeingDebugged check used as anti-debug heuristic.",
         confidence="medium"),
    dict(name="proc_wchan_stat_check", category="ANTI_DEBUG",
         regex=_c(r"/proc/self/wchan|ptrace_stop|/proc/self/stat"),
         description="Reads /proc/self/wchan or /proc/self/stat to detect ptrace_stop (debugger attached).",
         confidence="high"),
    dict(name="timing_attack_antidebug", category="ANTI_DEBUG",
         regex=_c(r"SystemClock\.elapsedRealtime|System\.nanoTime"),
         description="Timing-based anti-debug: measures execution time delta to detect single-stepping.",
         confidence="low"),
    dict(name="strict_mode_inspection", category="ANTI_DEBUG",
         regex=_c(r"android\.os\.StrictMode"),
         description="StrictMode inspection — may be used to detect development/debug environment.",
         confidence="low"),
    dict(name="proc_fd_excessive", category="ANTI_DEBUG",
         regex=_c(r"/proc/self/fd"),
         description="Enumerates /proc/self/fd — excessive open file descriptors can indicate a debugger.",
         confidence="medium"),
    dict(name="jdwp_port_check", category="ANTI_DEBUG",
         regex=_c(r"\bJDWP\b|jdwp.*transport|jdwp.*port"),
         description="JDWP (Java Debug Wire Protocol) port or transport string — detects Java debugger.",
         confidence="high"),
    dict(name="proc_parent_name_check", category="ANTI_DEBUG",
         regex=_c(r"/proc/self/status.*Name:|Name:.*\bfield\b"),
         description="Reads parent process name from /proc/self/status as anti-debug heuristic.",
         confidence="medium"),

    # ====================================================================
    # ANTI-HOOK / ANTI-FRIDA — Android
    # ====================================================================
    dict(name="frida_indicators", category="ANTI_HOOK",
         regex=_c(r"frida-server|frida-agent|gum-js-loop|gmain|frida_agent_main|"
                   r"/data/local/tmp/(re\.)?frida|linjector"),
         description="String/process indicators used to detect Frida instrumentation.",
         confidence="high"),
    dict(name="frida_default_port", category="ANTI_HOOK",
         regex=_c(r"\b27042\b|\b27043\b"),
         description="Default Frida server port(s), often probed via socket connect as a detection technique.",
         confidence="medium"),
    dict(name="xposed_indicators", category="ANTI_HOOK",
         regex=_c(r"de\.robv\.android\.xposed|XposedBridge|XposedHelpers|XC_MethodHook"),
         description="Detection/usage of the Xposed hooking framework.",
         confidence="high"),
    dict(name="substrate_cydia", category="ANTI_HOOK",
         regex=_c(r"\bsubstrate\b|cydia"),
         description="Reference to Cydia Substrate hooking framework artifacts.",
         confidence="medium"),
    dict(name="maps_selfscan", category="ANTI_HOOK",
         regex=_c(r"/proc/self/maps"),
         description="Scans its own loaded-library map, often to detect injected hooking libraries.",
         confidence="medium"),

    # --- LSPosed detection ---
    dict(name="lsposed_hook_detect", category="ANTI_HOOK",
         regex=_c(r"LSPosed|org\.lsposed|io\.github\.lsposed\.manager"),
         description="LSPosed module framework detection (Xposed successor).",
         confidence="high"),

    # --- Riru ---
    dict(name="riru_detect", category="ANTI_HOOK",
         regex=_c(r"\briru\b|com\.ririsoftware|/data/misc/riru"),
         description="Riru (Riru - Core) Zygote injection framework detection.",
         confidence="high"),

    # --- ReZygisk ---
    dict(name="rezygisk_detect", category="ANTI_HOOK",
         regex=_c(r"rezygisk"),
         description="ReZygisk (alternative Zygisk implementation) detection.",
         confidence="high"),

    # --- KernelSU hook modules ---
    dict(name="kernelsu_hook_detect", category="ANTI_HOOK",
         regex=_c(r"ksu_hook|kp_hook"),
         description="KernelSU kernel-level hook module indicators.",
         confidence="high"),

    # --- Dobby hooking library ---
    dict(name="dobby_hook_detect", category="ANTI_HOOK",
         regex=_c(r"\bdobby\b|DobbyHook"),
         description="Dobby inline hooking library detection (native Android/iOS hook framework).",
         confidence="high"),

    # --- ShadowHook ---
    dict(name="shadowhook_detect", category="ANTI_HOOK",
         regex=_c(r"shadowhook|SHADOWHOOK"),
         description="ShadowHook (ByteDance) inline hook library detection.",
         confidence="high"),

    # --- bhook / bytehook ---
    dict(name="bytehook_detect", category="ANTI_HOOK",
         regex=_c(r"bytehook|bh_hook"),
         description="ByteHook (bhook) PLT hook library detection.",
         confidence="high"),

    # --- VirtualApp / VirtualXposed ---
    dict(name="virtual_app_detect", category="ANTI_HOOK",
         regex=_c(r"io\.virtualapp|com\.lody\.virtual|VirtualCore|VirtualXposed"),
         description="VirtualApp / VirtualXposed — virtual execution environment that can host hooks.",
         confidence="high"),

    # --- Whale framework ---
    dict(name="whale_hook_detect", category="ANTI_HOOK",
         regex=_c(r"com\.whale|whale_hook"),
         description="Whale hooking framework reference.",
         confidence="medium"),

    # --- SO names in /proc/self/maps ---
    dict(name="maps_so_hook_names", category="ANTI_HOOK",
         regex=_c(r"frida-gadget\.so|xposed\.so|substrate\.so|riru\.so|zygisk\.so"),
         description="Known hooking library SO names scanned from /proc/self/maps.",
         confidence="high"),

    # --- Inline hook detection (jump trampoline) ---
    dict(name="inline_hook_trampoline", category="ANTI_HOOK",
         regex=_c(r"function.*prologue|trampoline.*hook|hook.*trampoline|jump.*patch"),
         description="Inline hook trampoline detection — checks function prologues for B/BL patches.",
         confidence="medium"),

    # --- Ingenic / Epic hooking ---
    dict(name="epic_ingenic_hook", category="ANTI_HOOK",
         regex=_c(r"me\.weishu\.epic|com\.taobao\.android\.dexposed"),
         description="Epic / dexposed Android method hooking framework reference.",
         confidence="high"),

    # --- Frida USB mode / gadget in maps ---
    dict(name="frida_gadget_usb", category="ANTI_HOOK",
         regex=_c(r"frida-gadget|gum-js-loop|gumjs"),
         description="Frida Gadget (USB/embedded mode) or GumJS engine detection.",
         confidence="high"),

    # ====================================================================
    # EMULATOR DETECTION — Android
    # ====================================================================
    dict(name="emulator_build_props", category="EMULATOR_DETECT",
         regex=_c(r"ro\.kernel\.qemu|goldfish|ranchu|generic_x86|Build\.FINGERPRINT.*generic"),
         description="Checks build properties/fingerprint strings typical of AVD/emulator images.",
         confidence="medium"),
    dict(name="emulator_device_files", category="EMULATOR_DETECT",
         regex=_c(r"/dev/socket/qemud|/dev/qemu_pipe"),
         description="Checks for emulator-specific device files.",
         confidence="medium"),

    # --- Build.MANUFACTURER / MODEL / HARDWARE extended ---
    dict(name="emulator_manufacturer_check", category="EMULATOR_DETECT",
         regex=_c(r"Build\.MANUFACTURER.*(?:Genymotion|unknown|Andy|Nox|MEmu)|"
                   r"(?:Genymotion|unknown|Andy|Nox|MEmu).*Build\.MANUFACTURER"),
         description="Build.MANUFACTURER emulator values: Genymotion, Nox, MEmu, Andy, unknown.",
         confidence="medium"),
    dict(name="emulator_model_check", category="EMULATOR_DETECT",
         regex=_c(
             r"Build\.MODEL.*(?:sdk|emulator|Android SDK built for x86|google_sdk|Droid4X|TiantianVM)|"
             r"(?:sdk|google_sdk|Droid4X|TiantianVM).*Build\.MODEL"
         ),
         description="Build.MODEL emulator values: sdk, google_sdk, Droid4X, TiantianVM.",
         confidence="medium"),
    dict(name="emulator_hardware_check", category="EMULATOR_DETECT",
         regex=_c(r"Build\.HARDWARE.*(?:goldfish|ranchu|vbox86|nox|andy)|"
                   r"(?:vbox86|nox|andy).*Build\.HARDWARE"),
         description="Build.HARDWARE emulator values: goldfish, ranchu, vbox86, nox, andy.",
         confidence="medium"),
    dict(name="emulator_vbox_files", category="EMULATOR_DETECT",
         regex=_c(r"/dev/vboxguest|/dev/vboxuser"),
         description="VirtualBox guest device files indicating VirtualBox-based emulator (Genymotion).",
         confidence="high"),
    dict(name="emulator_no_accelerometer", category="EMULATOR_DETECT",
         regex=_c(r"SensorManager.*accelerometer|getDefaultSensor.*TYPE_ACCELEROMETER"),
         description="Accelerometer sensor absence check — emulators often lack real sensors.",
         confidence="low"),
    dict(name="emulator_cpuinfo_x86", category="EMULATOR_DETECT",
         regex=_c(r"/proc/cpuinfo.*(?:x86|intel)|(?:x86|intel).*processor"),
         description="/proc/cpuinfo x86/Intel processor name — emulator running on x86 host.",
         confidence="medium"),
    dict(name="emulator_device_id_zeros", category="EMULATOR_DETECT",
         regex=_c(r"getDeviceId\(\).*0{10,}|TelephonyManager.*0{10,}"),
         description="TelephonyManager.getDeviceId() returning all zeros — emulator indicator.",
         confidence="medium"),
    dict(name="emulator_cpu_abi_x86", category="EMULATOR_DETECT",
         regex=_c(r"ro\.product\.cpu\.abi.*x86|cpu\.abi.*x86"),
         description="ro.product.cpu.abi = x86 system property check for emulator detection.",
         confidence="medium"),
    dict(name="emulator_network_ip", category="EMULATOR_DETECT",
         regex=_c(r"10\.0\.2\.2|10\.0\.3\.2"),
         description="Default emulator gateway IPs: 10.0.2.2 (AVD) and 10.0.3.2 (Genymotion).",
         confidence="medium"),
    dict(name="emulator_bluestacks", category="EMULATOR_DETECT",
         regex=_c(r"com\.bluestacks|BST_LockScreen|bstfolder"),
         description="BlueStacks emulator package / lock screen / folder references.",
         confidence="high"),
    dict(name="emulator_ldplayer", category="EMULATOR_DETECT",
         regex=_c(r"com\.ldmnq\.launcher3"),
         description="LDPlayer emulator launcher package reference.",
         confidence="high"),

    # ====================================================================
    # MDM / DEVICE-MANAGEMENT — Android
    # ====================================================================
    dict(name="device_policy_manager", category="MDM_CHECK",
         regex=_c(r"android\.app\.admin\.DevicePolicyManager|DevicePolicyManager\b|"
                   r"getSystemService\(\s*[\"']device_policy[\"']\s*\)"),
         description="Uses DevicePolicyManager -- the entry point for querying MDM / device-admin state.",
         confidence="medium"),
    dict(name="device_owner_check", category="MDM_CHECK",
         regex=_c(r"isDeviceOwnerApp\(|isProfileOwnerApp\(|isDeviceManaged\(|"
                   r"isOrganizationOwnedDeviceWithManagedProfile\(|getDeviceOwner\(|"
                   r"isDeviceOwner\b|isProfileOwner\b"),
         description="Queries whether a device/profile owner (MDM) is provisioned.",
         confidence="high"),
    dict(name="managed_profile_check", category="MDM_CHECK",
         regex=_c(r"isManagedProfile\(|getUserProfiles\(|UserManager\.DISALLOW_|"
                   r"android\.os\.UserManager|bindDeviceAdmin"),
         description="Detects a work profile / managed user (Android for Work / BYOD container).",
         confidence="medium"),
    dict(name="device_admin_active", category="MDM_CHECK",
         regex=_c(r"isAdminActive\(|getActiveAdmins\(|DeviceAdminReceiver|BIND_DEVICE_ADMIN|"
                   r"android\.app\.action\.ADD_DEVICE_ADMIN"),
         description="Checks for an active Device Admin receiver (legacy MDM enforcement hook).",
         confidence="medium"),
    dict(name="app_restrictions_check", category="MDM_CHECK",
         regex=_c(r"getApplicationRestrictions\(|RestrictionsManager\b|"
                   r"getSystemService\(\s*[\"']restrictions[\"']\s*\)"),
         description="Reads managed app configuration / restrictions pushed by an EMM console.",
         confidence="medium"),
    dict(name="mdm_vendor_sdk", category="MDM_CHECK",
         regex=_c(
             r"com\.airwatch|com\.vmware\.(view|ws1|workspace)|awsdk|"
             r"com\.mobileiron|com\.ivanti|"
             r"com\.microsoft\.intune|com\.microsoft\.windowsintune|com\.microsoft\.intune\.mam|"
             r"com\.citrix\.(mdx|worx|mvpn)|com\.zenprise|"
             r"com\.blackberry\.|com\.good\.|com\.blackberry\.bbd|"
             r"com\.samsung\.android\.knox|SamsungKnox|EnterpriseDeviceManager|EnterpriseLicenseManager|"
             r"net\.soti\.|com\.soti\.|"
             r"com\.manageengine|com\.mdm\.|com\.hexnode|com\.scalefusion|io\.scalefusion|"
             r"com\.jamf|com\.kandji|com\.miradore|com\.baidu\.bmp|com\.42gears|com\.gears42"
         ),
         description="References a known MDM/EMM vendor SDK (AirWatch/WS1, Intune, MobileIron, Knox, ...).",
         confidence="high"),
    dict(name="afw_provisioning", category="MDM_CHECK",
         regex=_c(r"android\.app\.extra\.PROVISIONING_|PROVISIONING_MODE_|"
                   r"ACTION_PROVISION_MANAGED_(DEVICE|PROFILE)|setDeviceOwner\("),
         description="Android-for-Work provisioning intents/APIs -- app is management-aware.",
         confidence="medium"),
    dict(name="knox_container", category="MDM_CHECK",
         regex=_c(r"knox\.container|KnoxContainerManager|RCPManager|"
                   r"com\.sec\.enterprise|persona\b.*knox|isKnoxEnabled\("),
         description="Samsung Knox container / enterprise API usage.",
         confidence="medium"),

    # --- Extended MDM patterns ---
    dict(name="device_admin_info_extended", category="MDM_CHECK",
         regex=_c(r"android\.app\.admin\.DeviceAdminInfo|DevicePolicyInfo"),
         description="DeviceAdminInfo / DevicePolicyInfo — detailed MDM policy introspection.",
         confidence="medium"),
    dict(name="zero_touch_enrollment", category="MDM_CHECK",
         regex=_c(r"com\.google\.android\.apps\.work\.oobconfig|ACTION_ADMIN_POLICY_COMPLIANCE"),
         description="Zero-touch enrollment package or policy-compliance action — corporate provisioning.",
         confidence="high"),
    dict(name="cope_cobo_check", category="MDM_CHECK",
         regex=_c(r"isCompanyOwnedPersonallyEnabled|getPersonalAppsSuspendedReasons"),
         description="COPE/COBO ownership model API — detects managed corporate device.",
         confidence="high"),
    dict(name="per_app_vpn_check", category="MDM_CHECK",
         regex=_c(r"VpnManager|android\.net\.VpnManager|Ikev2VpnProfile"),
         description="Per-app VPN / IKEv2 profile API — MDM-managed VPN configuration.",
         confidence="medium"),
    dict(name="oemconfig_check", category="MDM_CHECK",
         regex=_c(r"com\.airwatch\.oemconfig|com\.mobileiron\.oemconfig"),
         description="OEMConfig managed configuration interface for MDM vendors.",
         confidence="high"),
    dict(name="cross_profile_intents", category="MDM_CHECK",
         regex=_c(r"cross.?profile.*intent|startActivityForUserWithFeature|"
                   r"CrossProfileApps"),
         description="Cross-profile intents / CrossProfileApps API usage in work-profile context.",
         confidence="medium"),

    # ====================================================================
    # SSL / CERTIFICATE PINNING — Android
    # ====================================================================
    dict(name="okhttp_certificate_pinner", category="SSL_PINNING",
         regex=_c(r"okhttp3?\.CertificatePinner|CertificatePinner\.Builder|\.certificatePinner\(|"
                   r"new\s+CertificatePinner"),
         description="OkHttp CertificatePinner -- pins server certs/SPKI hashes at the HTTP client layer.",
         confidence="high"),
    dict(name="pinned_spki_hash", category="SSL_PINNING",
         regex=_c(r"sha256/[A-Za-z0-9+/=]{43,}|sha1/[A-Za-z0-9+/=]{27,}"),
         description="Literal pinned public-key hash (SPKI pin) embedded in code/resources.",
         confidence="high"),
    dict(name="network_security_config_pins", category="SSL_PINNING",
         regex=_c(r"<pin-set|<pin\s+digest|network_security_config|networkSecurityConfig"),
         description="Android Network Security Config pin-set (declarative certificate pinning).",
         confidence="high"),
    dict(name="custom_trustmanager", category="SSL_PINNING",
         regex=_c(r"implements\s+X509TrustManager|extends\s+X509ExtendedTrustManager|"
                   r"checkServerTrusted\(|checkClientTrusted\(|X509TrustManager\b"),
         description="Custom X509TrustManager -- often a hand-rolled pinning / cert-validation routine.",
         confidence="medium"),
    dict(name="custom_hostname_verifier", category="SSL_PINNING",
         regex=_c(r"implements\s+HostnameVerifier|HostnameVerifier\b|setHostnameVerifier\(|"
                   r"setDefaultHostnameVerifier\("),
         description="Custom HostnameVerifier -- may enforce an expected host/cert binding.",
         confidence="medium"),
    dict(name="ssl_context_pinning", category="SSL_PINNING",
         regex=_c(r"SSLContext\.getInstance\(|TrustManagerFactory\.getInstance\(|"
                   r"KeyStore\.getInstance\(\s*[\"'](BKS|PKCS12)|\.bks\b|trusted_roots"),
         description="Builds a custom SSLContext/TrustManagerFactory from a bundled keystore (pinned trust store).",
         confidence="medium"),
    dict(name="trustkit_pinning", category="SSL_PINNING",
         regex=_c(r"com\.datatheorem\.android\.trustkit|TrustKit\b|"
                   r"appmattus\.certificatetransparency|conscrypt\b.*pin"),
         description="Third-party pinning library (TrustKit / Appmattus CT) in use.",
         confidence="high"),
    dict(name="webview_ssl_error_handler", category="SSL_PINNING",
         regex=_c(r"onReceivedSslError\(|SslErrorHandler\b|\.proceed\(\)|\.cancel\(\)\s*;.*ssl"),
         description="WebView onReceivedSslError handler -- controls whether invalid certs are accepted.",
         confidence="low"),

    # --- Extended SSL pinning ---
    dict(name="retrofit_ssl_pinning", category="SSL_PINNING",
         regex=_c(r"retrofit2.*pins|PinningSSLSocketFactory"),
         description="Retrofit SSL pinning configuration or PinningSSLSocketFactory.",
         confidence="high"),
    dict(name="conscrypt_pinning", category="SSL_PINNING",
         regex=_c(r"conscrypt\.OkHttp|conscrypt\.Conscrypt"),
         description="Conscrypt SSL provider used with OkHttp for certificate pinning.",
         confidence="medium"),
    dict(name="volley_ssl_pinning", category="SSL_PINNING",
         regex=_c(r"com\.android\.volley.*ssl|HurlStack"),
         description="Volley HTTP library SSL/TLS customization or HurlStack with pinning.",
         confidence="medium"),
    dict(name="httpurlconnection_pinning", category="SSL_PINNING",
         regex=_c(r"javax\.net\.ssl\.HttpsURLConnection|getServerCertificates"),
         description="HttpsURLConnection certificate pinning via getServerCertificates().",
         confidence="medium"),
    dict(name="grpc_tls_pinning", category="SSL_PINNING",
         regex=_c(r"io\.grpc\.okhttp\.OkHttpChannelBuilder|sslSocketFactory.*grpc|grpc.*sslSocketFactory"),
         description="gRPC OkHttp channel builder with custom SSL socket factory (TLS pinning).",
         confidence="high"),
    dict(name="manual_cert_der_compare", category="SSL_PINNING",
         regex=_c(r"byte.*DER|DER.*byte|Arrays\.equals.*cert|cert.*Arrays\.equals"),
         description="Manual byte-level comparison of DER-encoded certificate for pinning.",
         confidence="medium"),
    dict(name="android_keystore_cert_chain", category="SSL_PINNING",
         regex=_c(r"android\.security\.keystore|KeyChain\.getCertificateChain"),
         description="Android Keystore usage with certificate chain validation for SSL pinning.",
         confidence="medium"),
    dict(name="certificate_transparency_lib", category="SSL_PINNING",
         regex=_c(r"xyz\.doikki\.videoplayer|appmattus\.certificatetransparency"),
         description="Certificate Transparency library integration for advanced pinning.",
         confidence="medium"),

    # ====================================================================
    # RASP / APP SHIELDING — Android
    # ====================================================================
    dict(name="rasp_vendor_sdk", category="RASP_DETECTION",
         regex=_c(r"com\.appdome|appdome|com\.promon|promonshield|"
                  r"dexguard|ixguard|guardsquare|"
                  r"com\.arxan|digital\.ai|"
                  r"protectt\.ai|appprotectt|"
                  r"zimperium|zshield|"
                  r"approov|criticalblue|"
                  r"iverify|appsealing|"
                  r"com\.lockincomp\.liapp|liapp|"
                  r"dexprotector|licel|"
                  r"byterialab|byteria|alphyn|"
                  r"pradeo|nowsecure|"
                  r"com\.secneo|com\.vasco|com\.onespan|com\.preemptive"),
         description="References a known RASP vendor SDK (Appdome, DexGuard, Promon, Arxan, Zimperium, ...).",
         confidence="high"),
    dict(name="rasp_generic_check", category="RASP_DETECTION",
         regex=_c(r"isRaspEnabled|checkRasp|RaspManager|initRasp|RaspClient"),
         description="Generic RASP integration initialization or check method.",
         confidence="medium"),

    # --- Extended RASP vendors ---
    dict(name="talsec_freerasp", category="RASP_DETECTION",
         regex=_c(r"com\.aheaditec\.talsec|freeRasp|TalsecConfig"),
         description="Talsec / freeRASP open-source RASP SDK integration.",
         confidence="high"),
    dict(name="promon_shield", category="RASP_DETECTION",
         regex=_c(r"com\.promon\.shield"),
         description="Promon SHIELD app protection SDK reference.",
         confidence="high"),
    dict(name="verimatrix_rasp", category="RASP_DETECTION",
         regex=_c(r"com\.verimatrix|VCAS"),
         description="Verimatrix VCAS / app-protection SDK reference.",
         confidence="high"),
    dict(name="intertrust_neverware", category="RASP_DETECTION",
         regex=_c(r"com\.intertrust"),
         description="Intertrust Neverware (now Vitria) RASP solution reference.",
         confidence="high"),
    dict(name="datadome_rasp", category="RASP_DETECTION",
         regex=_c(r"com\.datadome"),
         description="DataDome bot/fraud protection SDK reference.",
         confidence="medium"),
    dict(name="incognia_rasp", category="RASP_DETECTION",
         regex=_c(r"com\.incognia"),
         description="Incognia location-based fraud detection SDK reference.",
         confidence="medium"),
    dict(name="threatcast_rasp", category="RASP_DETECTION",
         regex=_c(r"com\.threatcast"),
         description="Threatcast RASP / threat intelligence SDK reference.",
         confidence="medium"),
    dict(name="entersekt_rasp", category="RASP_DETECTION",
         regex=_c(r"com\.entersekt"),
         description="Entersekt authentication / RASP SDK reference.",
         confidence="medium"),
    dict(name="rasp_heap_inspection", category="RASP_DETECTION",
         regex=_c(r"InstrumentationRegistry|getInstrumentation\(\)|android\.app\.Instrumentation"),
         description="Runtime heap/instrumentation inspection to detect testing/RASP agents.",
         confidence="low"),

    # ====================================================================
    # iOS-specific — JAILBREAK_DETECT
    # ====================================================================
    dict(name="ios_jailbreak_tools", category="JAILBREAK_DETECT",
         regex=_c(
             r"unc0ver|checkra1n|palera1n|Dopamine|Fugu15|XinaA15|Taurine|"
             r"Odyssey|Chimera|Phoenix|Electra|Meridian"
         ),
         description="Modern iOS jailbreak tool names found in binary strings or source.",
         confidence="high"),
    dict(name="ios_jailbreak_paths", category="JAILBREAK_DETECT",
         regex=_c(
             r"/var/jb|/var/LIB|/usr/lib/TweakInject|/usr/lib/tweaks|"
             r"/var/containers/Bundle/DispatcherApp|/Library/TweakInject"
         ),
         description="Modern iOS jailbreak filesystem paths checked for jailbreak presence.",
         confidence="high"),
    dict(name="ios_package_managers", category="JAILBREAK_DETECT",
         regex=_c(r"\bSileo\b|\bZebra\b|\bInstaller5\b"),
         description="Alternative iOS package managers (Sileo, Zebra, Installer5) as jailbreak indicators.",
         confidence="high"),
    dict(name="ios_jailbreak_daemons", category="JAILBREAK_DETECT",
         regex=_c(r"bootstrapURL|jailbreakd|amfid"),
         description="Jailbreak daemon / bootstrap references: jailbreakd, amfid bypass, bootstrapURL.",
         confidence="high"),
    dict(name="ios_dyld_env_inject", category="JAILBREAK_DETECT",
         regex=_c(r"DYLD_INSERT_LIBRARIES"),
         description="DYLD_INSERT_LIBRARIES environment variable — dynamic library injection on iOS.",
         confidence="high"),
    dict(name="ios_sandbox_escape_check", category="JAILBREAK_DETECT",
         regex=_c(r"SandboxIOSChecker|/etc/fstab.*writ|sandbox.*escape"),
         description="iOS sandbox escape detection: fstab writable check or sandbox escape attempt.",
         confidence="high"),
    dict(name="ios_access_ssh_bash", category="JAILBREAK_DETECT",
         regex=_c(r'access\("/usr/bin/ssh"\)|access\("/bin/bash"\)'),
         description="Native access() call checking for SSH or bash — jailbreak indicator.",
         confidence="high"),
    dict(name="ios_filemanager_jb_paths", category="JAILBREAK_DETECT",
         regex=_c(r"FileManager\.fileExists\(atPath:\s*[\"']/(?:var/jb|Library/TweakInject|"
                   r"usr/lib/TweakInject|var/LIB)"),
         description="Swift FileManager.fileExists(atPath:) checking known jailbreak paths.",
         confidence="high"),
    dict(name="ios_fork_jb_detect", category="JAILBREAK_DETECT",
         regex=_c(r"Darwin\.fork\(\)|syscall\(SYS_fork\)|syscall\(SYS_ptrace\)"),
         description="fork()/ptrace() raw syscall used to detect jailbreak (non-sandboxed processes can fork).",
         confidence="high"),
    dict(name="ios_security_suite_ref", category="JAILBREAK_DETECT",
         regex=_c(r"SandboxIOSChecker|DTTJailbreakDetection|IOSSecuritySuite"),
         description="iOS jailbreak detection library reference (IOSSecuritySuite, DTTJailbreakDetection).",
         confidence="high"),

    # --- iOS Anti-Debug ---
    dict(name="ios_pt_deny_attach", category="ANTI_DEBUG",
         regex=_c(r"PT_DENY_ATTACH\s*=\s*31|ptrace\(PT_DENY_ATTACH|ptrace.*31.*0.*nil.*0"),
         description="iOS ptrace(PT_DENY_ATTACH, 0, nil, 0) -- prevents debugger attachment.",
         confidence="high"),
    dict(name="ios_sysctl_ptrace_check", category="ANTI_DEBUG",
         regex=_c(r"sysctl.*CTL_KERN|KERN_PROC.*KERN_PROC_PID|kinfo_proc|P_TRACED"),
         description="sysctl-based debugger detection: reads kinfo_proc and checks P_TRACED flag.",
         confidence="high"),
    dict(name="ios_getppid_check", category="ANTI_DEBUG",
         regex=_c(r"getppid\(\)\s*!=\s*1|getppid\(\).*heuristic"),
         description="getppid() != 1 heuristic -- detects debugger parent process on iOS.",
         confidence="medium"),
    dict(name="ios_amidebugged", category="ANTI_DEBUG",
         regex=_c(r"AmIBeingDebugged|isDebugged|debuggerAttached"),
         description="iOS anti-debug function: AmIBeingDebugged / isDebugged check.",
         confidence="high"),
    dict(name="ios_exception_ports_check", category="ANTI_DEBUG",
         regex=_c(r"task_get_exception_ports"),
         description="task_get_exception_ports() — checks for debugger-installed exception handlers.",
         confidence="high"),
    dict(name="ios_raw_syscall_svc", category="ANTI_DEBUG",
         regex=_c(r'__asm__\s*\(\s*"svc\s+0x80"\s*\)|asm.*svc.*0x80'),
         description="Raw ARM64 SVC 0x80 syscall instruction in inline assembly — anti-debug technique.",
         confidence="high"),
    dict(name="ios_mach_time_antidebug", category="ANTI_DEBUG",
         regex=_c(r"mach_absolute_time.*delta|delta.*mach_absolute_time"),
         description="mach_absolute_time() timing delta check — detects single-step debugging on iOS.",
         confidence="medium"),

    # --- iOS Anti-Hook ---
    dict(name="ios_dyld_image_scan", category="ANTI_HOOK",
         regex=_c(r"_dyld_image_count|_dyld_get_image_name"),
         description="iOS dyld image enumeration to detect injected dylibs/frameworks.",
         confidence="high"),
    dict(name="ios_fishhook_libffi", category="ANTI_HOOK",
         regex=_c(r"\bfishhook\b|\blibffi\b|___interpose"),
         description="fishhook / libffi / __interpose section — iOS symbol interposing hooks.",
         confidence="high"),
    dict(name="ios_mobile_substrate_hooks", category="ANTI_HOOK",
         regex=_c(r"MSHookFunction|MSGetImageByName"),
         description="MobileSubstrate / Cydia Substrate hooking API: MSHookFunction / MSGetImageByName.",
         confidence="high"),
    dict(name="ios_frida_dylib_detect", category="ANTI_HOOK",
         regex=_c(r"frida-agent\.dylib|FridaGadget|gum-js-loop"),
         description="Frida agent dylib or Gadget detection on iOS.",
         confidence="high"),
    dict(name="ios_dladdr_module_check", category="ANTI_HOOK",
         regex=_c(r"\bdladdr\b"),
         description="dladdr() — resolves address to symbol/library, used to detect unexpected modules.",
         confidence="medium"),
    dict(name="ios_vm_region_scan", category="ANTI_HOOK",
         regex=_c(r"vm_region_64|vm_region\b"),
         description="vm_region_64() memory region scanning for injected code/hooks.",
         confidence="medium"),
    dict(name="ios_la_symbol_ptr_check", category="ANTI_HOOK",
         regex=_c(r"__DATA\.__la_symbol_ptr|la_symbol_ptr"),
         description="Reading own __DATA.__la_symbol_ptr to detect PLT-level symbol swizzling.",
         confidence="high"),
    dict(name="ios_objc_swizzle_detect", category="ANTI_HOOK",
         regex=_c(r"method_getImplementation|method_setImplementation|method_exchangeImplementations"),
         description="ObjC method implementation comparison to detect runtime swizzling (hook detection).",
         confidence="medium"),

    # --- iOS SSL Pinning ---
    dict(name="ios_nsurlsession_pinning", category="SSL_PINNING",
         regex=_c(r"URLSession\(_:didReceive:completionHandler:\)|"
                   r"urlSession.*didReceive.*challenge"),
         description="NSURLSession delegate TLS challenge handler — implements certificate pinning.",
         confidence="high"),
    dict(name="ios_sectrust_evaluate", category="SSL_PINNING",
         regex=_c(r"SecTrustEvaluateWithError|SecTrustCopyResult"),
         description="SecTrustEvaluateWithError / SecTrustCopyResult — custom TLS trust evaluation.",
         confidence="high"),
    dict(name="ios_afnetworking_pinning", category="SSL_PINNING",
         regex=_c(r"AFSSLPinningMode|AFSecurityPolicy"),
         description="AFNetworking SSL pinning mode / security policy configuration.",
         confidence="high"),
    dict(name="ios_alamofire_pinning", category="SSL_PINNING",
         regex=_c(r"ServerTrustPolicy|ServerTrustEvaluating"),
         description="Alamofire ServerTrustPolicy / ServerTrustEvaluating for certificate pinning.",
         confidence="high"),
    dict(name="ios_trustkit_pinning", category="SSL_PINNING",
         regex=_c(r"TSKSPKIHashCache|kTSKSwizzleNetworkDelegates"),
         description="TrustKit iOS SDK: SPKI hash cache and network delegate swizzling for pinning.",
         confidence="high"),
    dict(name="ios_urlcredential_challenge", category="SSL_PINNING",
         regex=_c(r"URLCredential\(trust:\)|URLSession\.AuthChallengeDisposition"),
         description="URLCredential(trust:) / AuthChallengeDisposition — TLS certificate challenge handling.",
         confidence="medium"),
    dict(name="ios_grpc_tls_pinning", category="SSL_PINNING",
         regex=_c(r"GRPCCall\.setTLSPEMRootCerts"),
         description="gRPC iOS TLS PEM root certificate pinning via GRPCCall.",
         confidence="high"),
    dict(name="ios_embedded_cert_files", category="SSL_PINNING",
         regex=_c(r"\.cer\b|\.der\b|\.crt\b"),
         description="Embedded DER/CRT/CER certificate file reference — bundled pinning cert.",
         confidence="medium"),

    # --- iOS MDM ---
    dict(name="ios_mdm_profile", category="MDM_CHECK",
         regex=_c(r"MDMProfile|com\.apple\.mdm|com\.apple\.configurator"),
         description="iOS MDM profile payload type or Apple Configurator reference.",
         confidence="high"),
    dict(name="ios_ne_profile_manager", category="MDM_CHECK",
         regex=_c(r"NEProfileManager|MDMEnrollment"),
         description="NetworkExtension profile manager or MDM enrollment API.",
         confidence="high"),
    dict(name="ios_supervised_device_check", category="MDM_CHECK",
         regex=_c(r"MGCopyAnswer.*kMGQIsSupervised|isSupervised|CMSupervisedDeviceEnrollment"),
         description="iOS device supervision check: MGCopyAnswer(kMGQIsSupervised) or isSupervised.",
         confidence="high"),
    dict(name="ios_scep_enrollment", category="MDM_CHECK",
         regex=_c(r"SCEPCertificateEnrollment"),
         description="SCEP certificate enrollment — MDM certificate provisioning.",
         confidence="high"),
    dict(name="ios_mdm_vendor_sdk", category="MDM_CHECK",
         regex=_c(r"\bjamf\b|\bkandji\b|\bmosyle\b|\baddigy\b"),
         description="iOS MDM vendor SDK reference: Jamf, Kandji, Mosyle, Addigy.",
         confidence="high"),

    # --- iOS RASP ---
    dict(name="ios_security_suite_api", category="RASP_DETECTION",
         regex=_c(
             r"IOSSecuritySuite\.amIJailbroken\(\)|IOSSecuritySuite\.amIDebugged\(\)|"
             r"IOSSecuritySuite\.amIReverseEngineered\(\)"
         ),
         description="IOSSecuritySuite RASP API: jailbreak, debug, and reverse engineering checks.",
         confidence="high"),
    dict(name="ios_dtt_jailbreak_detection", category="RASP_DETECTION",
         regex=_c(r"DTTJailbreakDetection"),
         description="DTTJailbreakDetection (doubleencore) iOS jailbreak detection library.",
         confidence="high"),
    dict(name="ios_freerasp_talsec", category="RASP_DETECTION",
         regex=_c(r"TalsecApplication|freeRASP"),
         description="freeRASP / Talsec iOS application RASP protection.",
         confidence="high"),
    dict(name="ios_approov_token", category="RASP_DETECTION",
         regex=_c(r"Approov\.fetchApproovToken"),
         description="Approov iOS SDK: runtime app attestation token fetch.",
         confidence="high"),
    dict(name="ios_guardsquare_ixguard", category="RASP_DETECTION",
         regex=_c(r"\bixguard\b|GuardSquare.*iOS|AppProtect"),
         description="GuardSquare iXGuard / AppProtect iOS code protection reference.",
         confidence="high"),
    dict(name="ios_promon_shield", category="RASP_DETECTION",
         regex=_c(r"PromonShield"),
         description="Promon SHIELD iOS app protection SDK.",
         confidence="high"),

    # --- iOS Emulator / Simulator ---
    dict(name="ios_simulator_target", category="EMULATOR_DETECT",
         regex=_c(r"TARGET_OS_SIMULATOR|TARGET_IPHONE_SIMULATOR"),
         description="Compile-time simulator target macros — code path for simulator detection.",
         confidence="medium"),
    dict(name="ios_simulator_env", category="EMULATOR_DETECT",
         regex=_c(r"ProcessInfo\.processInfo\.environment\[.SIMULATOR_DEVICE_NAME.\]"),
         description="Swift ProcessInfo environment SIMULATOR_DEVICE_NAME check — running in Xcode Simulator.",
         confidence="high"),
    dict(name="ios_simulator_model", category="EMULATOR_DETECT",
         regex=_c(r'UIDevice\.current\.model\s*==\s*["\']iPhone Simulator["\']|'
                   r'UIDevice\.current\.model.*Simulator'),
         description="UIDevice.current.model == 'iPhone Simulator' runtime simulator check.",
         confidence="high"),
    dict(name="ios_sysctl_hw_machine", category="EMULATOR_DETECT",
         regex=_c(r'sysctlbyname\s*\(\s*"hw\.machine"'),
         description="sysctlbyname('hw.machine') — checks architecture; x86_64/arm64 indicates simulator.",
         confidence="medium"),
    dict(name="ios_xctest_class_check", category="EMULATOR_DETECT",
         regex=_c(r'NSClassFromString\s*\(\s*["\']XCTestCase["\']'),
         description="NSClassFromString('XCTestCase') — detects if running under XCTest test harness.",
         confidence="medium"),
]


# -----------------------------------------------------------------------
# Fast pre-filter support.
#
# A big combined regex over every source line is far too slow. Each pattern
# declares lowercase LITERAL substrings such that a line can only match
# that pattern if it contains at least one of them. build_prefilter() joins
# them into one pure-literal alternation. Only lines that trip the literal
# gate run the real regex loop.
#
# A pattern absent from this table is simply evaluated on every line (safe
# default). When editing a pattern's regex, re-check its trigger list.
# -----------------------------------------------------------------------
PATTERN_TRIGGERS = {
    # --- ROOT DETECTION ---
    "su_binary_path": ["/su"],
    "su_command_exec": ["which", "getruntime()"],
    "busybox_ref": ["busybox"],
    "root_management_pkg": ["noshufou", "chainfire.supersu", "koushikdutta.superuser",
                            "thirdparty.superuser", "topjohnwu.magisk", "kingroot.kinguser",
                            "kingo.root", "smedialink.oneclickroot", "zhiqupk.root",
                            "alephzain.framaroot", "yellowes.su"],
    "rootbeer_lib": ["rootbeer"],
    "build_tags_test_keys": ["test-keys", "build.tags"],
    "dangerous_root_paths": ["superuser.apk", "init.d"],
    "root_props_check": ["ro.build.tags", "ro.debuggable", "ro.secure"],
    "magisk_indicators": ["topjohnwu.magisk", "magiskmanager", "magiskhide",
                          "zygiskmodule", "zygiskapi", "resetprop", "magiskpolicy"],
    "magisk_paths": ["/data/adb/magisk", "/sbin/.magisk", "/dev/pts"],
    "lsposed_edxposed": ["lsposed", "io.github.lsposed", "edxposed", "lsposedmanager",
                         "org.lsposed"],
    "kernelsu_indicators": ["kernelsu", "/data/adb/ksu",
                            "com.github.usmanjutt84.kernelsu"],
    "apatch_indicators": ["apatch", "/data/adb/apatch"],
    "su_native_string": ["su\\x00", "/data/adb/"],
    "supersu_legacy_paths": ["/system/xbin/daemonsu", "/system/xbin/sugote"],
    "rootcloak_ref": ["rootcloak", "com.devadvance.rootcloak"],
    "root_prop_values": ["ro.build.type", "ro.debuggable"],
    "knoxguard_ref": ["knoxguard", "tima"],
    "system_properties_get": ["systemproperties.get", "getproperty"],
    "adb_root_paths": ["/data/adb/", "/sbin/.magisk", "/dev/pts", "/proc/mounts"],
    "safetynet_bypass_detect": ["com.scottyab.safetynet", "droidguard"],

    # --- INTEGRITY CHECK ---
    "safetynet_api": ["safetynet"],
    "play_integrity_api": ["integrity"],
    "signature_verification": ["get_signatures", "checksignatures(", "packageinfo.signatures",
                               "get_signing_certificates"],
    "apk_hash_selfcheck": ["messagedigest.getinstance(", "getpackagecodepath()", "sourcedir"],
    "installer_package_check": ["getinstallerpackagename"],
    "play_integrity_verdict": ["meets_device_integrity", "meets_strong_integrity",
                               "meets_basic_integrity", "getintegritytoken", "verdict_opt_out"],
    "signature_sha256_compare": ["messagedigest", "sha-256", "sha256"],
    "dex_tamper_load": ["dexclassloader", "inmemorydexclassloader", "dalvik.system.dexfile"],
    "native_lib_hash_check": ["crc32", "adler32"],
    "smali_signature_check": ["check-cast", "iget-object", "signatures"],
    "apk_signing_scheme_verify": ["v2", "apkverif", "signaturescheme"],

    # --- ANTI DEBUG ---
    "debugger_connected": ["isdebuggerconnected", "waitingfordebugger"],
    "debuggable_flag": ["flag_debuggable", "android:debuggable"],
    "tracerpid_check": ["tracerpid", "/proc/self/status"],
    "ptrace_self": ["ptrace"],
    "debug_native_heap_probe": ["getnativeheapsize", "android.os.debug"],
    "singleton_process_debug": ["singletonprocessname", "isbeingdebugged"],
    "proc_wchan_stat_check": ["/proc/self/wchan", "ptrace_stop", "/proc/self/stat"],
    "timing_attack_antidebug": ["systemclock.elapsedrealtime", "system.nanotime"],
    "strict_mode_inspection": ["strictmode"],
    "proc_fd_excessive": ["/proc/self/fd"],
    "jdwp_port_check": ["jdwp"],
    "proc_parent_name_check": ["/proc/self/status", "name:"],
    "ios_pt_deny_attach": ["pt_deny_attach", "ptrace"],
    "ios_sysctl_ptrace_check": ["ctl_kern", "kern_proc", "kinfo_proc", "p_traced"],
    "ios_getppid_check": ["getppid"],
    "ios_amidebugged": ["amidebugged", "isdebugged", "debuggerattached"],
    "ios_exception_ports_check": ["task_get_exception_ports"],
    "ios_raw_syscall_svc": ["svc 0x80", "__asm__"],
    "ios_mach_time_antidebug": ["mach_absolute_time"],

    # --- ANTI HOOK ---
    "frida_indicators": ["frida", "gum-js-loop", "gmain", "linjector"],
    "frida_default_port": ["27042", "27043"],
    "xposed_indicators": ["xposed", "xc_methodhook"],
    "substrate_cydia": ["substrate", "cydia"],
    "maps_selfscan": ["/proc/self/maps"],
    "lsposed_hook_detect": ["lsposed", "org.lsposed", "io.github.lsposed"],
    "riru_detect": ["riru", "com.ririsoftware", "/data/misc/riru"],
    "rezygisk_detect": ["rezygisk"],
    "kernelsu_hook_detect": ["ksu_hook", "kp_hook"],
    "dobby_hook_detect": ["dobby", "dobbyhook"],
    "shadowhook_detect": ["shadowhook"],
    "bytehook_detect": ["bytehook", "bh_hook"],
    "virtual_app_detect": ["io.virtualapp", "com.lody.virtual", "virtualcore", "virtualxposed"],
    "whale_hook_detect": ["com.whale", "whale_hook"],
    "maps_so_hook_names": ["frida-gadget.so", "xposed.so", "substrate.so", "riru.so", "zygisk.so"],
    "inline_hook_trampoline": ["trampoline", "prologue"],
    "epic_ingenic_hook": ["me.weishu.epic", "com.taobao.android.dexposed"],
    "frida_gadget_usb": ["frida-gadget", "gumjs"],
    "ios_dyld_image_scan": ["_dyld_image_count", "_dyld_get_image_name"],
    "ios_fishhook_libffi": ["fishhook", "libffi", "___interpose"],
    "ios_mobile_substrate_hooks": ["mshookfunction", "msgetimagebyname"],
    "ios_frida_dylib_detect": ["frida-agent.dylib", "fridagadget", "gum-js-loop"],
    "ios_dladdr_module_check": ["dladdr"],
    "ios_vm_region_scan": ["vm_region_64", "vm_region"],
    "ios_la_symbol_ptr_check": ["__data.__la_symbol_ptr", "la_symbol_ptr"],
    "ios_objc_swizzle_detect": ["method_getimplementation", "method_setimplementation",
                                "method_exchangeimplementations"],

    # --- EMULATOR DETECT ---
    "emulator_build_props": ["ro.kernel.qemu", "goldfish", "ranchu", "generic_x86",
                             "build.fingerprint"],
    "emulator_device_files": ["qemud", "qemu_pipe"],
    "emulator_manufacturer_check": ["genymotion", "build.manufacturer", "memuplay", "andy"],
    "emulator_model_check": ["build.model", "google_sdk", "droid4x", "tiantianyvm"],
    "emulator_hardware_check": ["build.hardware", "vbox86", "nox", "andy"],
    "emulator_vbox_files": ["/dev/vboxguest", "/dev/vboxuser"],
    "emulator_no_accelerometer": ["sensormanager", "type_accelerometer"],
    "emulator_cpuinfo_x86": ["/proc/cpuinfo", "x86", "intel"],
    "emulator_device_id_zeros": ["getdeviceid()", "telephonymanager"],
    "emulator_cpu_abi_x86": ["ro.product.cpu.abi"],
    "emulator_network_ip": ["10.0.2.2", "10.0.3.2"],
    "emulator_bluestacks": ["com.bluestacks", "bst_lockscreen", "bstfolder"],
    "emulator_ldplayer": ["com.ldmnq.launcher3"],
    "ios_simulator_target": ["target_os_simulator", "target_iphone_simulator"],
    "ios_simulator_env": ["simulator_device_name", "processinfo"],
    "ios_simulator_model": ["iphone simulator", "uidevice.current.model"],
    "ios_sysctl_hw_machine": ["hw.machine", "sysctlbyname"],
    "ios_xctest_class_check": ["xctestcase", "nsclassfromstring"],

    # --- MDM CHECK ---
    "device_policy_manager": ["devicepolicymanager", "device_policy"],
    "device_owner_check": ["isdeviceowner", "isprofileowner", "isdevicemanaged",
                           "isorganizationowned", "getdeviceowner"],
    "managed_profile_check": ["ismanagedprofile", "getuserprofiles", "usermanager",
                              "binddeviceadmin"],
    "device_admin_active": ["isadminactive", "getactiveadmins", "deviceadminreceiver",
                            "bind_device_admin", "add_device_admin"],
    "app_restrictions_check": ["restrictions"],
    "mdm_vendor_sdk": ["com.airwatch", "com.vmware.", "awsdk", "com.mobileiron", "com.ivanti",
                       "com.microsoft.intune", "com.microsoft.windowsintune", "com.citrix.",
                       "com.zenprise", "com.blackberry.", "com.good.", "com.samsung.android.knox",
                       "samsungknox", "enterprisedevicemanager", "enterpriselicensemanager",
                       "net.soti.", "com.soti.", "com.manageengine", "com.mdm.", "com.hexnode",
                       "com.scalefusion", "io.scalefusion", "com.jamf", "com.kandji",
                       "com.miradore", "com.baidu.bmp", "com.42gears", "com.gears42"],
    "afw_provisioning": ["provisioning_", "action_provision_managed_", "setdeviceowner("],
    "knox_container": ["knox.container", "knoxcontainermanager", "rcpmanager",
                       "com.sec.enterprise", "persona", "isknoxenabled"],
    "device_admin_info_extended": ["deviceadmininfo", "devicepolicyinfo"],
    "zero_touch_enrollment": ["com.google.android.apps.work.oobconfig",
                              "action_admin_policy_compliance"],
    "cope_cobo_check": ["iscompanyownedpersonallyenabled", "getpersonalappssuspendedreasons"],
    "per_app_vpn_check": ["vpnmanager", "android.net.vpnmanager", "ikev2vpnprofile"],
    "oemconfig_check": ["com.airwatch.oemconfig", "com.mobileiron.oemconfig"],
    "cross_profile_intents": ["cross-profile", "crossprofilapps"],
    "ios_mdm_profile": ["mdmprofile", "com.apple.mdm", "com.apple.configurator"],
    "ios_ne_profile_manager": ["neprofilemanager", "mdmenrollment"],
    "ios_supervised_device_check": ["mgcopyanswer", "issupervised",
                                    "cmssuperviseddeviceenrollment"],
    "ios_scep_enrollment": ["scepcertificateenrollment"],
    "ios_mdm_vendor_sdk": ["jamf", "kandji", "mosyle", "addigy"],

    # --- SSL PINNING ---
    "okhttp_certificate_pinner": ["certificatepinner"],
    "pinned_spki_hash": ["sha256/", "sha1/"],
    "network_security_config_pins": ["<pin", "network_security_config", "networksecurityconfig"],
    "custom_trustmanager": ["x509trustmanager", "x509extendedtrustmanager",
                            "checkservertrusted", "checkclienttrusted"],
    "custom_hostname_verifier": ["hostnameverifier"],
    "ssl_context_pinning": ["sslcontext.getinstance(", "trustmanagerfactory.getinstance(",
                            "keystore.getinstance(", ".bks", "trusted_roots"],
    "trustkit_pinning": ["datatheorem.android.trustkit", "trustkit",
                         "appmattus.certificatetransparency", "conscrypt"],
    "webview_ssl_error_handler": ["onreceivedsslerror(", "sslerrorhandler", ".proceed()",
                                  ".cancel()"],
    "retrofit_ssl_pinning": ["retrofit2", "pinningssls"],
    "conscrypt_pinning": ["conscrypt.okhttp", "conscrypt.conscrypt"],
    "volley_ssl_pinning": ["com.android.volley", "hurlstack"],
    "httpurlconnection_pinning": ["javax.net.ssl.httpsurlconnection", "getservercertificates"],
    "grpc_tls_pinning": ["io.grpc.okhttp.okhttpchannelbuilder", "sslsocketfactory"],
    "manual_cert_der_compare": ["der", "arrays.equals"],
    "android_keystore_cert_chain": ["android.security.keystore", "keychain.getcertificatechain"],
    "certificate_transparency_lib": ["appmattus.certificatetransparency"],
    "ios_nsurlsession_pinning": ["didreceive", "completionhandler", "urlsession"],
    "ios_sectrust_evaluate": ["sectrustevaluatewitherror", "sectrustecopresult"],
    "ios_afnetworking_pinning": ["afsslpinningmode", "afsecuritypolicy"],
    "ios_alamofire_pinning": ["servertrustpolicy", "servertrusteval"],
    "ios_trustkit_pinning": ["tskspkihashcache", "ktskswizzle"],
    "ios_urlcredential_challenge": ["urlcredential(trust:", "authchallengedisposition"],
    "ios_grpc_tls_pinning": ["grpccall.settlspemrootcerts"],
    "ios_embedded_cert_files": [".cer", ".der", ".crt"],

    # --- RASP DETECTION ---
    "rasp_vendor_sdk": [
        "appdome", "promon", "dexguard", "ixguard", "guardsquare", "arxan",
        "digital.ai", "protectt", "appprotectt", "zimperium", "zshield",
        "approov", "criticalblue", "iverify", "appsealing", "liapp",
        "dexprotector", "licel", "byteria", "alphyn", "pradeo", "nowsecure",
        "secneo", "vasco", "onespan", "preemptive",
    ],
    "rasp_generic_check": ["rasp"],
    "talsec_freerasp": ["com.aheaditec.talsec", "freerasp", "talsecconfig"],
    "promon_shield": ["com.promon.shield"],
    "verimatrix_rasp": ["com.verimatrix", "vcas"],
    "intertrust_neverware": ["com.intertrust"],
    "datadome_rasp": ["com.datadome"],
    "incognia_rasp": ["com.incognia"],
    "threatcast_rasp": ["com.threatcast"],
    "entersekt_rasp": ["com.entersekt"],
    "rasp_heap_inspection": ["instrumentationregistry", "getinstrumentation()",
                             "android.app.instrumentation"],
    "ios_security_suite_api": ["iossecuritysuite.amijailbroken",
                               "iossecuritysuite.amidebugged",
                               "iossecuritysuite.amireverseengineered"],
    "ios_dtt_jailbreak_detection": ["dttjailbreakdetection"],
    "ios_freerasp_talsec": ["talsecapplication", "freerasp"],
    "ios_approov_token": ["approov.fetchapproovtoken"],
    "ios_guardsquare_ixguard": ["ixguard", "appprotect"],
    "ios_promon_shield": ["promonshield"],

    # --- JAILBREAK DETECT (iOS) ---
    "ios_jailbreak_tools": ["unc0ver", "checkra1n", "palera1n", "dopamine", "fugu15",
                            "xinaa15", "taurine", "odyssey", "chimera", "phoenix",
                            "electra", "meridian"],
    "ios_jailbreak_paths": ["/var/jb", "/var/lib", "/usr/lib/tweakinject",
                            "/usr/lib/tweaks", "/library/tweakinject"],
    "ios_package_managers": ["sileo", "zebra", "installer5"],
    "ios_jailbreak_daemons": ["bootstrapurl", "jailbreakd", "amfid"],
    "ios_dyld_env_inject": ["dyld_insert_libraries"],
    "ios_sandbox_escape_check": ["sandboxioschecker", "/etc/fstab", "sandbox"],
    "ios_access_ssh_bash": ["access(\"/usr/bin/ssh\")", "access(\"/bin/bash\")"],
    "ios_filemanager_jb_paths": ["filemanager.fileexists(atpath:", "/var/jb",
                                 "/library/tweakinject"],
    "ios_fork_jb_detect": ["darwin.fork()", "syscall(sys_fork)", "syscall(sys_ptrace)"],
    "ios_security_suite_ref": ["sandboxioschecker", "dttjailbreakdetection",
                               "iossecuritysuite"],
}


def build_prefilter(patterns):
    """Return (literal_gate_regex_or_None, gated_patterns, always_run_patterns).

    literal_gate_regex: pure-literal alternation; if it does not match a
        (lower-cased) line, none of the `gated_patterns` can match it either.
    always_run_patterns: patterns with no trigger list -- evaluate on every line.
    """
    gated, always, lits = [], [], []
    for p in patterns:
        t = PATTERN_TRIGGERS.get(p["name"])
        if t:
            gated.append(p)
            lits.extend(s.lower() for s in t)
        else:
            always.append(p)
    gate = None
    if lits:
        uniq = sorted(set(lits), key=len, reverse=True)
        gate = re.compile("|".join(re.escape(s) for s in uniq), re.IGNORECASE)
    return gate, gated, always


# -----------------------------------------------------------------------
# Native-only patterns: interesting imported symbols to trace call-sites
# for in the disassembly of each .so (see native_scanner.py).
# -----------------------------------------------------------------------
NATIVE_INTERESTING_IMPORTS = {
    "ptrace":              ("ANTI_DEBUG",      "high",   "Native ptrace() call - classic self-attach anti-debug."),
    "fork":                ("ANTI_DEBUG",      "low",    "fork() -- frequently paired with ptrace-based anti-debug watchdogs."),
    "kill":                ("ANTI_DEBUG",      "low",    "kill() -- often used to SIGSTOP/SIGKILL self or a traced child."),
    "getppid":             ("ANTI_DEBUG",      "low",    "getppid() -- used in parent-process / tracer identity checks."),
    "readlink":            ("ANTI_HOOK",       "low",    "readlink() -- often used on /proc/self/exe or maps entries to inspect loaded modules."),
    "opendir":             ("ANTI_HOOK",       "low",    "opendir() -- often used to enumerate /proc or loaded-library directories."),
    "dlopen":              ("ANTI_HOOK",       "low",    "dlopen() -- may be used to probe for presence of injected libraries."),
    "system":              ("ROOT_DETECTION",  "medium", "system()/popen() -- may shell out to check for su/busybox."),
    "popen":               ("ROOT_DETECTION",  "medium", "popen() -- may shell out to check for su/busybox."),
    "access":              ("ROOT_DETECTION",  "low",    "access() -- commonly used to probe for su binary / root paths."),
    "inotify_add_watch":   ("ANTI_HOOK",       "medium", "inotify_add_watch() -- can be used to watch for file tampering/injection."),
    "mmap":                ("ANTI_HOOK",       "medium", "mmap() -- used to scan/modify memory regions for hook detection or injection."),
    "open":                ("ROOT_DETECTION",  "low",    "open() -- used to probe for su binary / root paths."),
    "stat":                ("ROOT_DETECTION",  "low",    "stat() -- used to check file existence (su/root paths)."),
    "getenv":              ("ANTI_DEBUG",      "low",    "getenv() -- may check DYLD_INSERT_LIBRARIES or other env vars for hook detection."),
    "pthread_create":      ("ANTI_DEBUG",      "medium", "pthread_create() -- used to spawn watchdog threads for anti-debug monitoring."),
    "sysctl":              ("ANTI_DEBUG",      "high",   "sysctl() -- used to detect debugger via P_TRACED flag in kinfo_proc."),
    "sysctlbyname":        ("ANTI_DEBUG",      "high",   "sysctlbyname() -- used to read hw.machine / kern.proc for emulator or debugger detection."),
    "task_threads":        ("ANTI_DEBUG",      "medium", "task_threads() -- used to count/inspect own threads, anti-debug technique."),
    "vm_region_64":        ("ANTI_HOOK",       "medium", "vm_region_64() -- memory region scanning for injected hooks."),
    "dladdr":              ("ANTI_HOOK",       "medium", "dladdr() -- resolves address to symbol/library, used to detect unexpected modules."),
    "_dyld_image_count":   ("ANTI_HOOK",       "high",   "_dyld_image_count() -- enumerates loaded dylibs to detect injected frameworks."),
    "SecTrustEvaluate":    ("SSL_PINNING",     "high",   "SecTrustEvaluate() -- custom TLS trust evaluation, may implement cert pinning."),
    "MSHookFunction":      ("ANTI_HOOK",       "high",   "MSHookFunction() -- MobileSubstrate/Cydia Substrate hooking API."),
}

# Native string patterns (applied to strings extracted from .so rodata)
NATIVE_STRING_PATTERNS = [p for p in SOURCE_PATTERNS if p["category"] in
                          ("ROOT_DETECTION", "ANTI_HOOK", "ANTI_DEBUG", "EMULATOR_DETECT",
                           "SSL_PINNING", "RASP_DETECTION", "JAILBREAK_DETECT")]

# -----------------------------------------------------------------------
# Dart / Flutter patterns -- applied to Blutter output (asm/*.txt, objs.txt,
# pp.txt: resolved Dart assembly + dumped object-pool / string-pool text).
# Flutter apps ship all app logic compiled into libapp.so, invisible to the
# jadx/apktool Java/Smali scan above -- these patterns catch the Dart-level
# equivalents of the same security mechanisms. See flutter_scanner.py.
# -----------------------------------------------------------------------
DART_FLUTTER_PATTERNS = [
    dict(name="flutter_jailbreak_detection_pkg", category="ROOT_DETECTION",
         regex=_c(r"flutter_jailbreak_detection|JailbreakRootDetection"),
         description="`flutter_jailbreak_detection` plugin: cross-platform root/jailbreak check.",
         confidence="high"),
    dict(name="safe_device_pkg", category="ROOT_DETECTION",
         regex=_c(r"safe_device|SafeDevice\.(isJailBroken|isRealDevice|isRooted)"),
         description="`safe_device` Flutter plugin: root/jailbreak + real-device check.",
         confidence="high"),
    dict(name="flutter_root_checker", category="ROOT_DETECTION",
         regex=_c(r"flutter_root_checker|RootChecker|find_root|FindRoot\b"),
         description="Flutter root-checker plugin binding (e.g. `find_root`, `flutter_root_checker`).",
         confidence="medium"),
    dict(name="dart_generic_jailbreak_call", category="ROOT_DETECTION",
         regex=_c(r"isJailBroken|isJailbroken|isRooted\b|IsDeviceRooted"),
         description="Dart-level jailbreak/root query call surfaced in the object/string pool.",
         confidence="medium"),
    dict(name="flutter_ssl_pinning_plugin", category="SSL_PINNING",
         regex=_c(r"ssl_pinning_plugin|SslPinningPlugin|http_certificate_pinning|HttpCertificatePinning"),
         description="Flutter SSL-pinning plugin (`ssl_pinning_plugin` / `http_certificate_pinning`).",
         confidence="high"),
    dict(name="dio_certificate_pinning", category="SSL_PINNING",
         regex=_c(r"dio_certificate_pinning|badCertificateCallback|SecurityContext\.\(pem"),
         description="Dio/dart:io certificate pinning: `badCertificateCallback` or `dio_certificate_pinning` plugin.",
         confidence="medium"),
    dict(name="flutter_talsec_freerasp", category="RASP_DETECTION",
         regex=_c(r"TalsecConfig|FreeRaspConfig|talsec_flutter|ThreatIdentifier|TalsecApplication"),
         description="Talsec freeRASP Flutter binding: full anti-tamper/RASP suite.",
         confidence="high"),
    dict(name="flutter_approov", category="RASP_DETECTION",
         regex=_c(r"approov_service_flutter|ApproovService\b"),
         description="Approov Flutter plugin: runtime attestation / pinning-as-a-service.",
         confidence="high"),
    dict(name="flutter_rootbeer_binding", category="ROOT_DETECTION",
         regex=_c(r"flutter_rootbeer|RootBeerFlutter"),
         description="RootBeer exposed to Dart via a Flutter platform-channel binding.",
         confidence="high"),
    dict(name="dart_debug_mode_const", category="ANTI_DEBUG",
         regex=_c(r"\bkDebugMode\b|\bkReleaseMode\b|\bkProfileMode\b"),
         description="Dart `foundation.dart` build-mode constants, often gating anti-debug/RASP logic.",
         confidence="low"),
    dict(name="dart_vm_service_check", category="ANTI_DEBUG",
         regex=_c(r"VM_SERVICE_PORT|--disable-service-auth-codes|Observatory listening"),
         description="Dart VM service / Observatory port reference -- can be used to detect an attached debugger.",
         confidence="medium"),
    dict(name="dart_isPhysicalDevice", category="EMULATOR_DETECT",
         regex=_c(r"isPhysicalDevice"),
         description="`device_info_plus` isPhysicalDevice query -- common Flutter emulator check.",
         confidence="medium"),
    dict(name="frida_gadget_string_dart", category="ANTI_HOOK",
         regex=_c(r"frida-gadget|gum-js-loop|LIBFRIDA|frida:rpc|FRIDA_"),
         description="Frida gadget/agent indicator string embedded in the Dart snapshot's object pool.",
         confidence="high"),
]
