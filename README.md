# Divine Departure

<p align="center">
  <img src="divine-departure-logo.png" alt="Divine Departure" width="520">
</p>

<p align="center">
  <b>Mobile Application Security Analysis Tool</b><br>
  Peel • Analyze • Understand • Test
</p>

---

## Requirements

### System
- Python 3.10+
- Linux / macOS / Windows
- Java runtime for JADX

### Python

Install the required Python packages:

```bash
pip install -r requirements.txt
```

If your environment requires it:

```bash
pip install -r requirements.txt --break-system-packages
```

### External Tools

The following tools should be installed and available in your `PATH`:

- **JADX** — Android APK decompilation
- **Apktool** — Android APK/Smali analysis
- **Blutter** — optional, for Flutter analysis

Verify the tools:

```bash
jadx --version
apktool --version
```

For Flutter analysis, ensure Blutter is configured according to its installation requirements.

---

## Usage

### Android APK

```bash
python main.py -a /path/to/app.apk -o ./output
```

### iOS IPA

```bash
python main.py -a /path/to/app.ipa -o ./output
```

### Generate Security Model and Frida Prompt

```bash
python main.py -a /path/to/app.apk -o ./output --frida-brief
```

This generates:

```text
security_model.json
frida_prompt.md
```

These outputs provide structured findings and focused context to assist with Frida script development and dynamic testing.

### Flutter Application

```bash
python main.py -a /path/to/app.apk -o ./output --blutter
```

---

## Common Options

| Option | Description |
|---|---|
| `-a, --apk` | Input APK or IPA |
| `-o, --output` | Output directory |
| `--frida-brief` | Generate security model and Frida prompt |
| `--blutter` | Enable Flutter analysis |
| `--skip-java` | Skip Java/Kotlin/Smali analysis |
| `--skip-native` | Skip native binary analysis |
| `--no-banner` | Disable banner |
| `--no-progress` | Disable progress output |

---

## Output

Typical output files include:

```text
output/
├── report.html
├── security_model.json
└── frida_prompt.md
```

Additional analysis directories may be created depending on the input application and enabled options.

---

## Project Status

🚧 **Active Development**

Some features, including APK patching/rebuilding, are experimental and under development.

---

## Responsible Use

Use Divine Departure only for applications and environments where you have explicit authorization to perform security testing.
