<div align="center">

<img src="https://capsule-render.vercel.app/api?type=shield&color=0f0f0f&height=200&section=header&text=MRNOTHING%20SHIELD&fontSize=55&fontColor=ff3333&animation=fadeIn&fontAlignY=38&desc=Mobile%20Security%20Audit%20Framework%20%E2%80%94%20Detect%20Spyware%2C%20Hidden%20Apps%2C%20Malicious%20Permissions&descAlignY=58&descSize=16&descColor=ffffff" width="100%"/>

<br/>

<img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&size=16&duration=3000&pause=1000&color=ff3333&center=true&vAlign=true&width=900&lines=Spyware+detection+%7C+Hidden+app+scanner+%7C+Permission+auditor;Network+traffic+analyzer+%7C+Root+detection+%7C+Security+report+generation;Protecting+devices+from+unauthorized+surveillance+since+2026" />

<br/><br/>

[![Version](https://img.shields.io/badge/Version-1.0.0-ff3333?style=for-the-badge&logo=semver&logoColor=white)](https://github.com/Davidcarmelalex/mrnothing-shield/releases)
[![License](https://img.shields.io/badge/License-MIT-0f0f0f?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Android](https://img.shields.io/badge/Android-Termux-3ddc84?style=for-the-badge&logo=android&logoColor=white)](https://termux.dev)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-00ff88?style=for-the-badge&logo=checkmarx&logoColor=white)]()

<br/>

<a href="https://github.com/Davidcarmelalex/mrnothing-shield/stargazers"><img src="https://img.shields.io/github/stars/Davidcarmelalex/mrnothing-shield?style=flat-square&color=ff3333" /></a>
<a href="https://github.com/Davidcarmelalex/mrnothing-shield/network/members"><img src="https://img.shields.io/github/forks/Davidcarmelalex/mrnothing-shield?style=flat-square&color=ff3333" /></a>
<a href="https://github.com/Davidcarmelalex/mrnothing-shield/issues"><img src="https://img.shields.io/github/issues/Davidcarmelalex/mrnothing-shield?style=flat-square&color=ff3333" /></a>

</div>

---

## What is MrNothing Shield?

**MrNothing Shield** is a comprehensive mobile security audit framework designed to detect and neutralize spyware, stalkerware, and surveillance malware on Android devices. It performs deep forensic analysis of installed applications, network traffic, system configurations, and permission structures to identify threats that evade traditional antivirus solutions.

> **This is a defensive security tool.** It protects users from unauthorized surveillance — the exact opposite of spyware.

### The Threat Landscape

| Threat Vector | How Shield Detects It | Severity |
|---------------|----------------------|----------|
| **Spyware with camera/mic access** | Flags apps requesting `CAMERA` + `RECORD_AUDIO` + `INTERNET` without legitimate UI | Critical |
| **Hidden apps (no launcher icon)** | Cross-references installed packages against launcher entries | Critical |
| **Background location tracking** | Identifies apps with `ACCESS_FINE_LOCATION` + background execution privileges | High |
| **Suspicious network exfiltration** | Monitors outbound connections to unknown endpoints during off-hours | High |
| **Root-enabled surveillance** | Detects root access indicators that enable deep system compromise | High |
| **Permission abuse patterns** | Scores apps using heuristic permission combination analysis | Medium |
| **System file masquerading** | Identifies apps disguised as system updates or security patches | Critical |

---

## Architecture

```
                    +-------------------------------+
                    |     MRNOTHING SHIELD v1.0     |
                    |     Security Audit Engine      |
                    +---------------+---------------+
                                    |
            +-----------------------+-----------------------+
            |                       |                       |
    +-------v-------+     +---------v---------+   +--------v--------+
    |  App Scanner  |     |  Permission Audit |   | Network Monitor |
    |               |     |                   |   |                 |
    | - Package     |     | - Dangerous combo |   | - Traffic       |
    |   analysis    |     |   detection       |   |   analysis      |
    | - Hidden app  |     | - Heuristic       |   | - Suspicious    |
    |   detection   |     |   scoring         |   |   endpoints     |
    | - System file |     | - Permission      |   | - Exfiltration  |
    |   masquerade  |     |   mapping         |   |   patterns      |
    +-------+-------+     +---------+---------+   +--------+--------+
            |                       |                       |
            +-----------------------+-----------------------+
                                    |
                    +---------------v---------------+
                    |     Threat Intelligence       |
                    |     Correlation Engine         |
                    |                               |
                    | - Cross-vector threat linking |
                    | - Risk scoring & prioritization|
                    | - Evidence collection          |
                    +---------------+---------------+
                                    |
                    +---------------v---------------+
                    |      Report Generator         |
                    |                               |
                    | - JSON / PDF / HTML reports   |
                    | - Remediation guidance        |
                    | - Forensic evidence export    |
                    +-------------------------------+
```

---

## Detection Modules

### 1. Permission Auditor (`shield.core.permissions`)

Analyzes all installed apps for dangerous permission combinations using heuristic scoring.

**Flagged Permission Combinations:**
```python
CRITICAL_COMBOS = [
    ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "INTERNET"],
    ["CAMERA", "RECORD_AUDIO", "INTERNET"],
    ["READ_SMS", "SEND_SMS", "INTERNET"],
    ["READ_CONTACTS", "RECORD_AUDIO", "INTERNET"],
    ["ACCESS_FINE_LOCATION", "RECORD_AUDIO", "INTERNET"],
]
```

| Score | Classification | Action |
|-------|---------------|--------|
| 0.0-0.3 | **Low Risk** | Log only |
| 0.3-0.7 | **Medium Risk** | Flag for review |
| 0.7-1.0 | **High Risk** | Immediate alert + quarantine recommendation |

### 2. Hidden App Detector (`shield.core.hidden_apps`)

Identifies applications installed on the device that do not appear in the launcher — a common spyware technique.

**Detection Methods:**
- Cross-reference `PackageManager` installed packages against `LauncherActivityInfo`
- Flag apps with `android.intent.category.LAUNCHER` missing from `MAIN` intent
- Detect apps using alias components to hide primary activity
- Identify system-signed apps with non-standard package names

### 3. Network Traffic Analyzer (`shield.core.network`)

Monitors outbound network connections to detect data exfiltration patterns.

**Analysis Capabilities:**
- Baseline normal traffic patterns per app
- Detect connections to known malicious IP ranges
- Flag large data transfers during device idle periods
- Identify DNS queries to suspicious domains
- Track TLS certificate anomalies

### 4. Root & Compromise Detector (`shield.core.root_detect`)

Determines if the device has been rooted or compromised, which enables deep surveillance.

**Checks Performed:**
- `su` binary presence in standard paths (`/system/bin`, `/system/xbin`)
- `Superuser.apk` or Magisk installation
- `ro.debuggable` and `ro.secure` property inspection
- Test keys vs. release keys verification
- SafetyNet / Play Integrity API status
- Custom recovery image detection

### 5. Security Report Generator (`shield.core.report`)

Produces comprehensive, court-admissible security audit reports.

**Report Formats:**
- **JSON** — Machine-readable for SIEM integration
- **PDF** — Human-readable with forensic timestamps
- **HTML** — Interactive dashboard with severity charts

---

## Quick Start

### Prerequisites

- Python 3.11+
- Android device with Termux (for on-device scanning)
- ADB access (for remote device scanning from desktop)

### Installation

```bash
# Clone the repository
git clone https://github.com/Davidcarmelalex/mrnothing-shield.git
cd mrnothing-shield

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running a Security Audit

```bash
# Full device audit (requires ADB)
python -m shield audit --device <device_id> --output report.html

# Permission scan only
python -m shield audit --module permissions --output permissions.json

# Hidden app detection
python -m shield audit --module hidden_apps --verbose

# Network traffic analysis (requires root on device)
python -m shield audit --module network --duration 300 --output network_report.pdf
```

### Programmatic Usage

```python
from shield.core.auditor import SecurityAuditor
from shield.core.report import ReportGenerator

# Initialize auditor
auditor = SecurityAuditor(device_id="emulator-5554")

# Run full audit
results = auditor.run_full_audit()

# Generate report
generator = ReportGenerator(results)
generator.to_pdf("security_audit_2026.pdf")
generator.to_html("security_audit_2026.html")

# Check specific threats
if results.has_spyware_indicators:
    print("CRITICAL: Spyware indicators detected!")
    for threat in results.critical_threats:
        print(f"  - {threat.name}: {threat.description}")
```

---

## Project Structure

```
mrnothing-shield/
├── shield/                     # Core framework
│   ├── __init__.py
│   ├── core/                   # Detection modules
│   │   ├── __init__.py
│   │   ├── auditor.py          # Main audit orchestrator
│   │   ├── permissions.py      # Permission combination analyzer
│   │   ├── hidden_apps.py      # Hidden application detector
│   │   ├── network.py          # Network traffic analyzer
│   │   ├── root_detect.py      # Root/compromise detector
│   │   └── report.py           # Report generator (JSON/PDF/HTML)
│   ├── android/                # Android-specific tooling
│   │   ├── __init__.py
│   │   ├── app_scanner.py      # Package analysis via ADB
│   │   └── device_info.py      # Device fingerprinting
│   ├── threat_db/              # Threat intelligence
│   │   ├── __init__.py
│   │   ├── signatures.py       # Known spyware signatures
│   │   └── ioc.py             # Indicators of compromise
│   └── utils/
│       ├── __init__.py
│       ├── logger.py           # Structured logging
│       └── validators.py       # Input validation
├── tests/                      # Test suite
│   ├── test_permissions.py
│   ├── test_hidden_apps.py
│   ├── test_network.py
│   └── test_root_detect.py
├── docs/
│   ├── ARCHITECTURE.md         # System architecture
│   ├── THREAT_MODEL.md         # Threat model documentation
│   └── API.md                  # API reference
├── .github/
│   ├── ISSUE_TEMPLATE/
│   └── PULL_REQUEST_TEMPLATE.md
├── requirements.txt
├── setup.py
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
└── README.md
```

---

## Ecosystem

MrNothing Shield is part of the **MrNothing Security Stack**:

```
MrNothing Security
├── MrNothing Shield (this repo)    # Mobile security audit
├── VOID//Bounty                    # Agentic bug bounty platform
├── AZRAEL                          # Autonomous cyber defense
├── hermeslock                      # Zero-trust messaging
└── MrNothing OS                    # Secure AI agent OS
```

Part of the broader **Voltex Network** ecosystem.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code standards, and the PR process.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. We follow responsible disclosure practices.

## License

[MIT License](LICENSE) — Copyright 2026 David Carmel Alex / Voltex Network

---

<div align="center">

**Protect what matters.**

[github.com/Davidcarmelalex/mrnothing-shield](https://github.com/Davidcarmelalex/mrnothing-shield)

</div>

<img src="https://capsule-render.vercel.app/api?type=waving&color=0f0f0f&height=100&section=footer" width="100%"/>
