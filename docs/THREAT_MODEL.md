# MrNothing Shield — Threat Model

## Overview

This document outlines the threat model that MrNothing Shield is designed to address. We focus on **surveillance malware** (spyware/stalkerware) that targets Android devices.

## Threat Actors

### 1. Stalkerware Operators
- **Motivation**: Intimate partner surveillance, harassment
- **Capabilities**: Purchase commercial stalkerware, physical device access
- **Tools**: mSpy, FlexiSPY, Spyera, TheTruthSpy, etc.

### 2. State Surveillance
- **Motivation**: Intelligence gathering, dissident monitoring
- **Capabilities**: Advanced persistent threats, zero-day exploits
- **Tools**: Pegasus, Hermit, Predator, etc.

### 3. Corporate Espionage
- **Motivation**: Intellectual property theft, competitive intelligence
- **Capabilities**: Custom malware, insider threats
- **Tools**: Custom-developed spyware, off-the-shelf RATs

### 4. Criminal Organizations
- **Motivation**: Financial fraud, identity theft
- **Capabilities**: Banking trojans, SMS interceptors
- **Tools**: Anubis, EventBot, Teabot, etc.

## Attack Vectors

### Installation Methods

| Vector | Description | Detection Difficulty |
|--------|-------------|---------------------|
| **App Store** | Disguised as legitimate app | Medium |
| **Sideloading** | Direct APK installation | Easy (if monitored) |
| **Drive-by Download** | Auto-download from malicious site | Medium |
| **Physical Access** | Attacker installs directly | Hard (post-install) |
| **Exploit** | Zero-day or known vulnerability | Very Hard |
| **Supply Chain** | Compromised legitimate app | Very Hard |

### Persistence Mechanisms

1. **Device Admin Abuse**: Registers as device admin to prevent uninstallation
2. **Accessibility Service**: Uses Android accessibility APIs to monitor all screen content
3. **System App Masquerade**: Names itself to appear as system software
4. **Rootkit**: Gains root access to hide from userspace detection
5. **Boot Persistence**: Registers for BOOT_COMPLETED to restart after reboot

### Data Exfiltration Channels

1. **HTTPS POST**: Standard web requests to C2 server
2. **Email**: SMTP direct to attacker's inbox
3. **SMS**: Text messages to premium numbers or attacker phone
4. **Cloud Storage**: Uploads to attacker-controlled cloud accounts
5. **DNS Tunneling**: Exfiltrates via DNS queries

## Detection Coverage Matrix

| Threat | Permission Auditor | Hidden App Detector | Network Analyzer | Root Detector |
|--------|-------------------|---------------------|------------------|---------------|
| Commercial stalkerware | High | High | Medium | N/A |
| State-level spyware | Medium | Low | High | High |
| Banking trojans | High | Medium | High | N/A |
| Rootkit-based surveillance | N/A | N/A | Medium | Critical |
| Accessibility abusers | Critical | N/A | N/A | N/A |

## Limitations

### What Shield Cannot Detect

1. **Hardware-level implants**: Requires physical inspection
2. **Zero-day kernel exploits**: May not leave detectable traces
3. **Baseband compromises**: Below Android OS level
4. **Network-level interception**: Requires network-side detection
5. **Social engineering**: User behavior cannot be fully audited

### Evasion Techniques Used by Advanced Spyware

1. **Signature Randomization**: Changes package name on each install
2. **Encrypted Payloads**: Downloads malicious code after installation
3. **Root Hiding**: Uses Magisk Hide or similar to evade root detection
4. **C2 Rotation**: Changes command servers frequently
5. **Timing Evasion**: Only activates during specific hours

## Counter-Countermeasures

Shield implements the following to detect evasion:

- **Behavioral analysis** over time (planned)
- **Heuristic permission scoring** beyond signature matching
- **Network baseline deviation** detection
- **Cross-module correlation** to catch subtle indicators
- **Forensic evidence preservation** for manual analysis

## Responsible Use

MrNothing Shield is designed for:
- **Victims** checking their devices for stalkerware
- **Security researchers** analyzing surveillance malware
- **Enterprise IT** auditing corporate devices
- **Law enforcement** with proper authorization
- **Digital forensics professionals**

Shield is **NOT** for:
- Testing surveillance software effectiveness
- Bypassing security for malicious purposes
- Any use without device owner's explicit consent

---

*Threat Model v1.0 — MrNothing Shield — Voltex Network*
