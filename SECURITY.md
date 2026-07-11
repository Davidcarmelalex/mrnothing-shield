# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

MrNothing Shield is a security tool, and we take its security seriously.

### Responsible Disclosure

1. **Do NOT** open a public issue for security vulnerabilities
2. Email security disclosures to: `security@voltex.network`
3. Include detailed reproduction steps and impact assessment
4. Allow 90 days for remediation before public disclosure
5. We will acknowledge receipt within 48 hours

### What to Report

- Vulnerabilities in the Shield framework itself
- Bypass techniques that allow malware to evade detection
- False negatives (undetected spyware)
- Privacy issues in data handling

### What NOT to Report

- Spyware development assistance (we build defenses, not weapons)
- Vulnerabilities in third-party dependencies (report to upstream)
- General security questions (use Discussions instead)

## Security Features

### Audit Integrity

All audit reports include SHA-256 evidence hashes and are cryptographically signed to prevent tampering.

### Privacy Protection

- All scans run locally on the device
- No telemetry or data collection
- No network connections except for IOC database updates (optional)
- Audit reports are stored with restrictive permissions

### Secure Defaults

- ADB connections require explicit authorization
- Root-required modules are opt-in
- Reports exclude sensitive data (passwords, tokens)
- Automatic cleanup of temporary forensic files

## Bug Bounty

We participate in the VOID//Bounty program. Security researchers who report valid vulnerabilities may be eligible for rewards.

→ [github.com/Davidcarmelalex/void-bounty](https://github.com/Davidcarmelalex/void-bounty)
