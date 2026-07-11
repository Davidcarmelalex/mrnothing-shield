# Contributing to MrNothing Shield

Thank you for your interest in improving mobile security. This document provides guidelines for contributing to MrNothing Shield.

## Code of Conduct

This project adheres to a strict code of conduct. By participating, you agree to:
- Use your skills for defensive purposes only
- Respect user privacy and consent
- Follow responsible disclosure for vulnerabilities
- Maintain professional standards in all interactions

## Development Setup

```bash
git clone https://github.com/Davidcarmelalex/mrnothing-shield.git
cd mrnothing-shield
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific module tests
pytest tests/test_permissions.py -v

# Run with coverage
pytest tests/ --cov=shield --cov-report=html
```

## Adding a New Detection Module

1. Create a new file in `shield/core/`
2. Implement the `DetectionModule` interface
3. Add comprehensive tests in `tests/`
4. Update documentation
5. Submit a PR with detailed description

## PR Requirements

- All tests must pass
- New features require tests
- Code must follow PEP 8 style
- Documentation must be updated
- Commit messages must be descriptive

## Areas Needing Contribution

- [ ] Additional spyware signatures
- [ ] iOS support (via libimobiledevice)
- [ ] ML-based behavioral analysis
- [ ] Additional report templates
- [ ] Translation of reports to other languages
- [ ] Performance optimizations for large app sets

## Questions?

Open a Discussion or reach out via the Voltex Network Discord.

---

*Contributions are welcome from security researchers, developers, and privacy advocates worldwide.*
