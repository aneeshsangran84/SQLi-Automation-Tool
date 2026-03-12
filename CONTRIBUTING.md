# Contributing to SQLi Automation Tool

Thank you for considering contributing! Here's how you can help.

## 🐛 Reporting Bugs

1. Check existing [Issues](https://github.com/cyberwhiteelephant/sqli-automation-tool/issues)
2. Open a new issue with:
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version and OS

## 🔧 Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `python -m pytest tests/`
5. Commit with clear messages: `git commit -m "Add: new tamper script for base64"`
6. Push: `git push origin feature/my-feature`
7. Open a Pull Request

## 📝 Code Style

- Follow PEP 8
- Add docstrings to all functions
- Include "What's going on" explanations for complex logic
- Keep functions under 50 lines when possible

## 💡 Ideas for Contributions

- New tamper scripts (Base64, Unicode, double encoding)
- Support for additional databases (Oracle, SQLite)
- POST body injection support
- Proxy chain support (Tor, SOCKS5)
- Output formats (JSON, XML report generation)

## ⚠️ Ethical Guidelines

- All contributions must be for **defensive/educational** purposes
- Do not include exploits targeting specific real-world applications
- Do not include hardcoded credentials or sensitive data