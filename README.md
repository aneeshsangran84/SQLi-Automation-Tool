# 🛡️ Advanced SQLi Automation Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ethical Use Only](https://img.shields.io/badge/Use-Ethical%20Only-red.svg)](#legal-disclaimer)

A modular SQL Injection automation tool built in Python for **authorized penetration testing**. Covers basic header injection, boolean-based blind SQLi, and time-based blind SQLi with a dynamic delay calculator.

> ⚠️ **This tool is for authorized security testing and educational purposes ONLY. Unauthorized use is illegal.**

---

## 🎯 Features

### Basic (Phase 1)
- Injects payloads into HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`)
- Response size comparison for SQLi detection
- Multiple payload support with configurable thresholds

### Intermediate (Phase 2) — Boolean-Based Blind SQLi
- Character-by-character data extraction
- Auto-detection of TRUE/FALSE response indicators
- Full schema enumeration: database → tables → columns → data
- Support for MySQL, PostgreSQL, and MSSQL

### Super Advanced (Phase 3) — Time-Based Blind SQLi
- **Dynamic Delay Calculator**: Measures baseline latency, calculates optimal `SLEEP()` time
- Statistical analysis (mean, median, stddev, P95) for accuracy
- Retry logic with jitter tolerance for unstable networks
- Multi-database support: `SLEEP()`, `pg_sleep()`, `WAITFOR DELAY`
- Interactive extraction menu with ETA tracking
- Tamper scripts for WAF bypass (Hex encoding, URL encoding)
- Cookie and custom header injection support

---

## 📋 Requirements

- Python 3.8+
- `requests` library
- `beautifulsoup4` library
- Docker (for the test lab)

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/cyberwhiteelephant/sqli-automation-tool.git
cd sqli-automation-tool

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🧪 Setting Up the Test Lab

This tool is designed to be tested against [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application):

```bash
# Start DVWA using Docker
docker-compose up -d

# Access DVWA at http://localhost:8080
# Login: admin / password
# Click "Create / Reset Database"
# Set DVWA Security to "Low"
```

---

## 💻 Usage

### Phase 1: Basic Header Injection Scanner
```bash
python test_basic.py
```

### Phase 2: Boolean-Based Blind SQLi
```bash
python test_boolean_fixed.py
```

### Phase 3: Time-Based Blind SQLi (Super Advanced)
```bash
python time_blind_sqli.py
```

The time-based tool provides an interactive menu:
```
╔══════════════════════════════════════════════════╗
║             EXTRACTION MENU                      ║
║  1. Extract database name                        ║
║  2. Extract database version                     ║
║  3. Extract current user                         ║
║  4. Extract table names                          ║
║  5. Extract column names (specify table)         ║
║  6. Extract data (specify table + column)        ║
║  7. Full automated extraction                    ║
║  0. Exit                                         ║
╚══════════════════════════════════════════════════╝
```

---

## 🏗️ Project Structure

```
sqli-automation-tool/
├── config.py                  # Central configuration
├── main.py                    # CLI entry point
├── sqli_tool/
│   ├── core/
│   │   ├── requester.py       # HTTP client with timing
│   │   └── utils.py           # Helper functions
│   ├── modules/
│   │   ├── basic_scanner.py   # Phase 1: Header injection
│   │   ├── boolean_blind.py   # Phase 2: Boolean blind SQLi
│   │   └── time_blind.py      # Phase 3: Time-based blind
│   └── tampers/
│       └── encoders.py        # WAF bypass encoders
├── time_blind_sqli.py         # Standalone time-based tool
├── test_basic.py              # Phase 1 test runner
├── test_boolean_fixed.py      # Phase 2 test runner
├── debug_dvwa.py              # DVWA diagnostic tool
└── tests/                     # Unit tests
```

---

## 📖 How It Works

### Dynamic Delay Calculator (Phase 3)
The tool measures server baseline latency using statistical analysis:

1. **Ping** the server 7 times
2. Calculate **mean**, **median**, **standard deviation**, and **P95**
3. Set `sleep_time = max(3, ceil(P95 + 4×stddev + 1))`
4. Set `threshold = median + sleep_time × 0.65`

This ensures the tool adapts to any server speed — from fast local servers to slow remote targets.

---

## ⚖️ Legal Disclaimer

This tool is provided for **educational and authorized penetration testing purposes only**.

- ✅ Use against systems you **own** or have **written permission** to test
- ✅ Use in CTF competitions and lab environments
- ❌ **DO NOT** use against systems without explicit authorization
- ❌ Unauthorized computer access is a **criminal offense**

The author is not responsible for any misuse of this tool.

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📄 License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [DVWA](https://github.com/digininja/DVWA) — for providing a safe testing environment
- [OWASP](https://owasp.org/www-community/attacks/SQL_Injection) — for SQLi documentation
- [sqlmap](https://github.com/sqlmapproject/sqlmap) — inspiration for automation techniques
