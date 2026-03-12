# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-03-12

### Added
- **Phase 1 (Basic):** Header injection scanner with response size comparison
- **Phase 2 (Intermediate):** Boolean-based blind SQLi with character extraction
  - Auto-detection of TRUE/FALSE response indicators
  - Auto-login to DVWA (no manual cookie copying)
  - Support for `extra_params` (Submit=Submit for DVWA)
- **Phase 3 (Super Advanced):** Time-based blind SQLi
  - Dynamic Delay Calculator with statistical baseline analysis
  - Multi-database support (MySQL, PostgreSQL, MSSQL)
  - Retry logic with jitter tolerance
  - Interactive extraction menu with 7 options
  - Full automated extraction pipeline (db → tables → columns → data)
- Tamper scripts for WAF bypass (Hex, URL encoding)
- Cookie and custom header injection support
- DVWA auto-login (no more expired session issues)
- Debug script (`debug_dvwa.py`) for troubleshooting
- Docker Compose setup for DVWA test lab
- Comprehensive documentation and code comments