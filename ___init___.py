"""
SQLi Automation Tool
====================

An advanced SQL Injection automation tool for authorized penetration testing.

Modules:
    - core.requester: HTTP client with timing and size measurement
    - core.utils: Helper functions (cookie parsing, size comparison)
    - modules.basic_scanner: Phase 1 — Header injection scanner
    - modules.boolean_blind: Phase 2 — Boolean-based blind SQLi
    - modules.time_blind: Phase 3 — Time-based blind SQLi
    - tampers.encoders: WAF bypass encoding functions
"""

__version__ = "1.0.0"
__author__ = "cyberwhiteelephant"
__license__ = "MIT"