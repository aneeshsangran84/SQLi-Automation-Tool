"""
setup.py - Backward-compatible installer

What's going on:
    While pyproject.toml is the modern standard, some older tools
    and environments still look for setup.py. This file provides
    backward compatibility by reading from pyproject.toml.

    For most users: pip install -r requirements.txt is sufficient.
    This is only needed if someone wants to install the tool as
    a package: pip install .
"""

from setuptools import setup, find_packages

setup(
    name="sqli-automation-tool",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "urllib3>=1.26.0",
    ],
    python_requires=">=3.8",
    author="cyberwhiteelephant",
    description="Advanced SQL Injection automation tool for authorized penetration testing",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    license="MIT",
    entry_points={
        "console_scripts": [
            "sqli-tool=main:main",
        ],
    },
)