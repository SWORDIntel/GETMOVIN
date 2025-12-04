#!/usr/bin/env python3
"""
Setup script for Windows Lateral Movement Simulation TUI
"""

from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="windows-lateral-movement-tui",
    version="1.0.0",
    author="Security Research Team",
    description="Windows Lateral Movement Simulation TUI - Red Team / Threat Modeling Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/windows-lateral-movement-tui",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: Microsoft :: Windows",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "lateral-movement-tui=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
