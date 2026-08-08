"""Minimal setuptools shim so ``pip install -e .`` works.

All package metadata lives in ``pyproject.toml`` (PEP 621); this file
only exists for legacy tooling compatibility.
"""

from setuptools import setup

setup()
