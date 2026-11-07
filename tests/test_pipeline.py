"""Alias test runner so both `pytest tests/test_analyzer.py` and `unittest tests/test_pipeline.py` run all 7 gates."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT_DIR))

from tests.test_analyzer import TestCultive8AnalyzerGates  # noqa: E402, F401

if __name__ == "__main__":
    unittest.main()
