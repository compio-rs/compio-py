# SPDX-License-Identifier: Apache-2.0 OR MulanPSL-2.0
# Copyright 2025 Fantix King

import os
import subprocess
import sys
import unittest


class TestCQA(unittest.TestCase):
    """Code Quality Assurance tests"""

    def test_mypy(self) -> None:
        """Run mypy type checking on the codebase"""
        result = subprocess.run(
            [sys.executable, "-m", "mypy", "src/compio/_core.pyi"],
            env={**os.environ, "FORCE_COLOR": "1"},
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            self.fail("mypy type checking failed:\n" + result.stdout.strip())

    def test_ruff(self) -> None:
        """Run ruff linter on the codebase"""
        result = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "src", "tests"],
            env={**os.environ, "FORCE_COLOR": "1"},
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            self.fail("ruff linting failed:\n" + result.stdout.strip())
