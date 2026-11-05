"""The package metadata must describe what the repo actually contains.

tiny-audit shipped a `package.json` - an npm manifest - for a single-file
Python library. Nothing read it, so nothing failed, and it declared the name
`tiny-audit` on a registry this project never publishes to. It also declared
`Requires-Python: >=3.8` while using `@dataclass(slots=True)`, which is 3.10+,
so the module could not be imported on its declared floor.
"""

import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _pyproject_version() -> str:
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', _read("pyproject.toml"))
    assert match, "pyproject.toml has no version field"
    return match.group(1)


class TestPackaging(unittest.TestCase):
    def test_has_pyproject(self) -> None:
        self.assertTrue((ROOT / "pyproject.toml").exists())

    def test_has_no_npm_manifest(self) -> None:
        # A package.json in a Python-only repo is not metadata; it is a claim
        # of ownership on a name we do not control.
        self.assertFalse(
            (ROOT / "package.json").exists(),
            "a Python library must not ship an npm manifest",
        )

    def test_version_matches_module(self) -> None:
        import tiny_audit

        self.assertEqual(_pyproject_version(), tiny_audit.__version__)

    def test_version_is_semver(self) -> None:
        self.assertRegex(_pyproject_version(), r"^\d+\.\d+\.\d+$")

    def test_requires_python_matches_this_interpreter_floor(self) -> None:
        match = re.search(r'(?m)^requires-python\s*=\s*">=(\d+)\.(\d+)"', _read("pyproject.toml"))
        self.assertIsNotNone(match, "pyproject.toml has no requires-python floor")
        floor = (int(match.group(1)), int(match.group(2)))
        # The floor must be exercised by CI, not merely declared. Read the
        # workflow so a floor raised without a matrix change fails here.
        workflow = _read(".github/workflows/ci.yml")
        versions = re.search(r'python-version:\s*\[([^\]]+)\]', workflow).group(1)
        matrix = {v.strip().strip('"\'') for v in versions.split(",")}
        self.assertIn(
            "%d.%d" % floor,
            matrix,
            "declared floor %d.%d is not in the CI matrix %s" % (floor[0], floor[1], sorted(matrix)),
        )


if __name__ == "__main__":
    unittest.main()
