"""Check captured-fixture declarations and byte integrity, not authenticity.

An explicit empty manifest is valid and reports zero captured evidence.
Nonempty manifests require reviewed recorded-telemetry origins, capture windows,
permissive license declarations, detector names, and local fixture SHA-256 pins.
The offline validator cannot authenticate upstream sources or prove execution.
"""

from __future__ import annotations

import hashlib
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

ROOT = Path(__file__).resolve().parent.parent
CAPTURED_DIR = ROOT / "skills" / "detection-engineering" / "captured"
DETECTOR_DIR = ROOT / "skills" / "detection"
MANIFEST_PATH = CAPTURED_DIR / "MANIFEST.yaml"
NON_FIXTURE_FILES = frozenset({"README.md", "MANIFEST.yaml"})

ALLOWED_LICENSES = frozenset(
    {
        "Apache-2.0",
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "CC0-1.0",
        "CC-BY-4.0",
    }
)

REQUIRED_KEYS = (
    "path",
    "origin",
    "license",
    "capture_window_utc",
    "attack_pattern",
    "consuming_detector",
    "synthetic_seeded",
    "sha256",
)


def _load_manifest() -> list[Any]:
    if MANIFEST_PATH.is_symlink():
        raise ValueError("manifest must not be a symlink")
    data = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("captured/MANIFEST.yaml must be a mapping")
    fixtures = data.get("fixtures")
    if not isinstance(fixtures, list):
        raise ValueError("captured/MANIFEST.yaml must contain an explicit fixtures list")
    return fixtures


def _valid_window(value: str) -> bool:
    try:
        start, end = (datetime.fromisoformat(part) for part in value.split("/"))
        return (
            start.utcoffset() == timedelta(0) and end.utcoffset() == timedelta(0) and start <= end
        )
    except ValueError:
        return False


def _valid_origin(value: str) -> bool:
    if any(char.isspace() for char in value):
        return False
    try:
        url = urlsplit(value)
        return (
            url.scheme in {"https", "http"}
            and bool(url.hostname)
            and not url.username
            and not url.password
        )
    except ValueError:
        return False


def _validate_entry(entry: dict[str, Any]) -> list[str]:
    violations: list[str] = []
    for key in REQUIRED_KEYS:
        value = entry.get(key)
        if key == "synthetic_seeded":
            if value is not False:
                violations.append(
                    "synthetic_seeded must be explicitly false; synthetic fixtures belong in golden/"
                )
        elif not isinstance(value, str) or not value.strip():
            violations.append(f"{key} must be a nonempty string")
    if violations:
        return violations

    path = entry["path"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.ocsf\.jsonl", path):
        violations.append("path must name one local .ocsf.jsonl file without directories")
    else:
        fixture = CAPTURED_DIR / path
        if fixture.is_symlink() or not fixture.is_file():
            violations.append(f"{path}: fixture must be a regular local file")
        elif re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            with fixture.open("rb") as handle:
                digest = hashlib.file_digest(handle, "sha256").hexdigest()
            if digest != entry["sha256"]:
                violations.append(f"{path}: sha256 does not match fixture bytes")
    if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
        violations.append("sha256 must be a lowercase SHA-256 digest of the local fixture")
    if entry["license"] not in ALLOWED_LICENSES:
        violations.append("license must be in the permissive allowlist")
    if not _valid_origin(entry["origin"]):
        violations.append(
            "origin must be an http(s) URL without credentials to the reviewed telemetry artifact"
        )
    if not _valid_window(entry["capture_window_utc"]):
        violations.append("capture_window_utc must be an ordered start/end range of UTC timestamps")
    detector = entry["consuming_detector"]
    if (
        not re.fullmatch(r"detect-[a-z0-9-]+", detector)
        or not (DETECTOR_DIR / detector / "SKILL.md").is_file()
    ):
        violations.append("consuming_detector must name an existing detector skill")
    return violations


def main() -> int:
    try:
        entries = _load_manifest()
        violations: list[str] = []
        declared: set[str] = set()
        for index, entry in enumerate(entries, start=1):
            if not isinstance(entry, dict):
                violations.append(f"entry {index}: must be a mapping")
                continue
            path = entry.get("path")
            if isinstance(path, str):
                if path in declared:
                    violations.append(f"entry {index}: duplicate fixture path")
                declared.add(path)
            violations.extend(f"entry {index}: {v}" for v in _validate_entry(entry))

        present: set[str] = set()
        for item in CAPTURED_DIR.iterdir():
            if item.is_symlink():
                violations.append(f"{item.name}: symlinks are not allowed")
            elif item.is_dir():
                violations.append(f"{item.name}: subdirectories are not allowed")
            elif item.name not in NON_FIXTURE_FILES:
                present.add(item.name)
        for name in sorted(present - declared):
            violations.append(f"{name}: file is not declared in MANIFEST.yaml")
        for name in sorted(declared - present):
            violations.append(f"{name}: declared file is missing")
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(
            f"ERROR: unable to validate captured manifest ({type(exc).__name__})", file=sys.stderr
        )
        return 1

    if violations:
        print(
            "Captured-fixture declaration violations:\n  - " + "\n  - ".join(violations),
            file=sys.stderr,
        )
        return 1
    if not present:
        print("OK: explicit empty corpus; no captured-traffic evidence is shipped.")
    else:
        print(
            f"OK: {len(present)} captured fixture declaration(s) and byte hashes validated; source authenticity requires review."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
