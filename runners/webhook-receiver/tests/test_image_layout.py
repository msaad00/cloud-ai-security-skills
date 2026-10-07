"""The receiver must boot from the filesystem layout its Dockerfile builds.

`router.py`, `server.py`, and `sinks.py` derive the repo root from their own
path, so the image has to place the receiver source where that arithmetic
lands on the directory holding `skills/` and `mcp-server/src`. This test
rebuilds the runtime-stage layout from the Dockerfile's own COPY and CMD
lines and imports the app from it in a clean interpreter.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = REPO_ROOT / "runners" / "webhook-receiver" / "Dockerfile"


def _runtime_stage(text: str) -> str:
    return text.split("AS runtime", 1)[1]


def _copies(stage: str) -> list[tuple[str, str]]:
    pattern = re.compile(r"^COPY\s+--chown=\S+\s+(\S+)\s+(\S+)\s*$", re.MULTILINE)
    return pattern.findall(stage)


def _app_dir(stage: str) -> str:
    match = re.search(r'"--app-dir",\s*"([^"]+)"', stage)
    assert match, "CMD must pass --app-dir"
    return match.group(1)


def test_receiver_boots_from_dockerfile_layout(tmp_path):
    stage = _runtime_stage(DOCKERFILE.read_text(encoding="utf-8"))
    image_root = tmp_path / "image"
    for src, dest in _copies(stage):
        target = image_root / dest.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        if src == "skills":
            # Large tree and read-only use: a symlink is enough.
            target.symlink_to(REPO_ROOT / src, target_is_directory=True)
        else:
            shutil.copytree(REPO_ROOT / src, target)
    app_dir = image_root / _app_dir(stage).lstrip("/")

    probe = (
        "import json, sys\n"
        f"sys.path.insert(0, {str(app_dir)!r})\n"
        "import server, router\n"
        "res = router.resolve('ingest-cloudtrail-ocsf')\n"
        "print(json.dumps({'root': str(router.REPO_ROOT), 'found': res.found,"
        " 'allowed': res.allowed, 'app': type(server.app).__name__}))\n"
    )
    env = {
        "PATH": os.environ.get("PATH", ""),
        "WEBHOOK_ALLOWED_SKILLS": "ingest-cloudtrail-ocsf",
    }
    # -I: isolated mode, so nothing from the repo checkout leaks onto sys.path.
    proc = subprocess.run(
        [sys.executable, "-I", "-c", probe],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out["root"] == str((image_root / "app").resolve())
    assert out["found"] is True
    assert out["allowed"] is True
    assert out["app"] == "FastAPI"
