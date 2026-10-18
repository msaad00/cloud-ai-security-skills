"""Per-detector precision/recall scorer for the detection corpus.

Loads ``corpus.yaml``, runs each registered detector against its labelled
input fixture, and computes per-detector and aggregate TP / FP / FN /
precision / recall / F1. Intended to be invoked locally and by the
``detector-scoring`` GitHub Actions job on every PR that touches
``skills/detection/``.

Two scoring modes are supported, declared per corpus entry:

* ``event_uid`` — labels map input event ``metadata.uid`` -> bool. The
  scorer extracts the set of input event uids referenced by the
  detector's findings via ``finding_event_uid_path`` (default
  ``evidence.raw_event_uids``) and treats every label key as the
  universe. Any uid the detector references that is in the labelled
  universe but labelled false is counted as a false positive. Unlabelled
  predictions are excluded from metrics and reported separately.

* ``finding_uid`` — labels map *finding* ``metadata.uid`` -> bool. The
  scorer compares the set of emitted finding uids against the labels.

The corpus contract is intentionally narrow so the scorer stays honest:
it does not score finding *content*, only whether the right set of
events / findings was produced. Labels must be actual booleans; every
emitted finding must carry a usable ID for its scoring mode. Invalid
output fails the detector score instead of silently dropping findings.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

try:
    import yaml
except ImportError as exc:  # pragma: no cover - dev dependency
    sys.stderr.write(
        "score.py requires PyYAML. Install via `uv sync --group dev` or `pip install pyyaml`.\n"
    )
    raise SystemExit(2) from exc

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CORPUS = Path(__file__).resolve().parent / "corpus.yaml"

SUPPORTED_MODES = ("event_uid", "finding_uid")


@dataclass
class CorpusEntry:
    """A single labelled corpus row.

    Attributes:
        detector_name: Skill directory name under ``skills/detection/``.
        input_fixture: Path (relative to repo root) of the JSONL input.
        expected_findings_fixture: Optional path of a snapshot of expected
            findings — recorded for traceability, not consumed by the
            scorer.
        labels: Ground-truth mapping (uid -> bool). Interpretation
            depends on ``mode``.
        mode: ``event_uid`` or ``finding_uid``.
        finding_event_uid_path: Dotted path inside each finding that
            yields the list of input event uids the finding "covers".
            Only used when ``mode == 'event_uid'``.
        synthetic: True if the input fixture is synthetic (no production
            telemetry was captured). The honesty rule from
            ``golden/README.md`` requires this to be True for every
            entry until a captured corpus lands.
        extra_args: Extra CLI args appended to the detector subprocess
            command (e.g. ``["--output-format", "ocsf"]``).
    """

    detector_name: str
    input_fixture: str
    labels: dict[str, bool]
    mode: str = "event_uid"
    expected_findings_fixture: str | None = None
    finding_event_uid_path: str = "evidence.raw_event_uids"
    synthetic: bool = True
    extra_args: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CorpusEntry":
        if not isinstance(raw, Mapping):
            raise ValueError("each corpus entry must be a mapping")
        labels_raw = raw.get("labels")
        if not isinstance(labels_raw, Mapping) or not labels_raw:
            raise ValueError("'labels' must be a nonempty mapping of uid -> bool")
        if any(
            not isinstance(uid, str) or not uid.strip() or type(expected) is not bool
            for uid, expected in labels_raw.items()
        ):
            raise ValueError("'labels' requires nonempty string UIDs and boolean values")
        mode = raw.get("mode", "event_uid")
        if mode not in SUPPORTED_MODES:
            raise ValueError(f"unsupported mode {mode!r} (expected one of {SUPPORTED_MODES})")

        def string_field(name: str, default: str | None = None) -> str:
            value = raw.get(name, default)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"'{name}' must be a nonempty string")
            return value

        detector_name = string_field("detector_name")
        input_fixture = string_field("input_fixture")
        uid_path = string_field("finding_event_uid_path", "evidence.raw_event_uids")
        if any(not segment.strip() for segment in uid_path.split(".")):
            raise ValueError("'finding_event_uid_path' must have nonempty dotted segments")
        expected_fixture = raw.get("expected_findings_fixture")
        if expected_fixture is not None:
            expected_fixture = string_field("expected_findings_fixture")
        synthetic = raw.get("synthetic", True)
        if type(synthetic) is not bool:
            raise ValueError("'synthetic' must be a boolean")
        extra_args = raw.get("extra_args", [])
        if not isinstance(extra_args, list) or any(not isinstance(a, str) for a in extra_args):
            raise ValueError("'extra_args' must be a list of strings")
        return cls(
            detector_name=detector_name,
            input_fixture=input_fixture,
            labels=dict(labels_raw),
            mode=mode,
            expected_findings_fixture=expected_fixture,
            finding_event_uid_path=uid_path,
            synthetic=synthetic,
            extra_args=extra_args,
        )


@dataclass
class DetectorScore:
    detector_name: str
    mode: str
    tp: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float
    note: str | None = None
    error: str | None = None
    unlabelled_predictions: int = 0

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "detector_name": self.detector_name,
            "mode": self.mode,
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "unlabelled_predictions": self.unlabelled_predictions,
        }
        if self.note:
            out["note"] = self.note
        if self.error:
            out["error"] = self.error
        return out


def load_corpus(path: Path) -> list[CorpusEntry]:
    if not path.exists():
        raise FileNotFoundError(f"corpus file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: invalid YAML") from exc
    if not isinstance(data, Mapping):
        raise ValueError(f"{path}: corpus must be a mapping with an 'entries' list")
    entries_raw = data.get("entries")
    if not isinstance(entries_raw, list):
        raise ValueError(f"{path}: top-level 'entries' must be a list")
    return [CorpusEntry.from_dict(entry) for entry in entries_raw]


def detector_script_path(detector_name: str) -> Path:
    return REPO_ROOT / "skills" / "detection" / detector_name / "src" / "detect.py"


def run_detector(entry: CorpusEntry) -> list[dict[str, Any]]:
    """Run the detector subprocess and return parsed findings."""

    script = detector_script_path(entry.detector_name)
    if not script.exists():
        raise FileNotFoundError(
            f"detector entrypoint not found: {script} (detector_name={entry.detector_name!r})"
        )
    fixture = REPO_ROOT / entry.input_fixture
    if not fixture.exists():
        raise FileNotFoundError(f"input fixture not found: {fixture}")
    cmd = [sys.executable, str(script), str(fixture), *entry.extra_args]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"detector {entry.detector_name} exited {proc.returncode}: {proc.stderr.strip()[:500]}"
        )
    findings: list[dict[str, Any]] = []
    for line_no, raw_line in enumerate(proc.stdout.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            finding = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"detector {entry.detector_name} produced non-JSON output "
                f"on line {line_no}: {exc.msg}"
            ) from exc
        if not isinstance(finding, dict):
            raise RuntimeError(
                f"detector {entry.detector_name} must emit a JSON object on line {line_no}"
            )
        findings.append(finding)
    return findings


def _walk_path(obj: Any, path: str) -> Any:
    """Resolve a dotted path inside a JSON object (no list indices)."""

    cursor: Any = obj
    for segment in path.split("."):
        if not segment:
            continue
        if isinstance(cursor, Mapping):
            cursor = cursor.get(segment)
        else:
            return None
    return cursor


def extract_event_uids(findings: Iterable[Mapping[str, Any]], path: str) -> set[str]:
    """Pull the union of event uids referenced by ``path`` across findings."""

    out: set[str] = set()
    for index, finding in enumerate(findings, start=1):
        value = _walk_path(finding, path)
        values = [value] if isinstance(value, str) else value
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(uid, str) or not uid.strip() for uid in values)
        ):
            raise ValueError(f"finding {index}: '{path}' must contain nonempty string UIDs")
        out.update(values)
    return out


def extract_finding_uids(findings: Iterable[Mapping[str, Any]]) -> set[str]:
    out: set[str] = set()
    for index, finding in enumerate(findings, start=1):
        uid = _walk_path(finding, "metadata.uid")
        if not isinstance(uid, str) or not uid.strip():
            raise ValueError(f"finding {index}: 'metadata.uid' must be a nonempty string")
        out.add(uid)
    return out


def score_entry(entry: CorpusEntry) -> DetectorScore:
    truth_positive = {uid for uid, expected in entry.labels.items() if expected}
    truth_universe = set(entry.labels.keys())
    try:
        findings = run_detector(entry)
        if entry.mode == "event_uid":
            predicted = extract_event_uids(findings, entry.finding_event_uid_path)
        else:
            predicted = extract_finding_uids(findings)
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        return DetectorScore(
            detector_name=entry.detector_name,
            mode=entry.mode,
            tp=0,
            fp=0,
            fn=len(truth_positive),
            precision=0.0,
            recall=0.0,
            f1=0.0,
            error=str(exc),
        )

    if entry.mode == "event_uid":
        # Only score within the labelled universe — events that are not
        # labelled at all do not count for or against the detector.
        in_universe_predictions = predicted & truth_universe
        tp = len(in_universe_predictions & truth_positive)
        fp = len(in_universe_predictions - truth_positive)
        fn = len(truth_positive - predicted)
    else:
        tp = len(predicted & truth_positive)
        fp = len(predicted - truth_positive)
        fn = len(truth_positive - predicted)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    note = "synthetic fixture" if entry.synthetic else None
    return DetectorScore(
        detector_name=entry.detector_name,
        mode=entry.mode,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        note=note,
        unlabelled_predictions=len(predicted - truth_universe) if entry.mode == "event_uid" else 0,
    )


def aggregate(scores: list[DetectorScore]) -> dict[str, Any]:
    runnable = [s for s in scores if s.error is None]
    tp = sum(s.tp for s in runnable)
    fp = sum(s.fp for s in runnable)
    fn = sum(s.fn for s in runnable)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {
        "detectors_scored": len(runnable),
        "unlabelled_predictions": sum(s.unlabelled_predictions for s in runnable),
        "detectors_errored": sum(1 for s in scores if s.error is not None),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def changed_detectors(base_ref: str) -> set[str]:
    """Return the set of detector names whose ``src/detect.py`` changed.

    Uses ``git diff --name-only <base>...HEAD``. When ``HEAD`` is not
    available (e.g. shallow checkout), fall back to ``<base>``.
    """

    base = base_ref
    candidates_revs = [f"{base}...HEAD", base]
    file_paths: set[str] = set()
    for rev in candidates_revs:
        proc = subprocess.run(
            ["git", "diff", "--name-only", rev],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            check=False,
        )
        if proc.returncode == 0:
            file_paths = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
            break
    if not file_paths:
        sys.stderr.write(
            f"warning: could not compute changed files vs {base_ref}; scoring all detectors.\n"
        )
        return set()
    detectors: set[str] = set()
    for fp in file_paths:
        parts = fp.split("/")
        if len(parts) >= 4 and parts[0] == "skills" and parts[1] == "detection":
            detectors.add(parts[2])
    return detectors


def filter_entries(
    entries: list[CorpusEntry],
    *,
    detector: str | None,
    changed_only: bool,
    base_ref: str,
) -> list[CorpusEntry]:
    if detector:
        return [e for e in entries if e.detector_name == detector]
    if changed_only:
        changed = changed_detectors(base_ref)
        if not changed:
            return entries  # fall back: score everything
        return [e for e in entries if e.detector_name in changed]
    return entries


def render_markdown(scores: list[DetectorScore], totals: dict[str, Any]) -> str:
    lines = [
        "| Detector | Mode | TP | FP | FN | Precision | Recall | F1 | Unlabelled (excluded) | Note |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for s in scores:
        note = s.note or ""
        if s.error:
            note = f"error: {s.error[:80]}"
        lines.append(
            "| {name} | {mode} | {tp} | {fp} | {fn} | {p:.3f} | {r:.3f} | {f:.3f} | {unlabelled} | {note} |".format(
                name=s.detector_name,
                mode=s.mode,
                tp=s.tp,
                fp=s.fp,
                fn=s.fn,
                p=s.precision,
                r=s.recall,
                f=s.f1,
                note=note,
                unlabelled=s.unlabelled_predictions,
            )
        )
    lines.append(
        "| **aggregate** | — | **{tp}** | **{fp}** | **{fn}** | **{p:.3f}** | **{r:.3f}** | **{f:.3f}** | **{unlabelled}** | {n} scored; {errors} errored |".format(
            tp=totals["tp"],
            fp=totals["fp"],
            fn=totals["fn"],
            p=totals["precision"],
            r=totals["recall"],
            f=totals["f1"],
            n=totals["detectors_scored"],
            unlabelled=totals["unlabelled_predictions"],
            errors=totals["detectors_errored"],
        )
    )
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus",
        default=str(DEFAULT_CORPUS),
        help=f"Path to corpus.yaml (default: {DEFAULT_CORPUS}).",
    )
    parser.add_argument(
        "--detector",
        default=None,
        help="Score only the named detector (e.g. detect-okta-mfa-fatigue).",
    )
    parser.add_argument(
        "--changed-only",
        action="store_true",
        help="Score only detectors whose src/detect.py changed vs --base.",
    )
    parser.add_argument(
        "--base",
        default="origin/main",
        help="Base ref for --changed-only (default: origin/main).",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Append a markdown summary table to stdout after the JSON.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    corpus_path = Path(args.corpus)
    try:
        entries = load_corpus(corpus_path)
    except (FileNotFoundError, ValueError) as exc:
        sys.stderr.write(f"score: failed to load corpus: {exc}\n")
        return 2
    if not entries:
        sys.stdout.write(
            json.dumps({"per_detector": [], "aggregate": aggregate([])}, indent=2) + "\n"
        )
        return 0
    selected = filter_entries(
        entries,
        detector=args.detector,
        changed_only=args.changed_only,
        base_ref=args.base,
    )
    if not selected:
        sys.stderr.write(
            "score: no corpus entries matched the selected filter; nothing to score.\n"
        )
        sys.stdout.write(
            json.dumps({"per_detector": [], "aggregate": aggregate([])}, indent=2) + "\n"
        )
        return 0

    scores = [score_entry(entry) for entry in selected]
    totals = aggregate(scores)
    payload = {
        "per_detector": [s.to_dict() for s in scores],
        "aggregate": totals,
        "command": shlex.join(sys.argv),
        "cwd": os.path.relpath(REPO_ROOT, REPO_ROOT) or ".",
    }
    sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    if args.markdown:
        sys.stdout.write("\n" + render_markdown(scores, totals) + "\n")
    # Non-zero exit if any detector errored, so CI can flag wiring breaks.
    return 1 if any(s.error for s in scores) else 0


if __name__ == "__main__":
    raise SystemExit(main())
