from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
IMAGES = ROOT / "docs" / "images"
SVGS = sorted(p for p in IMAGES.glob("*.svg"))
SVG_NS = "{http://www.w3.org/2000/svg}"


def test_images_dir_has_svgs():
    assert SVGS, "expected source SVGs under docs/images/"


@pytest.mark.parametrize("svg", SVGS, ids=lambda p: p.name)
def test_svg_is_strict_utf8(svg: Path):
    data = svg.read_bytes()
    data.decode("utf-8")
    bad = [b for b in data if b < 0x20 and b not in (0x09, 0x0A, 0x0D)]
    assert not bad, f"{svg.name} contains C0 control bytes {sorted(set(bad))}"


@pytest.mark.parametrize("svg", SVGS, ids=lambda p: p.name)
def test_svg_is_well_formed_with_title(svg: Path):
    root = ET.parse(svg).getroot()
    assert root.tag == f"{SVG_NS}svg"
    title = root.find(f"{SVG_NS}title")
    assert title is not None and (title.text or "").strip(), f"{svg.name} needs a <title>"

