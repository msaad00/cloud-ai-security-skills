from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
SKILLS_ROOT = ROOT / "skills"

NAME_RE = re.compile(r"^[a-z0-9-]{1,64}$")
FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
URL_RE = re.compile(r"https://[^\s)>\"]+")

ENTRYPOINT_CANDIDATES = (
    "src/ingest.py",
    "src/detect.py",
    "src/convert.py",
    "src/checks.py",
    "src/discover.py",
)

OFFICIAL_REFERENCE_HOSTS = {
    "attack.mitre.org",
    "atlas.mitre.org",
    "boto3.amazonaws.com",
    "clickhouse.com",
    "cloud.google.com",
    "cyclonedx.org",
    "developer.okta.com",
    "community.workday.com",
    "datatracker.ietf.org",
    "developers.google.com",
    "docs.aws.amazon.com",
    "docs.databricks.com",
    "docs.docker.com",
    "docs.nvidia.com",
    "docs.oasis-open.org",
    "docs.snowflake.com",
    "genai.owasp.org",
    "grpc.github.io",
    "kubernetes.io",
    "learn.microsoft.com",
    "mermaid.js.org",
    "modelcontextprotocol.io",
    "nvidia.custhelp.com",
    "ocsf.io",
    "schema.ocsf.io",
    "www.aicpa-cima.com",
    "www.cisecurity.org",
    "www.iso.org",
    "www.nist.gov",
    "www.pcisecuritystandards.org",
}

ALLOWED_GITHUB_PREFIXES = (
    "NVIDIA/dcgm-exporter",
    "NVIDIA/nvidia-container-toolkit",
    "cncf-tags/container-device-interface",
    "falcosecurity/rules",
    "msaad00/agent-bom",
    "opencontainers/image-spec",
)


@dataclass(frozen=True)
class SkillContract:
    name: str
    description: str
    category: str
    skill_dir: Path
    frontmatter: dict[str, str]
    skill_text: str
    entrypoint: Path | None

    @property
    def references_path(self) -> Path:
        return self.skill_dir / "REFERENCES.md"

    @property
    def is_write_capable(self) -> bool:
        if self.frontmatter.get("capability", "").startswith("write-"):
            return True
        return self.category == "remediation" or self.name.startswith(("remediate-", "sink-", "runner-"))


def iter_skill_dirs() -> list[Path]:
    return sorted(path.parent for path in SKILLS_ROOT.glob("*/*/SKILL.md"))


def extract_frontmatter(skill_md: Path) -> str:
    text = skill_md.read_text()
    match = FRONTMATTER_RE.match(text)
    if not match:
        raise ValueError(f"{skill_md} missing YAML frontmatter")
    return match.group(1)


def parse_frontmatter(frontmatter: str) -> dict[str, str]:
    data: dict[str, str] = {}
    lines = frontmatter.splitlines()
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        if not line.strip() or line.startswith(" "):
            idx += 1
            continue
        if ":" not in line:
            idx += 1
            continue

        key, raw_value = line.split(":", 1)
        key = key.strip()
        value = raw_value.strip()

        if not value or value in {">-", "|", ">"}:
            idx += 1
            block: list[str] = []
            while idx < len(lines):
                child = lines[idx]
                if child.startswith("  "):
                    block.append(child.strip())
                    idx += 1
                    continue
                if not child.strip():
                    idx += 1
                    continue
                break
            data[key] = " ".join(part for part in block if part)
            continue

        data[key] = value.strip("\"'")
        idx += 1

    return data


def resolve_entrypoint(skill_dir: Path) -> Path | None:
    for candidate in ENTRYPOINT_CANDIDATES:
        path = skill_dir / candidate
        if path.exists():
            return path
    return None


def discover_skill_contracts() -> list[SkillContract]:
    skills: list[SkillContract] = []
    for skill_dir in iter_skill_dirs():
        skill_md = skill_dir / "SKILL.md"
        text = skill_md.read_text()
        frontmatter = parse_frontmatter(extract_frontmatter(skill_md))
        skills.append(
            SkillContract(
                name=frontmatter.get("name", ""),
                description=frontmatter.get("description", ""),
                category=skill_dir.parent.name,
                skill_dir=skill_dir,
                frontmatter=frontmatter,
                skill_text=text,
                entrypoint=resolve_entrypoint(skill_dir),
            )
        )
    return skills


def extract_reference_urls(path: Path) -> list[str]:
    if not path.exists():
        return []
    return URL_RE.findall(path.read_text())


def reference_url_allowed(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False

    host = parsed.netloc.lower()
    if host in OFFICIAL_REFERENCE_HOSTS:
        return True

    if host == "github.com":
        path = parsed.path.strip("/")
        return any(path.startswith(prefix) for prefix in ALLOWED_GITHUB_PREFIXES)

    return False
