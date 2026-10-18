from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from skills._shared.skill_metadata import extract_frontmatter as extract_frontmatter  # noqa: E402
from skills._shared.skill_metadata import parse_frontmatter as parse_frontmatter  # noqa: E402
from skills._shared.skill_metadata import parse_modes as parse_modes  # noqa: E402
from skills._shared.skill_metadata import resolve_entrypoint as resolve_entrypoint  # noqa: E402

SKILLS_ROOT = ROOT / "skills"
CANONICAL_SKILL_CATEGORIES = {
    "ingestion",
    "detection",
    "discovery",
    "evaluation",
    "view",
    "remediation",
    "output",
}

NAME_RE = re.compile(r"^[a-z0-9-]{1,64}$")
URL_RE = re.compile(r"https://[^\s)>\"]+")

APPROVAL_MODE_VALUES = {"none", "dry_run_required", "human_required"}
EXECUTION_MODE_VALUES = {"jit", "ci", "mcp", "persistent"}
SIDE_EFFECT_VALUES = {
    "none",
    "writes-cloud",
    "writes-identity",
    "writes-storage",
    "writes-database",
    "writes-audit",
}
INPUT_FORMAT_VALUES = {"raw", "canonical", "native", "ocsf"}
OUTPUT_FORMAT_VALUES = {"raw", "native", "ocsf", "bridge"}
CONCURRENCY_SAFETY_VALUES = {"stateless", "requires_consistent_sharding", "operator_coordinated"}
NETWORK_EGRESS_RE = re.compile(r"^(?:\*\.)?(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+$")
FRONTMATTER_KEY_ORDER = (
    "name",
    "description",
    # Agent-bom trust-heuristic axis fields. They live immediately after
    # description so a human reviewer sees the trust posture before the
    # operational metadata. See `scripts/add_skill_trust_frontmatter.py`
    # for the derivation rules and `docs/SKILL_CONTRACT.md` for the
    # field definitions.
    "purpose",
    "capability",
    "persistence",
    "telemetry",
    "privilege_escalation",
    "license",
    "approval_model",
    "execution_modes",
    "side_effects",
    "input_formats",
    "output_formats",
    "concurrency_safety",
    "network_egress",
    "caller_roles",
    "approver_roles",
    "min_approvers",
    "compatibility",
    "metadata",
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
    "developer.salesforce.com",
    "docs.aws.amazon.com",
    "docs.databricks.com",
    "docs.docker.com",
    "docs.github.com",
    "docs.nvidia.com",
    "docs.oasis-open.org",
    "docs.snowflake.com",
    "genai.owasp.org",
    "owasp.org",
    "cheatsheetseries.owasp.org",
    "cwe.mitre.org",
    "capec.mitre.org",
    "grpc.github.io",
    "help.salesforce.com",
    "help.sap.com",
    "kubernetes.io",
    "learn.microsoft.com",
    "mermaid.js.org",
    "modelcontextprotocol.io",
    "nvidia.custhelp.com",
    "ocsf.io",
    "api.slack.com",
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
    "aquasecurity/tracee",
    "cncf-tags/container-device-interface",
    "falcosecurity/rules",
    "msaad00/agent-bom",
    "opencontainers/image-spec",
    "OWASP/ASVS",
    "OWASP/CheatSheetSeries",
    "OWASP/Top10",
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
        return self.category == "remediation" or self.name.startswith(
            ("remediate-", "sink-", "runner-")
        )

    @property
    def approval_model(self) -> str:
        return self.frontmatter.get("approval_model", "")

    @property
    def execution_modes(self) -> tuple[str, ...]:
        return parse_modes(self.frontmatter.get("execution_modes"))

    @property
    def side_effects(self) -> tuple[str, ...]:
        return parse_modes(self.frontmatter.get("side_effects"))

    @property
    def network_egress(self) -> tuple[str, ...]:
        return parse_modes(self.frontmatter.get("network_egress"))

    @property
    def concurrency_safety(self) -> str:
        return self.frontmatter.get("concurrency_safety", "")

    @property
    def caller_roles(self) -> tuple[str, ...]:
        return parse_modes(self.frontmatter.get("caller_roles"))

    @property
    def approver_roles(self) -> tuple[str, ...]:
        return parse_modes(self.frontmatter.get("approver_roles"))

    @property
    def min_approvers(self) -> int | None:
        raw_value = self.frontmatter.get("min_approvers", "").strip()
        if not raw_value:
            return None
        return int(raw_value)


def iter_skill_dirs() -> list[Path]:
    return sorted(path.parent for path in SKILLS_ROOT.glob("*/*/SKILL.md"))


def iter_skill_like_dirs() -> list[Path]:
    skill_dirs: list[Path] = []
    for category_dir in sorted(SKILLS_ROOT.iterdir()):
        if not category_dir.is_dir():
            continue
        if category_dir.name not in CANONICAL_SKILL_CATEGORIES:
            continue
        for skill_dir in sorted(category_dir.iterdir()):
            if not skill_dir.is_dir():
                continue
            skill_dirs.append(skill_dir)
    return skill_dirs


def extract_frontmatter_keys(frontmatter: str) -> tuple[str, ...]:
    keys: list[str] = []
    for line in frontmatter.splitlines():
        if not line.strip() or line.startswith(" "):
            continue
        if ":" not in line:
            continue
        key, _ = line.split(":", 1)
        keys.append(key.strip())
    return tuple(keys)


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
