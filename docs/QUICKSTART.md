# Quickstart

The shortest path to seeing a finding, then to wiring these skills into any
agent. One page. Copy-paste.

---

## 1 · See a finding in 30 seconds (no cloud creds)

```bash
git clone https://github.com/msaad00/cloud-ai-security-skills.git
cd cloud-ai-security-skills
uv sync                      # install uv first: https://docs.astral.sh/uv/
uv run make demo
```

`make demo` runs the three-stage pipeline (`ingest-cloudtrail-ocsf →
detect-aws-access-key-creation → convert-ocsf-to-sarif`) against a captured
CloudTrail fixture, writes `/tmp/cloud-security-demo.sarif`, and prints the
findings. Structured JSON logs go to stderr; the tail of the output is:

```text
Findings written to /tmp/cloud-security-demo.sarif
1 finding(s) emitted
  - <rule id>: AWS IAM access key created

Actor `AROAEXAMPLEID:alice` successfully called `CreateAccessKey` for IAM user `bob` in account `123456789012` (us-east-1). Source IP: 203.0.113.42. This creates additional AWS credential material for a valid cloud account.
```

The same pipeline spelled out, one skill per stage joined by Unix pipes:

```bash
uv run python skills/ingestion/ingest-cloudtrail-ocsf/src/ingest.py \
       skills/detection-engineering/golden/cloudtrail_raw_sample.jsonl \
  | uv run python skills/detection/detect-aws-access-key-creation/src/detect.py \
  | uv run python skills/view/convert-ocsf-to-sarif/src/convert.py \
  > findings.sarif
```

Drop the last stage to see the raw OCSF 1.8 Detection Finding (`class_uid`
2004) on stdout. These three skills are stdlib-only, so a plain Python 3.11+
interpreter also works; `uv run` just keeps you inside the project
environment. Cloud-specific skills (anything that talks to AWS / GCP / Azure /
K8s / Snowflake / Databricks / ClickHouse) need their group installed first:
`uv sync --group dev --group <cloud>` — see [`INSTALL.md`](INSTALL.md).

> No top-level CLI is shipped today (the repo is structured as 134
> independent skill bundles, not a single binary). A `uvx`-installable entry
> point that wraps the most common pipelines is tracked as a P1 follow-up.

---

## 2 · Plug into your agent (every client, copy-paste)

The full agent-by-agent matrix — Claude Code, Claude Desktop, Cursor,
Windsurf, Codex, Cortex, Zed, plus Anthropic SDK / OpenAI SDK / LangGraph
example agents — lives in [`AGENT_QUICKSTART.md`](AGENT_QUICKSTART.md). Each
section is eight lines or fewer.

The repo-root [`.mcp.json`](../.mcp.json) is wired for Claude Code out of
the box: open the repo in Claude Code and the MCP server registers
automatically. **Note**: that file uses a relative path
(`mcp-server/src/server.py`), so the working directory must be the repo
root. For every other client (Claude Desktop, Cursor global, Windsurf,
Codex, Cortex, Zed) use an **absolute** path — those clients don't expand
`~` or `${workspaceFolder}` (except Cursor's project-scoped
`.cursor/mcp.json`).

---

## 3 · Where to go next

| You want to… | Read this |
|---|---|
| See every shipped skill grouped by environment / purpose | [`SKILL_INDEX.md`](SKILL_INDEX.md) |
| Find which vendor signal normalizes to which OCSF class | [`INGEST_COVERAGE.md`](INGEST_COVERAGE.md) |
| Understand the trust contract (audit, HITL, sandbox, allowlist) | [`MCP_AUDIT_CONTRACT.md`](MCP_AUDIT_CONTRACT.md), [`RUNTIME_ISOLATION.md`](RUNTIME_ISOLATION.md) |
| Compose skills into a pipeline | [`SKILL_COMPOSITION.md`](SKILL_COMPOSITION.md) |
| Run against real cloud creds | [`INSTALL.md`](INSTALL.md), [`CREDENTIAL_PROVENANCE.md`](CREDENTIAL_PROVENANCE.md) |
| Add a new skill | [`SKILL_CONTRACT.md`](SKILL_CONTRACT.md), [`../CONTRIBUTING.md`](../CONTRIBUTING.md) |
