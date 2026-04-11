# References — ingest-mcp-proxy-ocsf

## Source format

- **Model Context Protocol specification** — https://modelcontextprotocol.io/specification
- **MCP JSON-RPC shape** — https://modelcontextprotocol.io/specification/server/tools
- **MCP `tools/list` result** — https://modelcontextprotocol.io/specification/server/tools#listing-tools
- **MCP `tools/call` request** — https://modelcontextprotocol.io/specification/server/tools#calling-tools
- **agent-bom proxy log format** (the upstream producer) — https://github.com/msaad00/agent-bom

## Output format

- **OCSF 1.8 Application Activity (class 6002)** — https://schema.ocsf.io/1.8.0/classes/application_activity
- **OCSF 1.8 metadata.profiles** — https://schema.ocsf.io/1.8.0/objects/metadata

This skill uses the custom profile `cloud_security_mcp` (declared in
`OCSF_CONTRACT.md`) to carry MCP-specific fields (`mcp.session_uid`,
`mcp.method`, `mcp.direction`, `mcp.tool.*`) without forcing the
upstream OCSF schema to adopt them.

When OCSF publishes an official MCP / AI-agent profile, the skill will
migrate the `mcp` key to the official field names in a single PR and
bump the contract version.

## Fingerprint definition

```python
fingerprint = "sha256:" + hashlib.sha256(
    json.dumps(
        {
            "name":        tool.get("name", ""),
            "description": tool.get("description", ""),
            "inputSchema": tool.get("inputSchema", {}),
            "annotations": tool.get("annotations", {}),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
).hexdigest()
```

This is the pivot point `detect-mcp-tool-drift` uses to spot the MCP tool-poisoning / rug-pull attack pattern (MITRE T1195.001).

## Required permissions

None. The skill reads from stdin or a file. The upstream agent-bom proxy
runs as the user who invokes the MCP server; the log file inherits that
user's permissions.

## See also

- `OCSF_CONTRACT.md` (sibling) for the per-skill wire contract
- `detect-mcp-tool-drift` (sibling) — the downstream detector that consumes this skill's output
