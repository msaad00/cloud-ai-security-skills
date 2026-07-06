# Zed

Setup for loading `quiver` into Zed via the MCP context-
server extension.

## Install the MCP extension

Zed exposes MCP through the **context_servers** settings key. No extension
install is needed beyond Zed itself.

## Config location

`~/.config/zed/settings.json` (Linux/macOS)

```json
{
  "context_servers": {
    "quiver": {
      "command": {
        "path": "python3",
        "args": [
          "/absolute/path/to/quiver/mcp-server/src/server.py"
        ]
      }
    }
  }
}
```

## Enable in the UI

Open the Zed assistant panel (**⌘?** on macOS) → **Settings → Tools →
MCP** → verify `quiver` shows as connected.

## Least-privilege example — detection engineering

For a Zed workspace focused on writing detectors (so you want OCSF fixtures,
the SARIF converter, and detector skills available but nothing destructive):

```json
{
  "context_servers": {
    "quiver": {
      "command": {
        "path": "python3",
        "args": ["/absolute/path/.../mcp-server/src/server.py"],
        "env": {
          "CLOUD_SECURITY_MCP_ALLOWED_SKILLS": "detect-lateral-movement,detect-privilege-escalation-k8s,detect-credential-stuffing-okta,detect-mcp-tool-drift,convert-ocsf-to-sarif,convert-ocsf-to-mermaid-attack-flow"
        }
      }
    }
  }
}
```

## Quirks

- Zed restarts context servers on settings save — no manual reload.
- If the assistant can't see the tools, run `:language: zed -> Tasks: Show
  Context Server Logs` to inspect stderr from the wrapper.
- Zed's `path` field does not expand `~` — use absolute paths.

## HITL + audit behavior

Identical to every other MCP client in this repo. The assistant-side agentic
loop cannot bypass remediation gates — the wrapper enforces them at the
server, not the client.
