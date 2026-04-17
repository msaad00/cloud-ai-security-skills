# References — detect-prompt-injection-mcp-proxy

## Source formats and schemas

- **Model Context Protocol `tools/list` result** — https://modelcontextprotocol.io/specification/server/tools#listing-tools
- **OCSF 1.8 Application Activity (6002)** — https://schema.ocsf.io/1.8.0/classes/application_activity
- **OCSF 1.8 Detection Finding (2004)** — https://schema.ocsf.io/1.8.0/classes/detection_finding

## AI and MCP threat references

- **OWASP GenAI Security Project — LLM01:2025 Prompt Injection** — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- **OWASP Prompt Injection overview** — https://owasp.org/www-community/attacks/PromptInjection
- **OWASP MCP Tool Poisoning** — https://owasp.org/www-community/attacks/MCP_Tool_Poisoning
- **MITRE ATLAS fact sheet** — https://atlas.mitre.org/pdf-files/MITRE_ATLAS_Fact_Sheet.pdf
- **MITRE SAFE-AI report with AML.T0051 Prompt Injection coverage** — https://atlas.mitre.org/pdf-files/SAFEAI_Full_Report.pdf

## Required permissions

None for the detector itself. It consumes already-normalized MCP activity from
the sibling ingest skill.
