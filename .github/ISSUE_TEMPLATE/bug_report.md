---
name: Bug report
about: A skill, ingester, detector, or workflow behaves incorrectly
title: ""
labels: bug
assignees: ""
---

## What's wrong

<!-- One sentence. Which skill / layer? What did it do vs. what you expected? -->

- **Skill / path:** <!-- e.g. skills/detection/detect-mcp-tool-drift -->
- **Execution mode:** <!-- CLI · CI · MCP · runner -->

## Reproduce

<!-- Exact command + minimal input. Redact any real account IDs, ARNs, or secrets. -->

```
python skills/.../src/....py < input.jsonl
```

## Expected vs. actual

<!-- Include the relevant OCSF/finding output or error. stderr is diagnostic; stdout is the contract. -->

## Environment

- Python version:
- Cloud SDK versions (if relevant):
- Commit / release:
