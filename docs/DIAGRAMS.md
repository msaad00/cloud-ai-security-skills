# Diagrams

`ARCHITECTURE.md` is the design contract. This file is the visual companion.

Keep markdown diagrams lightweight and reviewable, then pair them with polished SVGs for docs pages and PRs. If a diagram becomes dense enough to overlap or require zooming, simplify it instead of adding more boxes.

## Visual set

- [Data handling paths](images/data-handling-paths.svg)
- [Start here guide](images/start-here-guide.svg)
- [Runtime surfaces](images/runtime-surfaces.svg)
- [IAM departures cross-cloud workflow](images/iam-departures-architecture.svg)
- [Repository architecture](images/repo-architecture.svg)
- [IAM departures data flow](images/iam-departures-data-flow.svg)
- [Detection engineering pipeline](images/detection-pipeline.svg)
- [End-to-end skill flows](images/end-to-end-skill-flows.svg)

## Diagram descriptions

Use these descriptions as the text companion for screen readers, plain-text
review, and PR discussions where opening the SVG is inconvenient.

- `data-handling-paths.svg`
  - Shows the main runtime choices: live cloud posture, raw log ingest, OCSF-ready lake detection, raw lake detection through ingest, persistence via sinks, and guarded remediation.
- `start-here-guide.svg`
  - Shows the shortest decision tree for choosing a first layer: discover for inventory/evidence, ingest for raw logs, detect for normalized events, evaluate for posture, sink for persistence, and remediate for guarded writes.
- `runtime-surfaces.svg`
  - Shows that CLI, CI, MCP, and persistent runners are access paths around the same skill bundle and execution core rather than separate implementations.
- `iam-departures-architecture.svg`
  - Shows the flagship write path: HR/IdP inputs, guarded orchestration, human approval, worker actions, and dual audit writes for reconciliation.
- `repo-architecture.svg`
  - Shows the six shipped skill layers plus the surrounding source, sink, query-pack, and runtime surfaces that compose around them.
- `iam-departures-data-flow.svg`
  - Shows the remediation workflow data path from source manifests through planning, approval, execution, and audit artifacts.
- `detection-pipeline.svg`
  - Shows the standard event path from raw input through normalization, detection, optional export, and downstream persistence.
- `end-to-end-skill-flows.svg`
  - Shows three concrete shipped compositions: raw logs through ingest/detect/export, warehouse rows through source/detect/sink, and live discovery/evaluation with native outputs and optional guarded action paths.

## Rules

- Keep ASCII or Mermaid diagrams in markdown for git-friendly diffs.
- Keep the polished SVGs in `docs/images/`.
- Prefer 2-3 high-signal diagrams over a large diagram dump.
- One diagram should answer one question. Do not mix repo structure, runtime surfaces, and roadmap detail in the same visual.
- The flagship remediation diagram can be more detailed than the repo overview, but the repo overview should stay readable in GitHub preview without zooming.
- Treat text overlap or zoom-dependent readability as a documentation bug, not a cosmetic issue.
