# Diagrams

`ARCHITECTURE.md` is the design contract. This file is the visual companion.

Keep markdown diagrams lightweight and reviewable, then pair them with polished SVGs for docs pages and PRs. If a diagram becomes dense enough to overlap or require zooming, simplify it instead of adding more boxes.

## Visual set

- Primary visuals:
  - [Repository architecture](images/repo-architecture.svg)
  - [End-to-end skill flows](images/end-to-end-skill-flows.svg)
  - [IAM departures cross-cloud workflow](images/iam-departures-architecture.svg)
- [Data handling paths](images/data-handling-paths.svg)
- [Start here guide](images/start-here-guide.svg)
- [Runtime surfaces](images/runtime-surfaces.svg)
- [IAM departures data flow](images/iam-departures-data-flow.svg)
- [Detection engineering pipeline](images/detection-pipeline.svg)

## Diagram descriptions

Use these descriptions as the text companion for screen readers, plain-text
review, and PR discussions where opening the SVG is inconvenient.

- `data-handling-paths.svg`
  - Shows the main data-entry choices, the first skill family for each, the resulting outputs, and the control boundary that applies on each path.
- `start-here-guide.svg`
  - Shows the shortest operator decision tree for choosing the first layer: discover, ingest, detect, evaluate, sink, or remediate.
- `runtime-surfaces.svg`
  - Shows that CLI, CI, MCP, and persistent runners are access paths around the same skill bundle and execution core rather than separate implementations.
- `iam-departures-architecture.svg`
  - Shows the flagship write path in four stages: actionable-set selection, guarded orchestration, scoped target writes, and dual audit with drift verification.
- `repo-architecture.svg`
  - Shows the six shipped skill layers plus the surrounding source, sink, query-pack, and runtime surfaces that compose around them.
- `iam-departures-data-flow.svg`
  - Shows the remediation workflow data path from source manifests through planning, approval, execution, and audit artifacts.
- `detection-pipeline.svg`
  - Shows the standard event path from raw input through normalization, detection, optional export, and downstream persistence.
- `end-to-end-skill-flows.svg`
  - Shows three concrete shipped compositions with the same four questions answered in each lane: what the input is, which skill families run, what the output becomes, and which guardrails apply.

## Rules

- Keep ASCII or Mermaid diagrams in markdown for git-friendly diffs.
- Keep the polished SVGs in `docs/images/`.
- Prefer 2-3 high-signal diagrams over a large diagram dump.
- One diagram should answer one question. Do not mix repo structure, runtime surfaces, and roadmap detail in the same visual.
- The flagship remediation diagram can be more detailed than the repo overview, but the repo overview should stay readable in GitHub preview without zooming.
- Treat text overlap or zoom-dependent readability as a documentation bug, not a cosmetic issue.
