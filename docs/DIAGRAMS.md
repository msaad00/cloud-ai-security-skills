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

## Rules

- Keep ASCII or Mermaid diagrams in markdown for git-friendly diffs.
- Keep the polished SVGs in `docs/images/`.
- Prefer 2-3 high-signal diagrams over a large diagram dump.
- One diagram should answer one question. Do not mix repo structure, runtime surfaces, and roadmap detail in the same visual.
- The flagship remediation diagram can be more detailed than the repo overview, but the repo overview should stay readable in GitHub preview without zooming.
- Treat text overlap or zoom-dependent readability as a documentation bug, not a cosmetic issue.
