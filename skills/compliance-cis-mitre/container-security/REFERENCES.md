# References — container-security

## Standards implemented

- **CIS Docker Benchmark** — https://www.cisecurity.org/benchmark/docker
- **OCI Image Spec** — https://github.com/opencontainers/image-spec
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework

## Inputs

This skill is **agentless** and reads any of:

1. A `Dockerfile` (text)
2. An OCI image config JSON (output of `docker inspect <image>`)
3. A container runtime dump (`docker container inspect <id>`)

It does **not** require a Docker daemon, does **not** pull images, and
does **not** execute containers. The skill is pure config analysis.

## Required permissions

None (pure file read). If you collect Dockerfile / inspect output via
the Docker CLI as part of a CI step, the CI runner needs read access to
the image registry — that's outside the skill's scope.

## What gets checked

| Check | Source | Reference |
|---|---|---|
| `USER` directive present (non-root) | Dockerfile | https://docs.docker.com/build/building/best-practices/#user |
| Image is pinned by digest, not `:latest` | Dockerfile / inspect | https://docs.docker.com/build/building/best-practices/#use-multi-stage-builds |
| No secrets in `ENV` | Dockerfile / inspect | https://docs.docker.com/build/building/secrets/ |
| `HEALTHCHECK` defined | Dockerfile | https://docs.docker.com/reference/dockerfile/#healthcheck |
| Read-only root filesystem at runtime | Inspect | https://docs.docker.com/reference/cli/docker/container/run/#read-only |
| `--privileged` not set | Inspect | https://docs.docker.com/reference/cli/docker/container/run/#privileged |
| Capability set minimised (`--cap-drop=ALL`) | Inspect | https://docs.docker.com/engine/security/#linux-kernel-capabilities |
| Seccomp profile applied (default or custom) | Inspect | https://docs.docker.com/engine/security/seccomp/ |

The full check list is in `src/checks.py`.
