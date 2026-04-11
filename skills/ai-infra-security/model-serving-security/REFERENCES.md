# References — model-serving-security

## Standards implemented

- **OWASP Top 10 for LLM Applications (2025)** — https://genai.owasp.org/llm-top-10/
- **MITRE ATLAS** — https://atlas.mitre.org/
- **NIST AI Risk Management Framework (AI RMF 1.0)** — https://www.nist.gov/itl/ai-risk-management-framework
- **NIST CSF 2.0** — https://www.nist.gov/cyberframework
- **SOC 2 TSC** — CC6.1, CC6.6 (logical access and transmission)

## Inputs

Pure config analysis. The skill consumes JSON or YAML describing your
serving stack:

- API Gateway / Lambda / ALB target group config
- Kubernetes Deployment + Service + Ingress (the same JSON `kubectl get -o json` produces)
- Cloud-native serving config (Vertex AI endpoint config, SageMaker endpoint config, Azure ML online endpoint config)

## Required permissions

None at runtime — the skill reads files. If you collect serving config
via cloud SDKs as part of a CI step, the CI runner needs the relevant
viewer role:

- **Vertex AI** — `roles/aiplatform.viewer` https://cloud.google.com/iam/docs/understanding-roles#aiplatform.viewer
- **SageMaker** — `AmazonSageMakerReadOnly` https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol.html#security-iam-awsmanpol-AmazonSageMakerReadOnly
- **Azure ML** — Reader role on the workspace https://learn.microsoft.com/en-us/azure/machine-learning/how-to-assign-roles

## What gets checked (16 controls across 6 domains)

| Domain | Controls | Reference |
|---|---|---|
| Authentication | OAuth2 / API key required, JWT validation | https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/ |
| Rate limiting | Per-key and per-IP RPM/RPD | https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/ |
| Data egress | VPC-only endpoint, no public internet | https://atlas.mitre.org/techniques/AML.T0024/ |
| Runtime isolation | Non-root, read-only FS, dropped caps | https://kubernetes.io/docs/concepts/security/pod-security-standards/ |
| TLS | TLS 1.2+ enforced, valid cert | https://datatracker.ietf.org/doc/rfc8446/ |
| Safety | Prompt injection filter, content classification, output filter | https://genai.owasp.org/llmrisk/llm01-prompt-injection/ |

The full check list is in `src/checks.py` — one function per check.
