# PatchFlow Product Principles

## 1. Context > Diff

A diff alone is insufficient.

PatchFlow must understand:
- Repository context
- Business context
- Dependency context
- Runtime context

## 2. Signal > Noise

Every alert costs attention.

Avoid:
- Style comments
- Lint duplication
- Low-confidence findings

Prioritize:
- Architectural risks
- Reachable vulnerabilities
- Breaking changes

## 3. Explain > Block

Blocking is expensive.

Order:
1. Explain
2. Educate
3. Recommend
4. Enforce

## 4. Trust > Automation

Automation without trust fails adoption.

Every finding must answer:
- Why?
- How?
- Impact?
- Evidence?
- Fix?

## 5. Human > AI

AI assists.

Humans decide.

## 6. Developer Experience First

Reduce:
- Context switching
- Cognitive load
- Review fatigue

Increase:
- Understanding
- Velocity
- Confidence

## 7. Vibe Then Verify

AI generates hypotheses.

Deterministic systems verify facts.

## 8. Native Workflow Integration

PatchFlow should live where developers already work:
- GitHub
- GitLab
- IDEs
- CLI

## 9. Privacy By Design

Support:
- Self-hosted
- VPC
- Air-gapped
- BYOK

## 10. Change Intelligence

PatchFlow is not a scanner.

PatchFlow is a Change Intelligence Platform.
