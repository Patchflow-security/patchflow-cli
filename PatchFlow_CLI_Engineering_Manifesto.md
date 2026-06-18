# PatchFlow CLI Engineering Manifesto

## Vision

PatchFlow is not a vulnerability scanner.

PatchFlow is a Change Intelligence Platform that helps engineering teams understand the security, operational, architectural, and business impact of software changes before they reach production.

Our goal is to reduce cognitive load, eliminate noisy reviews, and provide actionable intelligence that helps developers move faster without sacrificing quality or security.

---

# Core Principles

## Developer First

Developers are our primary users.

Every feature must answer:

- Does this reduce developer effort?
- Does this reduce context switching?
- Does this increase understanding?
- Does this save time?

If the answer is no, the feature should be reconsidered.

---

## Signal Over Noise

PatchFlow should never compete with:

- Linters
- Formatters
- IDE diagnostics

PatchFlow focuses on:

- Architectural risks
- Security risks
- Dependency risks
- Business logic risks
- Change impact analysis

---

## Explain Before Blocking

PatchFlow should:

1. Explain
2. Educate
3. Recommend
4. Enforce (only when policy requires)

Blocking is the last step.

---

## Context Is Everything

A diff alone is insufficient.

PatchFlow should leverage:

- Git history
- Pull requests
- ADRs
- Jira
- Linear
- Documentation
- Dependency graphs
- Repository standards
- Security policies

---

# Technology Stack

## CLI

Language: Go

Why:

- Single binary distribution
- Fast startup
- Cross-platform
- Strong concurrency
- Excellent Git integration
- Enterprise-friendly deployment

Core Libraries:

- cobra
- viper
- go-git
- oauth2
- grpc
- websocket
- zap

---

## Backend Platform

Language: Python

Frameworks:

- FastAPI
- Pydantic
- SQLAlchemy
- Celery

Responsibilities:

- Orchestration
- Context aggregation
- AI workflows
- Analysis pipelines
- Policy enforcement

---

## Database

Primary:

- PostgreSQL

Optional:

- Redis
- Qdrant

---

## AI Layer

Supported Providers:

- OpenAI
- Anthropic
- Google
- Ollama
- Local Models

Design Philosophy:

- Model agnostic
- Provider agnostic
- Privacy first

---

## Security Analysis Layer

Deterministic Engines:

- Semgrep
- Opengrep
- Trivy
- Gitleaks
- Checkov
- CodeQL
- Bandit

AI should explain findings, not invent them.

---

# CLI Architecture

```text
patchflow
├── auth
├── login
├── logout
├── doctor
├── config
├── scan
├── review
├── policy
├── explain
├── agent
└── telemetry
```

---

# Engineering Standards

## Code Quality

Required:

- Unit tests
- Integration tests
- Type safety
- Structured logging
- Error wrapping

Avoid:

- Global mutable state
- Hidden side effects
- Silent failures

---

## API Design

Rules:

- Version all APIs
- Use explicit schemas
- Return structured errors
- Maintain backward compatibility

---

## Security Standards

Never:

- Store repository source code permanently
- Log secrets
- Expose credentials
- Trust AI output without validation

Always:

- Encrypt sensitive data
- Validate inputs
- Verify permissions
- Audit actions

---

# AI Principles

## Vibe Then Verify

AI suggestions are hypotheses.

Deterministic systems are truth.

Workflow:

```text
AI Suggestion
      ↓
Validation
      ↓
Compilation
      ↓
Testing
      ↓
User Review
```

---

## Human In Control

AI can:

- Recommend
- Explain
- Summarize
- Prioritize

AI cannot:

- Replace engineering judgment
- Bypass security controls
- Approve production changes automatically

---

# Product Philosophy

PatchFlow should answer:

- What changed?
- Why does it matter?
- What is affected?
- What is the risk?
- What should happen next?

PatchFlow should not become another alerting system.

---

# Long-Term Vision

Build the operating system for software change intelligence.

Future capabilities:

- PR intelligence
- Design review agents
- Security review agents
- Runtime impact prediction
- Dependency intelligence
- Architecture drift detection
- Multi-repository reasoning
- Autonomous remediation with human approval

The objective is simple:

Help engineering teams understand software change faster than software change is being created.
