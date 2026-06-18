# PatchFlow CLI Building Context

## 1. Objective

The PatchFlow CLI is the local developer entry point for running security, dependency, reachability, and PR risk analysis before code reaches GitHub/GitLab review.

The goal is not to build another noisy scanner. The CLI should help developers answer one practical question:

> Is this change safe, understandable, and ready to open as a pull request?

The CLI must support the same analysis philosophy as the backend platform:

- asynchronous when running remotely;
- fast and incremental when running locally;
- deterministic scanners first;
- AI only for explanation, prioritization, summarization, and fix proposals;
- minimal friction inside the developer workflow;
- no duplicate storage of Git provider diffs;
- no unnecessary code retention.

---

## 2. Strategic Product Positioning

PatchFlow should not position the CLI as only an "AI PR reviewer".

A better positioning:

> PatchFlow CLI is a local change-risk intelligence tool for AI-assisted development teams.

It should help developers understand:

- what changed;
- what risk was introduced;
- what dependencies were affected;
- whether vulnerable code is reachable;
- whether new security boundaries were touched;
- whether the change is ready for review;
- what should be fixed before opening a PR.

The CLI should reduce cognitive load before the PR stage, not add another bureaucratic machine to the pipeline. Humanity already invented Jira; no need to worsen the situation.

---

## 3. Core CLI Commands

### 3.1 Authentication

```bash
patchflow auth login
patchflow auth logout
patchflow auth status
```

Purpose:

- authenticate developer against PatchFlow backend;
- support GitHub/GitLab identity mapping;
- optionally support local-only mode for self-hosted/on-prem deployments.

Expected behavior:

- store token securely using OS keychain when available;
- fallback to encrypted local config;
- never print tokens in logs.

---

### 3.2 Project Initialization

```bash
patchflow init
patchflow init --project <project-id>
patchflow init --org <org-id>
```

Creates a local `.patchflow/` directory.

Suggested structure:

```text
.patchflow/
  config.yml
  cache/
  baselines/
  reports/
  state.json
```

Example `config.yml`:

```yaml
project_id: "project_123"
organization_id: "org_123"
backend_url: "https://api.patchflow.io"
mode: "hybrid"

analysis:
  default_profile: "developer"
  changed_files_only: true
  include_reachability: true
  include_ai_summary: true
  include_fix_proposals: false

privacy:
  redact_secrets: true
  send_code_to_remote_ai: false
  retain_local_cache_days: 7

ignore:
  paths:
    - node_modules/**
    - dist/**
    - build/**
    - coverage/**
    - vendor/**
    - '*.lock'
```

---

### 3.3 Local Scan

```bash
patchflow scan
patchflow scan --changed
patchflow scan --staged
patchflow scan --path ./services/auth
patchflow scan --profile fast
patchflow scan --profile deep
```

Purpose:

Run local analysis before pushing code.

Analysis types:

- manifest discovery;
- SCA vulnerability analysis;
- SAST checks;
- secrets detection;
- IaC checks;
- dependency graph analysis;
- reachability analysis;
- AI summary if enabled.

Recommended behavior:

- default to `--changed` in Git repositories;
- avoid scanning generated files;
- avoid comments about style/lint issues already handled by configured linters;
- output concise results in terminal;
- write full report to `.patchflow/reports/`.

---

### 3.4 PR Review Simulation

```bash
patchflow pr-review
patchflow pr-review --base main
patchflow pr-review --head feature/auth-refactor
patchflow pr-review --local
patchflow pr-review --json
patchflow pr-review --markdown
```

Purpose:

Simulate what PatchFlow would say on a PR before the developer opens it.

It should compute:

- changed files;
- changed manifests;
- affected dependency graph nodes;
- introduced vulnerabilities;
- reachable vulnerable dependencies;
- security boundary changes;
- breaking changes;
- recommended reviewers;
- risk score;
- suggested fix plan.

Example output:

```text
PatchFlow PR Risk Review

Status: Warning
Risk Score: 72/100

Summary:
- Authentication middleware changed
- 2 dependency manifests modified
- 1 high-severity reachable vulnerability introduced
- 3 test files missing for changed auth paths

Recommended before PR:
1. Upgrade pyjwt to >= 2.8.0
2. Add tests for expired token handling
3. Request review from Identity owner
```

---

### 3.5 Dependency Analysis

```bash
patchflow deps
patchflow deps tree
patchflow deps diff --base main
patchflow deps vulnerable
patchflow deps licenses
```

Purpose:

Provide visibility into dependency changes without requiring the frontend dashboard.

The CLI should show:

- direct dependencies;
- transitive dependencies;
- newly introduced packages;
- removed packages;
- vulnerable packages;
- license risks;
- dependency owner if known;
- reachability if available.

---

### 3.6 Reachability Analysis

```bash
patchflow reachability
patchflow reachability --package <name>
patchflow reachability --cve <cve-id>
patchflow reachability --explain
```

Purpose:

Tell developers whether a vulnerable dependency is actually used.

Reachability confidence levels:

```text
HIGH       directly imported or invoked
MEDIUM     direct dependency, possible runtime usage
LOW        transitive dependency, no direct usage found
NONE       not present in dependency graph
UNKNOWN    analysis incomplete
```

The CLI should explain evidence:

```text
CVE-2024-XXXX in package xyz
Reachability: HIGH
Evidence:
- Imported in services/auth/token.py
- Used by function verify_session_token
- Code path reachable from public endpoint POST /login
```

---

### 3.7 Fix Proposal

```bash
patchflow fix suggest
patchflow fix suggest --finding <id>
patchflow fix apply --finding <id>
patchflow fix apply --dry-run
```

Important rule:

The CLI must not silently mutate code. AI-generated fixes should always be previewed first unless the user explicitly passes an apply flag.

Safe fix flow:

1. generate patch;
2. show patch preview;
3. validate patch applies cleanly;
4. run relevant tests if configured;
5. apply only after user confirmation or explicit `--yes`;
6. store result in local report.

Example:

```bash
patchflow fix apply --finding pf_find_123 --dry-run
patchflow fix apply --finding pf_find_123 --yes
```

---

### 3.8 Report Generation

```bash
patchflow report
patchflow report --format markdown
patchflow report --format json
patchflow report --format sarif
patchflow report --output ./patchflow-report.md
```

Supported output formats:

- terminal summary;
- JSON;
- Markdown;
- SARIF;
- GitHub Checks payload format;
- GitLab Code Quality format later.

Markdown report sections:

```text
Summary
Risk Score
Changed Files
Dependency Changes
Security Findings
Reachability Findings
Breaking Changes
Recommended Reviewers
Suggested Fixes
Audit Metadata
```

---

## 4. Architecture

### 4.1 Local CLI Architecture

```text
CLI Command
  ↓
Command Handler
  ↓
Git Context Resolver
  ↓
Analysis Orchestrator
  ↓
Analyzer Plugins
  ↓
Result Normalizer
  ↓
Risk Engine
  ↓
Output Renderer
```

Recommended implementation language:

- Go if you want fast distribution and single binaries;
- Rust if you want stricter safety and long-term CLI quality;
- Python if you want faster reuse from existing backend services.

Pragmatic recommendation:

Start with Python using Typer or Click because the backend already has Python analyzers. Later, extract performance-critical pieces or ship a Go wrapper if distribution becomes painful.

---

### 4.2 Shared Engine with Backend

Avoid building two different analysis systems.

The CLI and backend should share the same conceptual pipeline:

```text
AnalysisRun
  → RepoContext
  → ManifestDiscovery
  → DependencyGraph
  → AnalyzerExecution
  → Reachability
  → RiskScoring
  → AIExplanation
  → ReportRenderer
```

The backend triggers analysis through:

- GitHub webhooks;
- GitLab webhooks;
- scheduled scans;
- manual dashboard scans;
- CI integration.

The CLI triggers analysis through:

- local Git diff;
- staged files;
- branch comparison;
- developer command.

Same engine, different trigger. Otherwise the codebase becomes a two-headed goat and everyone pretends it is architecture.

---

## 5. Integration with Existing Safe-pip Backend

Current backend capabilities already available:

- scan lifecycle: `PENDING`, `RUNNING`, `COMPLETED`, `FAILED`, `TIMED_OUT`;
- SCA scan through `POST /api/v1/scans/polyglot`;
- SAST scan through `POST /api/v1/scans/sast`;
- Celery background execution;
- Redis Pub/Sub event updates;
- SSE progress streaming;
- OSV vulnerability lookup;
- optional NVD enrichment;
- Bandit-based Python SAST;
- dependency graph reconstruction;
- Python AST import parsing;
- reachability scoring;
- stale scan cleanup.

CLI should initially call backend APIs for remote scans, but support local lightweight mode.

Suggested modes:

```text
local      runs analyzers locally only
remote     sends metadata to backend and waits for result
hybrid     local pre-analysis + backend enrichment
offline    no network, local report only
```

---

## 6. Required Backend API Extensions for CLI

### 6.1 Create Analysis Run

```http
POST /api/v1/analysis-runs
```

Payload:

```json
{
  "project_id": "project_123",
  "trigger_type": "cli",
  "source_ref": "feature/auth-refactor",
  "base_sha": "abc123",
  "head_sha": "def456",
  "mode": "hybrid",
  "changed_files": [],
  "metadata": {
    "cli_version": "0.1.0",
    "git_provider": "github"
  }
}
```

---

### 6.2 Upload Analysis Metadata

```http
POST /api/v1/analysis-runs/{run_id}/metadata
```

Should upload:

- manifest list;
- dependency metadata;
- changed file paths;
- sanitized diff summary;
- local scanner results;
- no raw code unless allowed by policy.

---

### 6.3 Get Analysis Status

```http
GET /api/v1/analysis-runs/{run_id}/status
```

Returns:

```json
{
  "status": "running",
  "progress": 60,
  "stage": "reachability_analysis"
}
```

---

### 6.4 Get Analysis Result

```http
GET /api/v1/analysis-runs/{run_id}
```

Returns normalized findings, risk score, summaries, and fix proposals.

---

## 7. Data Model Recommendations

Unify scans and PR reviews under one generic analysis model.

### 7.1 AnalysisRun

```text
AnalysisRun
- id
- project_id
- organization_id
- trigger_type: manual | scheduled | pr | cli | ci
- source_provider: github | gitlab | local | unknown
- repository
- branch
- base_sha
- head_sha
- status
- progress
- stage
- risk_score
- started_at
- completed_at
- error_message
```

### 7.2 AnalyzerResult

```text
AnalyzerResult
- id
- analysis_run_id
- analyzer_name: osv | nvd | bandit | semgrep | gitleaks | checkov | codeql
- analyzer_version
- status
- started_at
- completed_at
- raw_output_reference
- error_message
```

### 7.3 Finding

```text
Finding
- id
- analysis_run_id
- analyzer_result_id
- type: sca | sast | secret | iac | license | breaking_change | ai_review
- severity
- confidence
- title
- description
- file_path
- line_start
- line_end
- package_name
- package_version
- cve_id
- cwe_id
- fingerprint
- status: open | fixed | dismissed | false_positive | accepted_risk
- evidence
- recommendation
```

### 7.4 ReachabilityResult

```text
ReachabilityResult
- id
- finding_id
- status: high | medium | low | none | unknown
- confidence
- evidence_path
- imported_by
- runtime_entrypoint
- explanation
```

### 7.5 FixProposal

```text
FixProposal
- id
- finding_id
- patch
- explanation
- validation_status
- test_status
- applied
- applied_commit_sha
```

---

## 8. Analyzer Plugin Interface

Each analyzer should implement a common interface.

Pseudo-interface:

```python
class AnalyzerPlugin:
    name: str
    version: str

    def is_applicable(self, repo_context: RepoContext) -> bool:
        ...

    def run(self, repo_context: RepoContext, analysis_scope: AnalysisScope) -> AnalyzerResult:
        ...

    def normalize(self, raw_result: Any) -> list[Finding]:
        ...
```

Initial analyzers:

```text
OSVAnalyzer
NVDEnricher
BanditAnalyzer
SemgrepAnalyzer
GitleaksAnalyzer
CheckovAnalyzer
DependencyGraphAnalyzer
ReachabilityAnalyzer
AIExplanationAnalyzer
```

---

## 9. Developer Experience Principles

### 9.1 Do Not Block by Default

The CLI should warn first and block only when policy explicitly says so.

Default behavior:

```text
show risk → explain risk → suggest fix → allow developer decision
```

Blocking behavior only for:

- critical reachable vulnerabilities;
- detected secrets;
- policy violations;
- unsafe dependency licenses;
- protected repositories.

---

### 9.2 Baseline Mode

Developers should not be punished for old project debt.

Default PR mode should show:

```text
New findings introduced by this change
Existing findings made worse by this change
Existing findings made reachable by this change
Existing findings fixed by this change
```

Do not dump the entire vulnerability history into every PR. That is how tools get muted, then emotionally abandoned.

---

### 9.3 Signal Over Noise

The CLI should suppress:

- lint-only comments;
- formatting issues;
- generated files;
- lockfile noise unless dependency changed materially;
- low-confidence AI guesses;
- duplicated findings;
- issues already covered by configured tools.

---

### 9.4 Native Workflow

The CLI should fit existing developer behavior:

```bash
git add .
patchflow scan --staged
git commit -m "..."
patchflow pr-review --base main
git push
```

Later integration:

```bash
gh pr create --fill
patchflow gh annotate
```

---

## 10. Privacy and Security Requirements

### 10.1 Secret Redaction

Before any remote analysis:

- scan for secrets;
- redact known token patterns;
- redact `.env` content;
- avoid uploading raw secrets;
- warn developer if secrets are found.

### 10.2 Code Retention Modes

Supported modes:

```text
zero-retention      process only, no storage
metadata-only       upload manifests and summaries only
full-analysis       upload sanitized diff/code where policy permits
local-only          no remote upload
```

### 10.3 AI Provider Controls

Config should support:

```yaml
ai:
  enabled: true
  provider: local
  model: reachcore-planner
  send_code_to_external_provider: false
```

Remote enterprise modes:

- local model;
- private VPC model;
- Azure OpenAI tenant-isolated model;
- external AI disabled.

---

## 11. Risk Scoring

Suggested scoring dimensions:

```text
severity_score
reachability_score
exploitability_score
affected_surface_score
dependency_criticality_score
test_coverage_score
change_complexity_score
confidence_score
```

Example formula:

```text
risk_score =
  severity_weight
+ reachability_weight
+ exposure_weight
+ dependency_weight
+ complexity_weight
- test_confidence_weight
```

Output should be understandable, not mystical.

Bad:

```text
Risk Score: 78
```

Good:

```text
Risk Score: 78/100
Reason:
- High severity dependency introduced
- Dependency is directly imported
- Used in authentication path
- No test added for modified code path
```

---

## 12. CLI Output Design

### 12.1 Default Terminal Output

Keep it concise:

```text
PatchFlow Scan Complete

Status: Warning
Risk Score: 72/100
Findings: 4 total, 1 critical, 1 high, 2 medium
Reachable: 2
Fixable: 1

Top Issues:
1. Critical reachable CVE in pyjwt@2.3.0
2. Missing authorization check in services/auth/session.py
3. New dependency has restrictive license

Run `patchflow report --format markdown` for full details.
```

### 12.2 JSON Output

Used by CI/CD:

```bash
patchflow scan --json
```

### 12.3 SARIF Output

Used by GitHub Advanced Security and code scanning:

```bash
patchflow report --format sarif
```

---

## 13. Caching Strategy

Local cache should store:

- dependency graph;
- manifest hashes;
- analyzer versions;
- vulnerability lookup cache;
- previous baseline fingerprints;
- AST index when supported.

Cache invalidation:

```text
manifest hash changed → invalidate dependency graph
source hash changed → invalidate AST slice
analyzer version changed → invalidate analyzer result
config changed → invalidate policy results
```

---

## 14. MVP Scope

### MVP Commands

```bash
patchflow init
patchflow auth login
patchflow scan --changed
patchflow pr-review --base main
patchflow report --format markdown
patchflow fix suggest
```

### MVP Analyzers

```text
OSV SCA
Bandit Python SAST
Gitleaks secrets detection
Python reachability
Dependency diff
AI PR summary
```

### MVP Outputs

```text
Terminal summary
Markdown report
JSON report
```

### MVP Backend Integration

```text
Create analysis run
Upload metadata
Poll result
Fetch report
```

---

## 15. Version 2 Scope

```text
Semgrep / Opengrep support
Checkov IaC support
SARIF output
GitHub Checks integration
GitLab MR annotation
TypeScript reachability
Go reachability
Java dependency graph support
Policy-as-code
Local AI model support
IDE extension bridge
```

---

## 16. Version 3 Scope

```text
Visual PR review
Playwright screenshot analysis
UI regression reasoning
Accessibility review
Architecture drift detection
Runtime exploitability validation
Multi-agent review orchestration
On-prem enterprise deployment
Air-gapped mode
Custom fine-tuned review models
```

---

## 17. Recommended Implementation Plan

### Phase 1: CLI Skeleton

- choose Python Typer;
- create command structure;
- implement config loading;
- implement Git context resolver;
- implement local report renderer.

### Phase 2: Local Analysis

- manifest discovery;
- OSV lookup;
- Bandit execution;
- Gitleaks integration;
- basic Python reachability;
- normalized finding model.

### Phase 3: Backend Sync

- authenticate with backend;
- create analysis run;
- upload sanitized metadata;
- poll status;
- fetch enriched results.

### Phase 4: PR Intelligence

- compare base/head;
- detect new findings only;
- generate PR summary;
- compute risk score;
- suggest reviewers.

### Phase 5: Safe Fixes

- generate fix proposal;
- preview patch;
- dry-run apply;
- run tests;
- apply with confirmation.

---

## 18. Non-Negotiable Rules

1. Never block developers by default.
2. Never upload raw code unless policy allows it.
3. Never show low-confidence AI guesses as facts.
4. Never duplicate findings across runs.
5. Never comment on what linters already handle.
6. Never silently apply AI fixes.
7. Never analyze draft/WIP changes aggressively.
8. Always explain why a finding matters.
9. Always preserve developer workflow.
10. Always make risk understandable.

---

## 19. Success Metrics

Developer experience metrics:

```text
time_to_first_result
false_positive_dismissal_rate
developer_reenable_rate
cli_daily_active_users
local_scan_before_pr_rate
fix_acceptance_rate
average_findings_per_pr
percentage_of_findings_new_vs_existing
```

Security metrics:

```text
critical_reachable_findings_prevented
secrets_prevented_before_push
vulnerable_dependencies_fixed
mean_time_to_remediation
policy_violations_blocked
```

Platform metrics:

```text
analysis_runtime_p95
cache_hit_rate
remote_analysis_failure_rate
backend_polling_latency
analyzer_timeout_rate
```

---

## 20. Final Design Principle

The PatchFlow CLI should feel like a senior security-minded engineer sitting beside the developer before the PR is opened.

Not a compliance dashboard.
Not a noisy bot.
Not a scanner vomiting CVEs into the terminal like it discovered fire.

A quiet local assistant that says:

> This change touches something important. Here is why. Here is what to fix. Here is what is safe to ignore.

That is the developer experience worth building.
