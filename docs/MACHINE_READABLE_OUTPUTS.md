# Machine-readable output contracts

PatchFlow treats JSON, SARIF, and SBOM output as public interfaces. Release
candidates must pass the output-correctness tests and the public repository's
dogfooding workflow before publication.

## Stream behavior

- `--json` writes exactly one JSON document to stdout.
- `--json` suppresses progress, scanner timings, update notices, and debug
  messages on stderr. `--quiet` provides the same suppression for scripting.
- `--verbose` may add human diagnostics only in human-output mode. Combining
  `--verbose` with `--json` must not add another JSON document or write scanner
  diagnostics to stderr.
- A non-zero exit code may communicate findings or a scan failure; consumers
  must inspect the structured payload and the documented exit-code meaning.

## SARIF contract

SARIF output conforms to SARIF 2.1.0, identified by `version: "2.1.0"` and the
SARIF 2.1.0 schema URI. Every invocation includes the required boolean
`executionSuccessful` property. Exit codes `0` (clean) and `1` (findings) mean
the tool executed successfully; configuration, internal, network, auth, and
timeout failures do not.

The release gate generates a real report, checks required tool, rule, result,
location, and invocation fields, and uploads it through GitHub Code Scanning.
An upload rejection is a release blocker.

## Compatibility policy

- Patch releases may fix values or add validation but do not remove fields,
  rename fields, or change field types.
- Minor releases may add optional fields. Consumers must ignore unknown fields.
- Removing a field, renaming it, changing its type, or changing the meaning of
  an exit code requires a documented deprecation and a major release.
- SARIF remains on 2.1.0 until a separately announced compatibility change.
  Vendor-specific metadata stays inside SARIF `properties` bags.

Any intentional contract change must update tests, examples, release notes,
and this document in the same pull request.
