# Framework Rule Packs

Official embedded PatchFlow framework security packs. Each pack is typed Go
code, versioned with PatchFlow releases, and tested via fixtures.

## Architecture

```
internal/frameworks/          # framework detection (signals, detector)
internal/sast/frameworks/     # framework rule model, registry, loader, matcher
  rails/                      # reference pack
    pack.go, sources.go, sinks.go, sanitizers.go, templates.go, rules.go
    tests/                    # vulnerable/safe/normal fixtures
```

## Pack contract

Every pack implements `frameworks.Pack`:

- `Name()` — canonical framework name (matches `frameworks.Name`)
- `Language()` — primary language
- `FileExtensions()` — source file extensions owned by the pack
- `TemplateExtensions()` — template extensions owned by the pack
- `Rules()` — typed `FrameworkRule` set
- `Sources()` / `Sinks()` / `Sanitizers()` — taint catalogs

## Rule model

A `FrameworkRule` declares:

- `MatchMode`: `pattern`, `ast`, `taint`, or `template`
- `FileTypes` / `TemplateTypes`: which files the rule applies to
- `Pattern`: regex for `pattern`/`template` rules
- `Sources` / `Sinks` / `Sanitizers`: taint catalogs for `taint` rules
- `SafePatterns`: regexes that mark a would-be match as safe
- `Exclusions`: path globs to skip
- `Maturity`: governance maturity (experimental/beta/stable/enterprise)

## Match flow

```
1. Detect frameworks (internal/frameworks.Detector)
2. Select packs (frameworks.Loader) based on detection + config
3. Pattern/template rules -> frameworks.Matcher (line-oriented)
4. Taint rules -> registered into the taintpatterns engine
5. Findings deduplicated by the SAST runner
```

## Adding a pack

1. Create `internal/sast/frameworks/<name>/` with pack.go, sources.go,
   sinks.go, sanitizers.go, templates.go, rules.go.
2. Register the pack in `default_registry.go`.
3. Add detection signals in `internal/frameworks/signatures.go`.
4. Add vulnerable/safe/normal fixtures under `tests/`.
5. Set `Maturity: MaturityExperimental` until fixtures pass.

## User YAML

User YAML extends (not replaces) official packs. Custom sources/sinks/
sanitizers and severity overrides are merged on top of the embedded pack.
This keeps PatchFlow as the source of truth for framework security
intelligence while letting customers encode internal app semantics.
