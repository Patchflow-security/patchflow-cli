# Framework Coverage Matrix — framework-rules-v1

**Date:** 2026-07-03  
**Total packs:** 18  
**Total framework rules:** 132

## Coverage Matrix

| Pack | Language | Rules | Taint | Pattern | Template | Sources | Sinks | Sanitizers | Blocking | Maturity |
|------|----------|-------|-------|---------|----------|---------|-------|------------|----------|----------|
| spring | java | 31 | 10 | 1 | 0 | 6 | 8 | 4 | 0 | beta |
| rails | ruby | 15 | 0 | 13 | 2 | 5 | 7 | 3 | 0 | beta |
| express | javascript | 9 | 0 | 5 | 4 | 6 | 7 | 3 | 0 | beta |
| fastapi | python | 9 | 2 | 7 | 0 | 11 | 15 | 5 | 0 | experimental |
| flask | python | 9 | 2 | 7 | 0 | 9 | 14 | 6 | 0 | beta |
| aspnet | csharp | 8 | 0 | 6 | 2 | 5 | 6 | 3 | 0 | beta |
| django | python | 7 | 0 | 5 | 2 | 9 | 4 | 3 | 0 | beta |
| laravel | php | 6 | 0 | 4 | 2 | 4 | 5 | 2 | 0 | beta |
| angular | typescript | 5 | 2 | 2 | 1 | 25 | 13 | 7 | 0 | beta |
| graphql | python | 5 | 3 | 2 | 0 | 9 | 11 | 9 | 0 | beta |
| gin | go | 4 | 0 | 2 | 2 | 3 | 4 | 2 | 0 | beta |
| nestjs | typescript | 4 | 0 | 2 | 2 | 4 | 5 | 2 | 0 | beta |
| nextjs | javascript | 4 | 0 | 2 | 2 | 4 | 5 | 2 | 0 | beta |
| react | javascript | 4 | 0 | 2 | 2 | 4 | 5 | 2 | 0 | beta |
| spring-security | java | 4 | 0 | 4 | 0 | 0 | 0 | 0 | 0 | beta |
| echo | go | 3 | 0 | 1 | 2 | 3 | 4 | 2 | 0 | beta |
| symfony | php | 3 | 0 | 1 | 2 | 4 | 5 | 2 | 0 | beta |
| razor | csharp | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 0 | beta |

## Detection Signals

| Pack | MinSignals | Key Signals |
|------|------------|-------------|
| spring | 2 | pom.xml (spring-boot), build.gradle, application.yml |
| rails | 2 | Gemfile (rails), config/routes.rb |
| express | 2 | package.json ("express") |
| fastapi | 2 | requirements.txt (fastapi), pyproject.toml |
| flask | 2 | requirements.txt (flask), pyproject.toml |
| aspnet | 2 | *.csproj, Program.cs, Startup.cs |
| django | 2 | manage.py, settings.py, urls.py |
| laravel | 2 | composer.json (laravel), artisan |
| angular | 2 | package.json (@angular/core), angular.json |
| graphql | 1 | requirements.txt (graphene/ariadne/strawberry), .graphql files |
| gin | 2 | go.mod (gin-gonic/gin) |
| nestjs | 2 | package.json (@nestjs/core) |
| nextjs | 2 | package.json (next) |
| react | 2 | package.json ("react"), src/**/*.jsx |
| spring-security | 2 | pom.xml (spring-security), SecurityConfig.java |
| echo | 2 | go.mod (labstack/echo) |
| symfony | 2 | composer.json (symfony) |
| razor | 2 | *.cshtml, _ViewImports.cshtml |

## Source-to-Sink Taint Coverage

| Pack | Source Model | Key Sinks | Taint Rules |
|------|-------------|-----------|-------------|
| spring | @RequestParam, @PathVariable, @RequestBody, @RequestHeader, @CookieValue, @ModelAttribute | execute, query, createQuery, RestTemplate | TP-JAVA001-010 |
| graphql | resolver args (resolve_*, mutate), info.context, info.variable_values | text, execute, requests/httpx, open, send_file | PF-GRAPHQL-SQLI-001, SSRF-001, PATH-001 |
| angular | route.queryParams, route.snapshot.*, FormControl.value, @Input, ElementRef.nativeElement | bypassSecurityTrust*, innerHTML, navigateByUrl | PF-ANGULAR-XSS-003, REDIRECT-002 |
| flask | request.args, request.form, request.json, request.files, request.data | text, execute, requests/httpx, send_file, open | PF-FLASK-SQLI-002, SSRF-002 |
| fastapi | request.query_params, request.path_params, Query, Path, Body | execute, text, RedirectResponse, subprocess | PF-FASTAPI-SQLI-002, REDIRECT-002 |
| express | req.query, req.body, req.params, req.headers, req.cookies | query, execute, eval, exec, redirect | (via TP-JS* rules) |
| django | request.GET, request.POST, request.headers, request.json | execute, executemany, text | (via TP-PY* rules) |

## Known Limitations by Pack

| Pack | Limitation |
|------|-----------|
| spring | Annotation source model requires tree-sitter Java parsing; multi-line SQL may be missed |
| graphql | AUTH/IDOR heuristic requires manual review; DoS rule only checks schema creation line |
| angular | MatchTaint rules are experimental; Angular interpolation {{ }} is safe by default |
| flask | Pattern rules check single lines; SSTI rule may flag test files |
| fastapi | AUTH rule is heuristic; auth via router-level dependencies may not be detected |
| express | Pattern rules are line-oriented; multi-line flows require taint tracking |
| django | ORM raw queries via .raw() may not be detected; conservative GraphQL detection |
| rails | Ruby source model is pattern-based, not AST-based |
| react | Template rules focus on dangerouslySetInnerHTML; hook-based sources not modeled |
