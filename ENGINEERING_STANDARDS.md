# Engineering Standards

## General Principles

- Readability over cleverness
- Simplicity over abstraction
- Explicit over implicit
- Deterministic over magical

## Git Standards

Branch Naming:
- feat/*
- fix/*
- chore/*
- refactor/*
- docs/*

Commit Convention:
- feat:
- fix:
- refactor:
- docs:
- test:
- chore:

## Go Standards

- Use cobra for CLI commands
- Structured logging with zap
- Context propagation mandatory
- Error wrapping required
- Unit tests for business logic

## Python Standards

- Type hints required
- Pydantic for schemas
- SQLAlchemy for persistence
- Async where appropriate

## API Standards

- Versioned APIs
- OpenAPI documentation
- Consistent error contracts

## Testing

Minimum Expectations:
- Unit tests
- Integration tests
- Security tests

Coverage Target:
- Critical paths >90%
- Core business logic >80%

## Observability

Required:
- Structured logs
- Metrics
- Traces
- Audit logs

## Security

Never:
- Log secrets
- Store plaintext credentials
- Trust AI output directly

Always:
- Validate inputs
- Verify permissions
- Encrypt sensitive data
