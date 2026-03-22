# Contributing

## Getting Started

1. Fork and clone the repo
2. `npm install`
3. `npm run build` to confirm clean compilation
4. `npm test` to confirm all tests pass

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Add or update tests — never reduce coverage
4. Run `npm test` to verify
5. Open a pull request

## Code Style

- **TypeScript strict mode** — no `any` unless absolutely necessary
- **Zod schemas** for all external input validation
- **Pure functions** preferred in services — side effects isolated to tool handlers
- **Error boundary** — all tool handlers wrap with `withErrorBoundary()`
- **Consistent naming** — kebab-case files, camelCase functions, PascalCase types

## Testing Requirements

- Every new tool must have integration tests
- Every new parser must have unit tests with real-world sample output
- Every new service function must have unit tests
- Tests must be deterministic — no network calls, no filesystem dependencies (use mocks)

## Adding Skills

Skills are markdown files in `skills/`. Follow this template:

```markdown
# Skill Name

tags: keyword1, keyword2, keyword3

## Objective
What this skill accomplishes.

## Prerequisites
What's needed before using this skill.

## Methodology
Step-by-step approach with exact commands.

## Reporting
What to report via report_finding.

## OPSEC Notes
Noise considerations and stealth alternatives.
```

Tags improve search ranking — use specific terms the LLM might search for.

## Commit Messages

Use conventional commits:

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `test:` — adding or updating tests
- `refactor:` — code restructuring without behavior change

## Pull Request Guidelines

- Keep PRs focused — one feature or fix per PR
- Include a clear description of what changed and why
- Reference any related issues
- Ensure CI passes (tests + build)
