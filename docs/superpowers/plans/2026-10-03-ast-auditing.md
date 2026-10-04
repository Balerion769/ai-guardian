# AST Auditing and Bounded Ollama Review Implementation Plan

**Goal:** Replace syntax-sensitive regex matching with parsed code rules, validate every model result, and bound review latency without exposing submitted code in logs.

**Architecture:** Extract added Git diff lines with their new-file locations. Parse Python with `ast`, JavaScript and TypeScript with tree-sitter, and inspect syntax nodes plus literal values. Keep static and semantic findings behind the existing API and deduplication boundary. Give Ollama one response attempt and at most three repair attempts inside a five-second total budget.

**Tech stack:** Python 3.11+, FastAPI, Pydantic v2, httpx, tree-sitter JavaScript and TypeScript grammars, esprima JavaScript fallback.

## Task 1: Parsed static rules

- Add one vulnerable and one safe case for each credential and unsafe-code rule in `tests/test_audit.py`.
- Replace `scanner/static_rules.py` with a diff-aware parser pipeline. Use `ast` for Python and tree-sitter for JavaScript/TypeScript; use esprima only when tree-sitter is unavailable for JavaScript.
- Benchmark a 200,000-character input against the 200 ms static budget.
- Update README Current limits and `docs/architecture.md`.

## Task 2: Ollama validation and latency

- Add mocked Ollama tests for invalid JSON, invalid schemas, repaired responses, exhausted retries, timeout, and no-code logging.
- Validate the Ollama envelope and every vulnerability through Pydantic. Retry malformed output three times with repair prompts.
- Cap the complete semantic stage at five seconds; return 503 on timeout. Log only input hash and counts.
- Update README Current limits and `docs/architecture.md`.

## Task 3: Final verification and commit

- Run the full test suite, compile checks, and the 200,000-character performance probe.
- Inspect all changes and check for raw input logging and regex use in syntax-aware rules.
- Update README Current limits and `docs/architecture.md` with measured behavior and remaining constraints.
- Create a conventional commit.
