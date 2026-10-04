# AI Guardian GitHub Action

The repository root `action.yml` is the published entry point for `uses: Balerion769/ai-guardian@v1`. The nested `.github/actions/ai-guardian/action.yml` supports a local action path. Both run the same `audit_pr.py` script. The `v1` tag must be created and pushed after this change is merged before consumers can use the remote reference; this task does not publish a release.

## Copyable workflow

Copy [the example workflow](../.github/workflows/ai-guardian.yml) into the consuming repository. It checks out full history, sets up Python 3.11, and grants `contents: read` plus `pull-requests: write`. The Action runs on `pull_request` and uses static analysis by default in the example. GitHub requires `fetch-depth: 0` so `origin/<base>...HEAD` is available.

```yaml
name: AI Guardian PR audit
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
  pull-requests: write
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - uses: Balerion769/ai-guardian@v1
        with:
          fail_on_high: 'true'
          use_static_only: 'true'
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

For a local copy of the action folder, replace the final `uses` value with `./.github/actions/ai-guardian`. The Action's Python code and dependencies must come from a trusted revision. It treats the checked-out PR files as data and never imports code from that checkout.

## Inputs and result

| Input | Default | Effect |
| --- | --- | --- |
| `fail_on_high` | `true` | Exit 1 when any HIGH finding exists. |
| `api_url` | `http://localhost:8000/api/v1/audit` | Send each changed file's diff to this endpoint when semantic mode is enabled. A remote URL sends source outside the runner. |
| `use_static_only` | `false` | Skip HTTP and run the trusted static analyzer and Python taint pass directly. |
| `model` | `qwen2.5-coder` | Require the API response's `model_used` to match this model; a mismatch falls back to static analysis. |

The action gets `git diff origin/$GITHUB_BASE_REF...HEAD --no-ext-diff` on PR runs. Without a base ref it compares `HEAD~1..HEAD`. It splits changes by file, ignores deleted and binary-only entries, and audits supported source files. Files larger than 200,000 characters or 2,000 added lines produce a HIGH `Analysis Incomplete` finding. If the API is unreachable, returns an error, or responds with invalid data, the action uses local static analysis. Unsupported code languages produce HIGH `Analysis Incomplete` when static analysis is the only available path; non-code files are skipped.

The runner prints a Markdown table and, when `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, and PR event data are present, posts the same table to the PR timeline through GitHub's [issue comments endpoint](https://docs.github.com/en/rest/issues/comments?apiVersion=2022-11-28). The table includes file, line, severity, category, and fixed generic guidance. It omits source snippets and model-provided descriptions/remediation, redacts credential-shaped file names, and caps display at 100 rows. A comment failure does not override the security exit code; inspect the runner warning and token permissions.

GitHub makes the `GITHUB_TOKEN` read-only for ordinary `pull_request` workflows from forks, so those runs can scan and fail the job but cannot post a PR comment unless the repository supplies a separate approved comment mechanism. This example deliberately avoids `pull_request_target` with untrusted PR code. See GitHub's [fork token rules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) and [security guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).

## Semantic mode

Set `use_static_only: 'false'` after starting a trusted AIGuardian API and Ollama on the same runner. Configure that API's `OLLAMA_MODEL` to the same value as the Action's `model` input. The Action does not install or start Ollama or the API. If the service or model is unavailable, it falls back to static findings. Do not start the API from a checked-out untrusted PR revision; run it from a trusted release. The backend limits Ollama analysis to five seconds, so cold or large models may leave an incomplete semantic review.

## Local dry run

In PowerShell, create a dummy patch and run the same script without GitHub credentials:

```powershell
@'
diff --git a/src/example.py b/src/example.py
--- a/src/example.py
+++ b/src/example.py
@@ -0,0 +1 @@
+eval(user_input)
'@ | Set-Content -Path .\sample.diff
.\.venv\Scripts\python.exe .\.github\actions\ai-guardian\audit_pr.py --diff-file .\sample.diff --use-static-only true --fail-on-high true --dry-run
```

The script prints a row for `src/example.py`, `Line 1`, and `HIGH`, then exits with code 1. It does not post a comment in dry-run mode. To test a clean file, change the added line to `+print("hello")`; the exit code becomes 0.

Run the automated suite with `python -m pytest tests/test_github_action.py -q`. The tests mock the API and GitHub comment request; they never post to a real PR.
