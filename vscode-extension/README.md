# AI Guardian - Local Security

AI Guardian shows security findings in the VS Code Problems panel for Python, JavaScript, and TypeScript. It sends the current file, or a 200-line window around the visible area of a large file, to the local AIGuardian API. The default URL is `http://localhost:8000/api/v1/audit`. The API runs static analysis and, when available, local Ollama review.

If the API is unavailable, the extension runs five limited checks inside VS Code: Python `eval()`, Python `exec()`, hardcoded password assignments, AWS access key IDs, and JavaScript/TypeScript `innerHTML` assignments. The status bar says **offline** when this happens. These checks are heuristic and may flag text in strings or miss vulnerabilities.

## Install from this checkout

1. Start the Python API from the repository root: `python -m uvicorn main:app --host 127.0.0.1 --port 8000`. Ollama is optional for static findings.
2. In `vscode-extension`, run `npm install` and `npm run compile`.
3. Open `vscode-extension` in VS Code and press **F5**. The included launch configuration compiles TypeScript and opens an Extension Development Host. Open a Python, JavaScript, or TypeScript file there.
4. Save the file, or run **AI Guardian: Audit Current File** from the Command Palette. Select the shield in the status bar to run the same command.
5. Open **View → Problems** to see findings. For supported offline findings, place the cursor on the highlighted code and use **Quick Fix** (`Ctrl+.` on Windows/Linux).

To package for local installation, run `npx @vscode/vsce package` in `vscode-extension`, then use **Extensions: Install from VSIX...** in VS Code. Packaging compiles TypeScript through `vscode:prepublish`.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `aiGuardian.apiUrl` | `http://localhost:8000/api/v1/audit` | Endpoint for full analysis. A remote URL sends source code to that server. |
| `aiGuardian.runOnSave` | `true` | Audit after saving. |
| `aiGuardian.runOnType` | `false` | Audit after a 750 ms typing pause. |

Files over 200,000 characters are skipped. Files of 500 lines or more send only a 200-line window; findings elsewhere in those files are not shown until that area is viewed and audited. The offline checks are a fallback, not an equivalent replacement for the backend. Two API or offline patterns offer quick fixes. The `ast.literal_eval` quick fix is appropriate only when the expression is intended to parse a Python literal. Rotating leaked credentials and reviewing other remediation steps remain manual.

## Demo GIF for the Marketplace

Record a short GIF in the Extension Development Host: open a sample Python file with `eval(user_input)`, save it, show the Problems panel, then place the cursor on the finding and open Quick Fix. Keep the recording free of real tokens or private source. Save it as `media/demo.gif` and add `![AI Guardian diagnostics demo](media/demo.gif)` near the top of this README before publishing. The GIF is intentionally not checked in because this repository has no captured editor session to show.

## Verify

Run `npm test`. It compiles the extension and checks vulnerable and safe examples for all five offline rules. The API integration needs the Python server and a VS Code Extension Development Host.
