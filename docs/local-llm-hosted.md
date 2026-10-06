# Hosted audits with local Ollama

The hosted API can use an authenticated HTTPS bridge on a developer machine.
Ollama stays on loopback port 11434. A separate bridge exposes only bounded,
non-streaming generation for one configured model; model listing, pulls, and
management endpoints are not available. It requires a bearer secret of at least
32 characters, forces deterministic generation, and keeps the five-second
scanner deadline. LLM results still pass the scanner's strict Pydantic schema.

## Local bridge

Install the project's Python requirements. Start Ollama and load your chosen
model before sending audits. Configure these environment values locally:

```text
OLLAMA_BRIDGE_TOKEN=<random secret of at least 32 characters>
OLLAMA_BRIDGE_MODEL=qwen2.5-coder:1.5b
```

Start the bridge in the repository root:

```powershell
.\.venv\Scripts\python.exe -m uvicorn scanner.ollama_bridge:create_bridge --factory --host 127.0.0.1 --port 11435 --no-access-log
```

Use a TLS tunnel to **the bridge on 11435**, never raw Ollama on 11434. The
tunnel provider relays code diffs and may inspect their plaintext. Use a named
tunnel and stable hostname for production. Cloudflare Quick Tunnels are only
for temporary testing; their hostnames change on restart and they have no
uptime guarantee. Do not disable TLS verification or put the bearer secret in
a URL. Keep secret values out of Git and chat.

On Windows, `scripts/start-local-llm.ps1` starts both helpers in hidden windows,
after the model is installed and the vendor's `cloudflared.exe` is present at
`%LOCALAPPDATA%\AIGuardian\bin\cloudflared.exe`. It creates a user-restricted
credential file and records helper PIDs in that directory. Use those PID files
to stop the helpers with `Stop-Process`; verify the processes still refer to
these helpers before stopping them. The tunnel log contains the temporary
hostname. On restart, update Render's `OLLAMA_URL` to the new hostname.

## Render environment

Configure the API service with:

```text
INLINE_AUDITS=1
STATIC_ONLY_MODE=0
OLLAMA_URL=https://<bridge-hostname>/api/generate
OLLAMA_MODEL=qwen2.5-coder:1.5b
OLLAMA_API_KEY=<the same OLLAMA_BRIDGE_TOKEN>
```

`INLINE_AUDITS` controls job execution independently of LLM mode, allowing the
free web service to run both analysis engines without Redis. PR events are
acknowledged before post-response work. API-key audits run inside their request.
The bridge must remain running and the computer must stay awake. A machine or
tunnel outage causes static-only fallback with an explicit incomplete semantic
review summary. A configured model name in `/health` proves configuration,
not a successful inference call; inspect a real completed audit to verify it.

Large inputs and slow or cold models may exceed the five-second deadline. The
bridge does not make model findings authoritative; manually review findings and
remediations. Small models trade inference speed for semantic coverage.
