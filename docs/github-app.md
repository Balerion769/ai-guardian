# GitHub App setup

## Hosted account connection

The registered personal App is **AI Guardian Balerion769**: [Install the App](https://github.com/apps/ai-guardian-balerion769/installations/new). The older `ai-guardian` slug was a placeholder.

Set `GITHUB_APP_INSTALL_URL` in both API and Next.js deployments. Set the App setup URL to `https://ai-guardian-theta.vercel.app/dashboard/settings/github`. After installation, click **Connect installation to workspace**. The API verifies the installation with an App JWT and compares its account to the workspace owner or linked GitHub organization. The callback identifier alone never authorizes access.

On **Repositories**, click **Link GitHub repository** to browse paginated metadata using your OAuth access. App installation access is separate from OAuth login. Select all repositories on GitHub for installation access across your account, or individual repositories. Free allows three linked repositories and 100 audits per UTC day. Only active linked repositories trigger audits on PR `opened` and `synchronize`; granting access does not scan the entire historical codebase.

The repository contains the runtime integration, but creating an App requires access to a GitHub account. In GitHub Developer Settings create an App with:

`github-app-manifest.json` contains the same permissions and event defaults for the GitHub App Manifest flow; replace the example domains before using it.

- **Webhook URL:** `https://api.example.com/api/v1/webhooks/github`
- **Webhook secret:** the value of `GITHUB_APP_WEBHOOK_SECRET`
- **Repository permissions:** Contents: Read-only; Pull requests: Read and write; Checks: Read and write
- **Subscribe to events:** Pull request

Download the generated private key and set `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, and `GITHUB_APP_WEBHOOK_SECRET`. Set `GITHUB_APP_INSTALL_URL` to the App's installation URL and use the dashboard's **Install GitHub App** button. The webhook accepts only `opened` and `synchronize` pull request actions, verifies `X-Hub-Signature-256`, downloads the bounded diff with an installation token, and queues the tenant-scoped audit.

The worker creates a completed **AI Guardian** check run on the pull request head commit. The conclusion is `failure` when a HIGH finding is retained and `success` otherwise. Enable branch protection and require the `AI Guardian` check if a failing check should block merges.
