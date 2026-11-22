# security-update-labs
Reusable codebase with helpers for managing the sea of security updates you're all receiving, like me! I've started with GitHub Copilot but I'm going to add more features along the way. Initially Windows users primarily - my hope is this is setup for even the more junior of programmers to find easy to use!

## Defence Desk

A colourful, local-first security orchestrator: turn GitHub security emails into a
prioritised inbox, verify them against Dependabot, and approve remediation through
trusted GitHub Actions workflows. No third-party packages are required.

### Run locally

Install [Node.js 22 or newer](https://nodejs.org/), then in this repository run:

```sh
npm start
```

Open **http://127.0.0.1:8787** (use this address, not `localhost`). Paste one security
email at a time. GitHub Dependabot links become deduplicated alert references;
emails without links remain unclassified. Severity inferred from email text is
unverified. Use the search, severity and status filters, then view each alert's
step-by-step remediation plan. Marking an item reviewed only changes local triage;
it does not dismiss an alert or make the vulnerability safe.

The app binds only to loopback, protects writes with a per-session request token,
and stores normalized alerts and local review status in `.local/alerts.json`.
The raw email body is not saved or uploaded, but the first nonempty line is saved
as the title: remove sensitive details before importing. Local storage is not
encrypted; do not run this on a shared or untrusted machine. Close the process
with Ctrl+C; delete `.local` to reset your workspace.

Only one process may use the workspace at a time, even on a different port.
Normal shutdown releases `.local/workspace.lock`. After a forced termination,
confirm the old process is no longer running before manually removing that lock
file; never remove a live process's lock.

### Connect GitHub

Set environment variables **before** starting the server. Do not put tokens in
source code, pasted emails or the browser.

PowerShell (Windows):

```powershell
$env:GITHUB_REPOSITORIES = "owner/repository,owner/another-repository"
$env:GITHUB_TOKEN = Read-Host "GitHub token" -MaskInput
npm start
```

On macOS/Linux, export `GITHUB_REPOSITORIES` and `GITHUB_TOKEN` in your terminal.
Use a fine-grained token restricted to the listed repositories with **Dependabot
alerts: Read**. These alerts must be enabled and your account must have access.
The token stays server-side and is sent only to `api.github.com`.

Click **Sync GitHub** to fetch alerts from every configured repository, including
paginated results. Imported references become verified when GitHub returns the
matching alert. Fixed and dismissed alerts remain available in the status filter.
An unsuccessful sync leaves the previous snapshot intact. Sync is manual; emails
are not monitored and stale snapshots are not proof that you are secure.

### Approved remediation

This starter orchestrates **your existing, trusted remediation workflow**; it does
not invent GitHub fix APIs, execute email instructions, or install arbitrary code.
GitHub's [Dependabot alerts API](https://docs.github.com/en/rest/dependabot/alerts)
does not provide an endpoint to request a security-update PR. Enable Dependabot
security updates in each repository for GitHub's own automatic update PRs.

To dispatch your own agentic fix workflow:

1. Create/review a workflow in each target repository that accepts
   `workflow_dispatch` with a required string input named `alert_number`.
2. The workflow must retrieve that alert using GitHub's API, validate the affected
   package and patched version, update the dependency and lockfile on a new branch,
   run the repository's checks, and open a PR for human review. Treat repository
   and advisory content as untrusted; do not interpolate it into shell commands.
   The workflow implementation and its permissions are your responsibility.
3. Give the token **Actions: Read and write** as well as Dependabot alerts read
   access. Use least privilege for the workflow itself.
4. Set `GITHUB_REMEDIATION_WORKFLOW` to the workflow filename (for example,
   `security-remediation.yml`) and `GITHUB_REMEDIATION_REF` to a trusted branch or
   tag. The same filename/ref is used across the allowlisted repositories.
5. Sync, open a verified open alert's plan, check the approval box, then request
   the fix. The server checks the live alert before dispatching.

The integration uses the documented
[workflow dispatch endpoint](https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event).
A requested workflow is **not a verified fix**: inspect Actions, review the PR,
merge only after passing checks, and sync again to confirm GitHub reports `fixed`.
Repeated dispatches are blocked. If the network fails during dispatch,
or GitHub returns a server error or request timeout, the request is marked
uncertain and is not retried automatically. Check Actions before any
manual recovery; there is no retry button. An explicitly rejected request can be
approved again after correcting its configuration.

### Coverage and safety

- **Available now:** local email triage, live GitHub Dependabot sync, deterministic
  remediation plans and approval-gated workflow dispatch. No LLM service is called;
  agentic code changes are delegated to the workflow you configure.
- **Not implemented:** mailbox login/deletion, native Windows/macOS/Linux update
  execution, other platform APIs, automatic PR merging, backup management or
  verification of workflow results beyond Dependabot's reported state. Platform
  cards are explicitly marked unconnected rather than implying protection.
- No system can reduce risk to zero. Keep independent, isolated backups, test
  restoration, review changes, and avoid sharing backup credentials with agents.
- This is a single-user local tool, not an internet-facing service. Do not expose
  the port through a tunnel or reverse proxy. It has no remote authentication.

### Tests

```sh
npm test
```

Tests use Node's built-in test runner and mocked GitHub responses. No credentials
or external API calls are needed. Set `PORT` to a different port (1024–65535) if
8787 is already in use.
