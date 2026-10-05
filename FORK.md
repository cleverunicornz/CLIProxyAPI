# Organization fork

Upstream: https://github.com/router-for-me/CLIProxyAPI.
The fork's `main` tracks upstream and remains unchanged by internal work.
The working trunk is `internal/main`, initialized at v7.3.17,
`9bdde54b59d1af70ae0534a0ef61b2c3361a1257`, the source of the deployed
release. Pinning that release keeps the cache fix isolated from unrelated
changes on upstream main. Updating this baseline is a separate decision.

Internal changes use `internal/*` pull requests and merge commits.
Both trunks have branch protection with administrator enforcement, no force
pushes and no deletion. `internal/main` requires a pull request and the `build`
check against an up-to-date base, with zero required human approvals. `main`
requires a pull request with one maintainer approval. Organization rulesets
also require merge commits and prevent deletion and force pushes.
Upstream contributions use code-only `upstream/*` branches cut from `main`;
advancing `main` or opening the upstream contribution needs maintainer review.
Fork CI changes and this document stay in separate commits from code.

The default websocket tool output and call caches now use a one-hour session
idle TTL. Cache access refreshes last-seen time and lazily cleans up expired
sessions. Recent replay stays available; replay after more than one hour idle
may lose cache-only tool history. The change does not impose payload byte
limits, limit active sessions, or run background cleanup. Synthetic regression
results do not establish a production memory slope improvement.

Pull request CI proves the expected idle-expiry and retained-byte failures at
the test-first commit, then runs the fixed regressions, handler package tests,
race checks, formatting checks and a portable server build. All test data is
synthetic; CI needs no provider credentials or calls. The inherited catalog
refresh step is omitted so CI builds the pinned source bytes.
The translator guard uses git rather than a third-party action; the inherited
AGENTS guard moves to an organization runner after this initial PR lands.
No image or binary publication or deployment pipeline is established here.
Since the v8.0.15 sync, the translator guard permits translator changes only
when every changed path's blob is byte-identical to fork `main`, so upstream
syncs pass and any fork-authored translator edit fails. The AGENTS.md guard
permits AGENTS.md changes under the same verbatim-from-`main` rule, so
upstream syncs pass while local AGENTS.md edits are still closed.

## Public fork Actions controls

On 2026-10-04 the fork's Actions contributor approval policy was set to
`all_external_contributors` using the repository Actions settings API and
read back with the same value. All outside contributors require approval
before their fork pull request workflow code runs; maintainers inspect workflow
changes before approving. This setting is independent of branch merge approval.

| Workflow | Event | Runner | Execution boundary |
| --- | --- | --- | --- |
| `pr-test-build.yml` | `pull_request`, base `internal/main` | `ci` / `automation-test-s` | Executes same-repository PR merge checkouts only, with read-only contents permission. Never uses `pull_request_target`. Synthetic tests and compile only; no provider credentials. |
| `pr-path-guard.yml` | `pull_request`, base `internal/main` | `ci` / `automation-test-s` | Checks out same-repository PR merges only and compares changed `internal/translator` paths' blob identity against fork `main` with git. Never uses `pull_request_target`. SHAs enter through quoted environment variables. Read-only contents permission. |
| `agents-md-guard.yml` | `pull_request_target` | `ci` / `automation-test-s` after this PR | Fixed base-branch GitHub API script lists changed filenames, tests AGENTS paths, and passes AGENTS.md changes whose head blobs match fork `main` verbatim; other AGENTS.md changes get a comment and the PR is closed. No checkout, PR files, downloaded artifacts, shell commands, dynamic evaluation or PR-head execution. PR metadata is only data. Write permissions are limited to issues and pull requests. |
| `auto-retarget-main-pr-to-dev.yml` | `pull_request_target`, base `main` | GitHub-hosted | Unmodified fixed API script; no checkout or PR-head execution. Does not target `internal/main`. |
| `docker-image.yml` | tag push | GitHub-hosted | Unmodified upstream publication workflow; not triggered by this work and never moved to organization runners. |
| `release.yaml` | tag push | GitHub-hosted platform matrix | Unmodified upstream publication workflow; not triggered by this work and never moved to organization runners. |

The initial PR's AGENTS guard uses the inherited GitHub-hosted base version.
No organization-runner workflow checks out or executes PR-head code under
`pull_request_target`. Keep that boundary when adding future workflows.
PR jobs that check out code run on organization runners only when the head
repository is this fork. External fork heads are skipped even after contributor
approval; a maintainer brings accepted work onto an `internal/*` branch and
requires its actual passing CI before merging. Do not merge an external-head
PR on the strength of a skipped `build` check.

The reused lazy cleanup scans every session under the cache mutex on each
`record` and `get` (O(number of sessions) per access). Session count is not
bounded by the TTL policy, and continued access can keep sessions alive.
Revisit cleanup scheduling/indexing if measured session count or cache-lock
contention degrades request latency; include those observations in the future
staging/production gates. This change intentionally reuses the existing
algorithm rather than claiming a throughput improvement.

The test/fix commits remain separate from workflow and fork-documentation
commits; upstream cherry-picks contain the test and fix only.
