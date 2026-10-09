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
The translator guard uses git rather than a third-party action.
No image or binary publication or deployment pipeline is established here;
the Releases section below adds binary releases later.
Since the v8.0.15 sync, the translator guard permits translator changes only
when every changed path's blob is byte-identical to fork `main`, so upstream
syncs pass and any fork-authored translator edit fails.

The AGENTS.md guard, `agents-md-guard.yml`, runs on `pull_request_target`.
GitHub runs `pull_request_target` workflows from the workflow file on the
default branch, whatever the pull request's base
([changelog](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/)).
The default branch is `main`, which tracks upstream, so pull requests into
`internal/main` get upstream's unchanged guard: it requests a GitHub-hosted
`ubuntu-latest` runner, and here its runs stay queued without starting. Had it
run, it would close every pull request that touches an AGENTS.md file. The
copy on `internal/main`, which uses an organization runner and passes
AGENTS.md changes byte-identical to fork `main`, is never run, and merging into
`internal/main` does not change that. The guard is not a required check on
`internal/main`, so the queued run does not block merges, and at present no
check closes a pull request that edits AGENTS.md.

## Claude logins through the management API

Fork-only, approved by the operator on 2026-10-09. A Claude login started with
`GET /v0/management/anthropic-auth-url` without `is_webui` uses Anthropic's
code page, `https://platform.claude.com/oauth/code/callback`, as its
`redirect_uri`. Upstream sends it to `http://localhost:54545/callback`, where
nothing listens when the proxy runs in the cluster. After sign-in the page
shows `code#state`. The v2 dashboard splits that and posts
`{provider: "anthropic", state, code}` to `POST /v0/management/oauth-callback`.
The session's code exchange sends the same `redirect_uri` and the session
state. A state with no pending session is refused before any exchange.

This is what Claude Code itself does on a remote machine. Read from
`@anthropic-ai/claude-code-linux-x64@2.1.295` on 2026-10-09: its
`MANUAL_REDIRECT_URL`, the same `CLIENT_ID` and `TOKEN_URL` as this fork, and
the same `redirect_uri` choice in the authorize URL and the token exchange.

The login with `is_webui=true`, which starts the local forwarder on 54545, and
the CLI login (`-claude-login`) keep the localhost redirect. The one decision
is in `RequestAnthropicToken`; `claude.GenerateAuthURL` and
`ExchangeCodeForTokens` are unchanged, and their `...WithRedirect` variants take
the redirect URI. Pull request CI proves the tests fail at the test-first commit
`04bc849836b5b2557630126e7204599abeb57c12`, then runs them, the Claude auth,
management handler and SDK auth packages, and the race checks.

## Releases

The fork publishes its own GitHub releases from `internal/main` through
`.github/workflows/internal-release.yml`.

Tags are `v<upstream version>-cvu.<n>`: the upstream release that
`internal/main` is synced to, then a fork counter that starts at 1 for each
upstream version and increases by one with every fork release on it. The first
release is `v8.0.15-cvu.1`. A sync to a newer upstream release restarts the
counter, for example `v8.0.16-cvu.1`. Tags are never reused or moved. The
workflow checks only the tag's form; the operator who dispatches it picks the
upstream version `internal/main` is synced to and the next unused counter.

Tags are created only by the `internal-release` workflow, never by hand: not
with `git push`, the web interface, or `gh release create` on a new tag. This
is a rule for maintainers; no repository setting enforces it. A tag ruleset
restricting all tag creation to the workflow is the operator's separate
decision, not part of this workflow. Whether GitHub accepts the GitHub
Actions app as a ruleset bypass actor in this organization is verified when
such a ruleset is applied. The workflow does not depend on one: it creates the
tag with its own `GITHUB_TOKEN`.

The rule exists because a tag push runs the workflow files of the tagged
commit. Upstream's `release.yaml` (any tag) and `docker-image.yml` (`v*`
tags) publish nothing here on commits that contain this section, because their
jobs run only in `router-for-me/CLIProxyAPI`. Every older commit still carries them without that
guard, and `release.yaml` there has `contents: write`, so a tag pushed onto an
older commit would start upstream's publication jobs on the fork.

Each release contains:

- `CLIProxyAPI_<version>_linux_amd64_no-plugin.tar.gz`, where `<version>` is
  the tag without its leading `v`, with the same files as upstream's archive
  (`cli-proxy-api`, `LICENSE`, `README.md`, `README_CN.md`,
  `config.example.yaml`). The binary is built like upstream's no-plugin one:
  Go 1.26.4, `CGO_ENABLED=0`, `-buildvcs=false`, statically linked, the same
  `-ldflags`. It does not support dynamic library plugins.
- `checksums.txt`, the SHA-256 of the archive in `sha256sum` format.

The archive is reproducible from its commit; `.github/scripts/internal-release-build.sh`
builds and verifies it. Unlike upstream's release build:

- the embedded model catalogs are the files committed under
  `internal/registry/models`; the build does not refresh them from
  `router-for-me/models`, and refuses to run when a tracked file differs from
  the commit;
- the build date is the commit time (`SOURCE_DATE_EPOCH`), and `-trimpath`
  keeps the build directory out of the binary;
- the tarball has fixed modes, every mtime set to the commit time, numeric
  owner `0:0`, a fixed member order and no extended headers, and gzip stores
  no file name or timestamp.

To rebuild a release, check out its commit and run
`RELEASE_TAG=<tag> GO_VERSION=1.26.4 bash .github/scripts/internal-release-build.sh release`
with Go 1.26.4 and GNU tar; `release/checksums.txt` matches the published one.

The binary embeds the version, the first seven characters of the source
commit and the build date, and prints them on startup as
`CLIProxyAPI Version: <version>, Commit: <commit>, BuiltAt: <date>`. The
release notes state the full source commit.

Every pull request into `internal/main` from a branch of this repository runs
the build twice, on two runners in two directories with separate build
caches, and requires identical checksums. Each build checks the archive
contents, that `checksums.txt` verifies the archive, that the binary has no
dynamic interpreter, and that it prints the expected version, commit and build
date. The archive is kept as the run's artifact; nothing is published. A pull
request from another repository's fork does not run the build (its jobs are
skipped).

To publish, run the `internal-release` workflow on `internal/main` with the
input `release_tag`, for example
`gh workflow run internal-release.yml --repo cleverunicornz/CLIProxyAPI --ref internal/main -f release_tag=v8.0.15-cvu.1`.
The run refuses any other ref and a tag outside the scheme. Both builds and
the checks above must pass. The publish job then creates the tag through the
API on exactly the built commit; creating an existing tag fails, so of two
concurrent publishes only one creates it, and publishes run one at a time.
Any error while looking up or creating the tag stops the run. If the tag
already exists, the run continues only when it points at the built commit and
has no release yet (a retry after an interrupted publish); a tag on another
commit, or an existing release, stops it. A dispatch without `release_tag`
only builds.

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
| `agents-md-guard.yml` | `pull_request_target` | GitHub-hosted `ubuntu-latest`; runs stay queued | Runs from the default branch `main`, so upstream's unchanged file applies and the `internal/main` copy is never run (see above). Its fixed GitHub API script lists changed filenames and closes, with a comment, any PR that touches an AGENTS.md path. No checkout, PR files, downloaded artifacts, shell commands, dynamic evaluation or PR-head execution. PR metadata is only data. Write permissions are limited to issues and pull requests. Not a required check. |
| `auto-retarget-main-pr-to-dev.yml` | `pull_request_target`, base `main` | GitHub-hosted | Unmodified fixed API script; no checkout or PR-head execution. Does not target `internal/main`. |
| `docker-image.yml` | `v*` tag push | GitHub-hosted | Upstream publication workflow. Every job that does not depend on another runs only when the repository is `router-for-me/CLIProxyAPI`, so a tag on a commit with this guard publishes nothing; older commits lack it (see Releases). Never moved to organization runners. |
| `release.yaml` | any tag push | GitHub-hosted platform matrix | Upstream publication workflow under the same repository guard on `prepare-release` and `publish-checksums`; the build jobs need `prepare-release` and are skipped with it. Older commits lack the guard (see Releases). Never moved to organization runners. |
| `internal-release.yml` | `pull_request`, base `internal/main`; `workflow_dispatch` | `ci` / `build-native` for the two builds, `ci` / `automation-test-s` for the comparison, tag tests and publication | Builds the release archive twice and compares checksums, with read-only contents permission; same-repository PR heads only. Only the publish job, which runs only on a dispatch with `release_tag`, has `contents: write`. See Releases. |

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
