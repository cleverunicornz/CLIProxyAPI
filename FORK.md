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
