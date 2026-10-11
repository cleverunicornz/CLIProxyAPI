# Codex device login through the management API

Fork-only (`cleverunicornz/CLIProxyAPI`, `internal/main`), from the operator's
ruling of 2026-10-11 and infra-v2 invariant I-000026: every provider login runs
from the platform's interface by the provider's code flow, never by a pasted
localhost redirect address, a pod shell or a port-forward. infra-v2 G-000480
records the v2 dashboard's Codex login, which pasted a `localhost:1455`
address back, as violating it.

**The device code is the only Codex login through the management API.** The
browser login with the localhost redirect is removed from it; see
[Removed: the Codex browser login](#removed-the-codex-browser-login). The CLI
logins (`-codex-login`, `-codex-device-login`) are unchanged.

This document is the contract the v2 dashboard builds against. It changes
only by announcing the change to the dashboard side first.

## Flow

1. The client starts a login: `POST /v0/management/codex-device-login`.
   The gateway asks OpenAI for a device code and answers with the
   verification URL and the one-time user code.
2. The operator opens the URL, signs in, and enters the code.
3. Meanwhile the gateway polls OpenAI itself. When OpenAI issues the
   authorization code, the gateway exchanges it for tokens and stores the
   Codex auth exactly as the CLI device login (`-codex-device-login`) does.
4. The client polls `GET /v0/management/codex-device-login?state=<state>`
   until the status is no longer `pending`.
5. The client may cancel a pending login at any time with
   `DELETE /v0/management/oauth-session?state=<state>`.

## Authentication

Every route requires the management key, like every other
`/v0/management` route: `Authorization: Bearer <key>` or
`X-Management-Key: <key>`. Without a valid key the management middleware
answers as it does for the other routes (for example `401` with
`{"error": "..."}`), and nothing is started or disclosed.

## Start: `POST /v0/management/codex-device-login`

Request: no parameters. An empty body or `{}` is accepted; any body is
ignored.

`200 OK`:

```json
{
  "status": "ok",
  "flow": "device",
  "state": "codex-device-3f0c9a5e1b7d4c2a8e6f0b1d2c3a4e5f",
  "verification_uri": "https://auth.openai.com/codex/device",
  "url": "https://auth.openai.com/codex/device",
  "user_code": "ABCD-1234",
  "expires_in": 900,
  "expires_at": "2026-10-11T12:15:00Z"
}
```

| Field | Meaning |
|---|---|
| `state` | The login's id. Matches `^codex-device-[0-9a-f]{32}$`. Used for status and cancel. |
| `verification_uri` | The page the operator opens. Show it as a link. |
| `url` | The same value, for clients written against the xAI/Kimi device responses. |
| `user_code` | The one-time code the operator enters on that page. Show it. Do not log or audit it. |
| `expires_in` | Seconds until the login expires: 900 (15 minutes, the CLI's and OpenAI Codex CLI's limit). |
| `expires_at` | The same instant, RFC 3339, UTC. |

Errors:

| Status | Body | When |
|---|---|---|
| `502` | `{"status": "error", "error": "device_code_request_failed", "message": "<reason>"}` | OpenAI refused or did not answer the device-code request, or answered without a user code. `message` names at most OpenAI's HTTP status, for example `OpenAI refused the device-code request (HTTP 500)`; it never carries OpenAI's response body or transport detail. |
| `500` | `{"status": "error", "error": "internal_error"}` | The gateway could not create the login (for example, random state generation failed). |

Several logins may run at the same time. Each gets its own `state` and user
code; finishing, failing or cancelling one does not affect another.

## Status: `GET /v0/management/codex-device-login?state=<state>`

`200 OK` with one of five `status` values. `state` and `expires_at` are
always present.

Pending, waiting for the operator:

```json
{
  "state": "codex-device-…",
  "status": "pending",
  "verification_uri": "https://auth.openai.com/codex/device",
  "user_code": "ABCD-1234",
  "expires_at": "2026-10-11T12:15:00Z"
}
```

Done, the auth is stored:

```json
{
  "state": "codex-device-…",
  "status": "done",
  "expires_at": "2026-10-11T12:15:00Z",
  "account": {
    "email": "operator@example.com",
    "plan_type": "pro",
    "name": "codex-1a2b3c4d-operator@example.com-pro.json"
  }
}
```

`account.name` is the stored auth file's name, the same value as `name` in
`GET /v0/management/auth-files`. `plan_type` is the ChatGPT plan read from
the ID token (default `free`).

Failed:

```json
{
  "state": "codex-device-…",
  "status": "failed",
  "expires_at": "2026-10-11T12:15:00Z",
  "error": "provider_rejected",
  "message": "OpenAI ended the device login with status 400"
}
```

Expired:

```json
{
  "state": "codex-device-…",
  "status": "expired",
  "expires_at": "2026-10-11T12:15:00Z",
  "error": "expired",
  "message": "The device code expired before the login was completed"
}
```

Cancelled:

```json
{
  "state": "codex-device-…",
  "status": "cancelled",
  "expires_at": "2026-10-11T12:15:00Z"
}
```

`verification_uri` and `user_code` appear only while `pending`. `account`
appears only on `done`. `error` and `message` appear only on `failed` and
`expired`.

`error` codes on `failed`:

| `error` | When |
|---|---|
| `provider_rejected` | OpenAI's device-token poll ended the login: `access_denied`, or any other error than those the gateway keeps polling on. The gateway polls as RFC 8628 section 3.5 asks: `authorization_pending` (and OpenAI's pending `403`/`404`) continue; `slow_down` continues with the polling interval raised by 5 seconds; `expired_token` makes the login `expired`. A denial arrives as `access_denied` or another error, or as no answer until expiry. |
| `provider_unreachable` | The poll request to OpenAI failed at the network level. |
| `invalid_provider_response` | OpenAI answered success without the authorization code fields. |
| `exchange_failed` | Exchanging the authorization code for tokens failed. |
| `missing_account` | The tokens carry no account e-mail, so the auth cannot be named or stored. |
| `save_failed` | Storing the auth failed. |

`message` is human-readable, names at most an HTTP status, and never contains a code, a token or a provider response body.

Errors:

| Status | Body | When |
|---|---|---|
| `400` | `{"status": "error", "error": "missing_state"}` | No `state` parameter. |
| `400` | `{"status": "error", "error": "invalid_state"}` | `state` is malformed. |
| `404` | `{"status": "error", "error": "unknown_state"}` | No device login with this `state`: never started on this gateway, started before a gateway restart, or finished more than 15 minutes ago. |

### Retention

A pending login stays pending until it finishes, is cancelled, or reaches
`expires_at`, when it becomes `expired`. Expiry is exact: a request to OpenAI
still in flight at `expires_at` is abandoned, a confirmation arriving after it
is ignored and nothing is stored, and from `expires_at` on the status reads
`expired` without the user code. A login whose confirmation arrived before
`expires_at` and whose auth is being stored still reads `pending` until it is
`done`. A finished login (`done`,
`failed`, `expired`, `cancelled`) is reported for 15 minutes after it
finished, then answers `404 unknown_state`. Nothing survives a gateway
restart; a client polling across a restart gets `404 unknown_state` and
should report that the gateway lost the login.

Clients should poll every 2 to 5 seconds. The gateway's own polling of
OpenAI uses OpenAI's interval (default 5 seconds), so `done` can lag the
operator's confirmation by that much plus the token exchange.

## Cancel: `DELETE /v0/management/oauth-session?state=<state>`

The existing route. For a device login, `cancelled` is `true` exactly when the
cancel took effect, so a client reports a login as cancelled only on
`cancelled: true`. The answer depends on the login's status when the request
arrives:

| Status when `DELETE` arrives | Answer | Status afterwards |
|---|---|---|
| `pending`, OpenAI not yet confirmed | `200 {"status": "ok", "cancelled": true}` | `cancelled` at once. The gateway stops polling OpenAI and stores nothing, even if OpenAI confirms later. |
| `pending`, OpenAI confirmed before `expires_at` and the auth is being stored (a racing poll) | `200 {"status": "ok", "cancelled": true}` | `cancelled` at once. If the save completes anyway, the gateway removes the stored auth again; the login never becomes `done`. |
| `pending` but `expires_at` has passed | `200 {"status": "ok", "cancelled": false}` | `expired` (no user code). |
| `done` | `200 {"status": "ok", "cancelled": false}` | `done`; the stored auth stays. A cancel and a completion never both succeed: whichever the gateway records first wins. |
| `expired`, `failed` or `cancelled` | `200 {"status": "ok", "cancelled": false}` | unchanged. |
| no device login with this `state` (unknown, or forgotten after retention) | `200 {"status": "ok", "cancelled": false}` | `GET` answers `404 unknown_state`. |
| `state` missing or malformed | `400 {"status": "error", "error": "missing state"}` or `400 {"status": "error", "error": "invalid state"}` | — |

`cancelled: true` is final: `GET` reports `cancelled` from that answer on and
never changes again, and the account is not stored.

## Legacy status: `GET /v0/management/get-auth-status?state=<state>`

Also works for a device login, with the existing coarse answers: `pending` →
`{"status": "wait"}`; `done` → `{"status": "ok"}` for one minute after
completion; `failed` and `expired` → `{"status": "error", "error": "<message>"}`;
`cancelled`, or later, → `{"status": "error", "error": "unknown or expired state"}`.
New clients use the status route above.

## Never returned

No response, log line or error message carries:

- OpenAI's `device_auth_id` (the device code: with the user code it lets
  anyone poll for the authorization code);
- the authorization code, the PKCE `code_verifier` or `code_challenge`;
- the access, refresh or ID token, or an API key.

The `user_code` is returned only to the management-key holder, only while the
login is pending, and is not written to the gateway log.

## Storage

The stored auth is the one the CLI device login stores: provider `codex`, the
file name `codex.CredentialFileName(email, plan_type, hash(account_id), true)`,
metadata `email` and `plan_type`, attribute `plan_type`, the token storage
from the code exchange with `redirect_uri`
`https://auth.openai.com/deviceauth/callback`. It is saved through the
gateway's token store like every other management login, so it appears in
`GET /v0/management/auth-files` and is used by the gateway right away.

## Removed: the Codex browser login

Under I-000026 the gateway no longer serves the Codex browser login with the
`localhost:1455` redirect, through the management API or its callbacks. These
requests answer `410 Gone` before any other validation of the request,
start no session, start no callback forwarder, write nothing, and leave no
query string in the gateway's access log:

- `GET /v0/management/codex-auth-url`, with or without `is_webui`;
- `GET /v8/management/oauth/auth-url?provider=codex`;
- `POST` and `GET /v0/management/oauth-callback`, and the same under
  `/v8/management/oauth/callback`, when `provider` is `codex` or `openai`, or
  when `state` belongs to a Codex login (including a device login);
- `GET /codex/callback`.

Body:

```json
{
  "status": "error",
  "error": "codex_browser_login_removed",
  "message": "The Codex browser login is removed; use the device login.",
  "device_login": "POST /v0/management/codex-device-login"
}
```

`codex-auth-url` and `oauth/auth-url` stay behind the management key, so a
request without it still gets the middleware's `401` first. Other providers'
logins, including Claude's code-page login, are unchanged.
