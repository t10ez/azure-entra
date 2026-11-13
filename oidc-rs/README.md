# Entra OIDC callback API (dev, Rust / axum)

Authorization code + PKCE against Microsoft Entra ID on `http://localhost:4000`.

| Start | Entra sends the browser to | Validated by |
|---|---|---|
| `/oidc/login?login_hint=<email>` | `GET /auth/callback?code&state` | `openidconnect`: state (one use), PKCE, token exchange, ID token signature / iss / aud / exp / nonce |

Same logic and JSON as the OIDC half of `../oidc/server.mjs`: `arrived` (query + headers, code masked), `ok`,
`tokenType`, `scopes`, `expiresOn`, `idTokenClaims` (full, incl. `roles` / `groups`), or `error` + `description`.
Without CLIENT_ID / CLIENT_SECRET the server still starts and `/oidc/login` answers 503; discovery runs on first login.

## Run

```sh
cp .env.example .env   # TENANT_ID (GUID), CLIENT_ID, CLIENT_SECRET
cargo run
```

Entra App registration: platform Web, Redirect URI `http://localhost:4000/auth/callback`.

Not for production: no session, state in process memory, plain http, JSON output exposes claims.
