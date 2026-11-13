# Entra callback API (dev)

One Express server on `http://localhost:4000` that receives Microsoft Entra ID sign-ins and validates them for real:

| Protocol | Start | Entra sends the browser to | Validated by |
|---|---|---|---|
| OIDC (code + PKCE) | `/oidc/login?login_hint=<email>` | `GET /auth/callback?code&state` | `@azure/msal-node`: state, PKCE, token exchange, ID token signature / iss / aud / exp / nonce |
| SAML 2.0 | `/saml/login?login_hint=<email>` | `POST /auth/saml/acs` (SAMLResponse) | `@node-saml/node-saml`: Assertion signature, audience, time window, InResponseTo, replay; Recipient checked in `server.mjs` |

Each callback answers with JSON: `arrived` (what the browser delivered: query/body/headers, code and SAMLResponse masked),
`ok`, and either the ID token claims / SAML attributes or the error.

## Run

1. Set up Entra (tenant, test users, App registration for OIDC, Enterprise app for SAML) as in the setup guide.
2. `cp .env.example .env` and fill it in. Leave the OIDC or SAML values empty to switch that half off.
3. `npm install && npm start`, open http://localhost:4000, type a test user's email, pick OIDC or SAML.

Other: `GET /saml/metadata` (SP metadata to upload to Entra).

## Not for production

No session (the callback just shows the result), state / request IDs kept in process memory, plain http,
JSON output exposes claims. Use a session store, HTTPS and a secrets manager before using this pattern for real.
