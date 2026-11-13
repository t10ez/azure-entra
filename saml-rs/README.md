# Entra SAML callback API (dev, Rust / axum)

SAML 2.0 SP for Microsoft Entra ID on `http://localhost:4000`.

| Start | Entra sends the browser to | Validated by |
|---|---|---|
| `/saml/login?login_hint=<email>` | `POST /auth/saml/acs` (SAMLResponse) | `samael` + xmlsec1: Assertion signature (RSA-SHA256), issuer, audience, time window, Recipient, InResponseTo (one use, so replays fail) |

Also `GET /saml/metadata` (SP metadata). The ACS answers with JSON: `arrived` (body + headers, SAMLResponse masked),
`ok`, NameID + attributes or the error, and the decoded SAML XML.

## Run

```sh
brew install libxmlsec1 libxml2 libxslt pkgconf   # see .cargo/config.toml
cp .env.example .env   # TENANT_ID, SAML_ENTITY_ID, ENTRA_SAML_CERT or SAML_IDP_METADATA_URL
cargo run
```

Entra Enterprise app > Single sign-on > SAML: Identifier = `SAML_ENTITY_ID`, Reply URL `http://localhost:4000/auth/saml/acs`.

Build from this folder so `.cargo/config.toml` applies. If the binary links macOS's `/usr/lib/libxml2`,
every response fails with "must be signed" (fails closed).

Not for production: no session, request IDs in process memory, plain http, JSON output exposes claims.
