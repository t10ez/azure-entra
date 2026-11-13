// Real Entra ID callback API for local testing: OIDC at /auth/callback, SAML at /auth/saml/acs.
// Each callback validates with the library and answers with JSON: what arrived + the validation result.
// DEV ONLY: http, no session, in-memory state.
import express from "express";
import { existsSync, readFileSync } from "node:fs";
import {
  ConfidentialClientApplication,
  CryptoProvider,
} from "@azure/msal-node";
import { SAML, ValidateInResponseTo } from "@node-saml/node-saml";

const env = process.env;
if (!env.TENANT_ID) {
  console.error("Missing TENANT_ID. Copy .env.example to .env and fill it in.");
  process.exit(1);
}
const PORT = Number(env.PORT || 4000);
const BASE = `http://localhost:${PORT}`;
const AUTHORITY = `https://login.microsoftonline.com/${env.TENANT_ID}`;

const app = express();

const mask = (v) =>
  typeof v === "string" && v.length > 16
    ? `${v.slice(0, 8)}…${v.slice(-4)} (len ${v.length})`
    : v;
const json = (res, status, body) =>
  res
    .status(status)
    .type("json")
    .send(JSON.stringify(body, null, 2));

// What the browser actually delivered to the callback.
function arrived(req, maskFields = []) {
  const pick = (o) =>
    Object.fromEntries(
      Object.entries(o ?? {}).map(([k, v]) => [
        k,
        maskFields.includes(k) ? mask(v) : v,
      ]),
    );
  const headers = Object.fromEntries(
    Object.entries(req.headers).filter(
      ([k]) =>
        ["host", "origin", "referer", "content-type", "cookie"].includes(k) ||
        k.startsWith("sec-fetch-"),
    ),
  );
  return {
    method: req.method,
    path: req.path,
    query: pick(req.query),
    body: req.body && pick(req.body),
    headers,
  };
}

// ---------- OIDC (authorization code + PKCE) ----------
const oidc =
  env.CLIENT_ID && env.CLIENT_SECRET
    ? new ConfidentialClientApplication({
        auth: {
          clientId: env.CLIENT_ID,
          clientSecret: env.CLIENT_SECRET,
          authority: AUTHORITY,
        },
      })
    : null;
const crypto = new CryptoProvider();
const SCOPES = ["openid", "profile", "email", "offline_access"];
const OIDC_REDIRECT = `${BASE}/auth/callback`;
// ponytail: state -> { verifier, nonce } in memory; lost on restart, single process only.
const pending = new Map();

app.get("/oidc/login", async (req, res, next) => {
  if (!oidc)
    return json(res, 503, {
      error: "OIDC not configured: set CLIENT_ID and CLIENT_SECRET",
    });
  try {
    const { verifier, challenge } = await crypto.generatePkceCodes();
    const state = crypto.createNewGuid();
    const nonce = crypto.createNewGuid();
    pending.set(state, { verifier, nonce });
    res.redirect(
      await oidc.getAuthCodeUrl({
        scopes: SCOPES,
        redirectUri: OIDC_REDIRECT,
        responseMode: "query",
        loginHint: req.query.login_hint || undefined,
        state,
        nonce,
        codeChallenge: challenge,
        codeChallengeMethod: "S256",
      }),
    );
  } catch (e) {
    next(e);
  }
});

app.get("/auth/callback", async (req, res) => {
  console.log(req);
  const seen = arrived(req, ["code"]);
  if (req.query.error)
    return json(res, 400, {
      ok: false,
      arrived: seen,
      error: req.query.error,
      description: req.query.error_description,
    });

  const p = pending.get(req.query.state);
  pending.delete(req.query.state); // one use only
  if (!p)
    return json(res, 400, {
      ok: false,
      arrived: seen,
      error: "invalid_state",
      description: "Unknown or already used state. Start again at /oidc/login.",
    });

  try {
    const r = await oidc.acquireTokenByCode({
      code: req.query.code,
      scopes: SCOPES,
      redirectUri: OIDC_REDIRECT,
      codeVerifier: p.verifier,
      nonce: p.nonce,
      state: req.query.state, // MSAL v7 needs nonce or rejects the ID token
    });
    const out = {
      ok: true,
      arrived: seen,
      tokenType: r.tokenType,
      scopes: r.scopes,
      expiresOn: r.expiresOn,
      idTokenClaims: r.idTokenClaims,
    };
    console.log(
      "[oidc] signed in",
      r.idTokenClaims.preferred_username,
      "roles",
      r.idTokenClaims.roles ?? [],
    );
    json(res, 200, out);
  } catch (e) {
    console.error("[oidc]", e.errorCode, e.message);
    json(res, 400, {
      ok: false,
      arrived: seen,
      error: e.errorCode || e.name,
      description: e.errorMessage || e.message,
    });
  }
});

// ---------- SAML 2.0 ----------
const SAML_ACS = `${BASE}/auth/saml/acs`;

async function loadIdpCert() {
  if (env.SAML_IDP_METADATA_URL) {
    const xml = await (await fetch(env.SAML_IDP_METADATA_URL)).text();
    return [
      ...new Set(
        [...xml.matchAll(/<(?:\w+:)?X509Certificate>([^<]+)</g)].map((m) =>
          m[1].replace(/\s+/g, ""),
        ),
      ),
    ];
  }
  const v = env.ENTRA_SAML_CERT;
  return (existsSync(v) ? readFileSync(v, "utf8") : v).replace(
    /-----(BEGIN|END) CERTIFICATE-----|\s+/g,
    "",
  );
}

const saml =
  env.SAML_ENTITY_ID && (env.ENTRA_SAML_CERT || env.SAML_IDP_METADATA_URL)
    ? new SAML({
        entryPoint: `${AUTHORITY}/saml2`,
        issuer: env.SAML_ENTITY_ID,
        audience: env.SAML_ENTITY_ID,
        callbackUrl: SAML_ACS,
        idpCert: await loadIdpCert(),
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: false, // Entra signs the Assertion by default, not the Response
        validateInResponseTo: ValidateInResponseTo.always, // request IDs live in node-saml's in-memory cache
        rejectReplayedAssertions: true,
        acceptedClockSkewMs: 5 * 60 * 1000,
        disableRequestedAuthnContext: true, // otherwise MFA / passwordless sign-ins fail with AADSTS75011
      })
    : null;

app.get("/saml/login", async (req, res, next) => {
  if (!saml)
    return json(res, 503, {
      error:
        "SAML not configured: set SAML_ENTITY_ID and ENTRA_SAML_CERT (or SAML_IDP_METADATA_URL)",
    });
  try {
    const hint = req.query.login_hint;
    res.redirect(
      await saml.getAuthorizeUrlAsync("/", {
        additionalParams: hint ? { login_hint: hint } : {},
      }),
    );
  } catch (e) {
    next(e);
  }
});

app.post(
  "/auth/saml/acs",
  express.urlencoded({ extended: false, limit: "1mb" }),
  async (req, res) => {
    const seen = arrived(req, ["SAMLResponse"]);
    if (!saml)
      return json(res, 503, {
        ok: false,
        arrived: seen,
        error: "SAML not configured",
      });
    const xml = Buffer.from(
      String(req.body?.SAMLResponse ?? ""),
      "base64",
    ).toString("utf8");
    try {
      const { profile } = await saml.validatePostResponseAsync(req.body ?? {});
      if (!profile) throw new Error("SAML response has no assertion");
      // node-saml 5.x only logs a wrong Recipient; enforce it on the verified assertion.
      const recipients = [
        ...profile.getAssertionXml().matchAll(/Recipient="([^"]+)"/g),
      ].map((m) => m[1]);
      if (!recipients.includes(SAML_ACS))
        throw new Error(
          `Recipient mismatch. Expected ${SAML_ACS}, got ${recipients.join(", ") || "none"}`,
        );
      console.log("[saml] signed in", profile.nameID);
      json(res, 200, {
        ok: true,
        arrived: seen,
        nameID: profile.nameID,
        attributes: profile.attributes,
        samlResponseXml: xml,
      });
    } catch (e) {
      console.error("[saml]", e.message);
      json(res, 400, {
        ok: false,
        arrived: seen,
        error: e.message,
        samlResponseXml: xml || undefined,
      });
    }
  },
);

app.get("/saml/metadata", (req, res) => {
  if (!saml) return json(res, 503, { error: "SAML not configured" });
  res
    .type("application/xml")
    .send(saml.generateServiceProviderMetadata(null, null));
});

// ---------- start page ----------
app.get("/", (req, res) => {
  res.type("html")
    .send(`<!doctype html><meta charset="utf-8"><title>Entra callback API</title>
<body style="font:16px system-ui;max-width:640px;margin:40px auto;padding:0 16px">
<h1 style="font-size:20px">Entra callback API (dev)</h1>
<form onsubmit="event.preventDefault();location.href=event.submitter.value+'?login_hint='+encodeURIComponent(this.email.value)">
<label>Work email (login_hint)<br><input name="email" type="email" required style="width:100%;padding:8px;font:inherit"></label>
<p><button value="/oidc/login" ${oidc ? "" : "disabled"}>Sign in with OIDC</button>
<button value="/saml/login" ${saml ? "" : "disabled"}>Sign in with SAML</button></p></form>
<p style="color:#666">OIDC callback: ${OIDC_REDIRECT}<br>SAML ACS: ${SAML_ACS}</p></body>`);
});

app.use((err, req, res, _next) => {
  console.error(err);
  json(res, 500, { error: err.message });
});

app.listen(PORT, () => {
  console.log(`Open ${BASE}`);
  console.log(`OIDC ${oidc ? "on " : "off"}  callback ${OIDC_REDIRECT}`);
  console.log(
    `SAML ${saml ? "on " : "off"}  ACS ${SAML_ACS}  entity ${env.SAML_ENTITY_ID ?? "-"}`,
  );
});
