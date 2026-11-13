// Real Entra ID OIDC callback API for local testing (Rust port of the OIDC half of ../oidc/server.mjs).
// The callback validates with the library and answers with JSON: what arrived + the validation result.
// DEV ONLY: http, no session, in-memory state.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{OriginalUri, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RequestTokenError, Scope, TokenResponse, reqwest,
};
use serde_json::{Value, json};
use tokio::sync::OnceCell;

// Vec keeps the URL's parameter order in `arrived`, like Express's req.query.
type Params = Vec<(String, String)>;

fn param<'a>(q: &'a Params, k: &str) -> Option<&'a String> {
    q.iter().find(|(n, _)| n == k).map(|(_, v)| v)
}
type OidcClient =
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

struct App {
    authority: String,
    redirect: String,
    creds: Option<(String, String)>, // CLIENT_ID, CLIENT_SECRET; None = OIDC off (503), like the JS version
    client: OnceCell<OidcClient>,    // built on first use: discovery is lazy, as in MSAL
    http: reqwest::Client,
    // ponytail: state -> (verifier, nonce) in memory; lost on restart, single process only.
    pending: Mutex<HashMap<String, (PkceCodeVerifier, Nonce)>>,
}

const SCOPES: [&str; 3] = ["profile", "email", "offline_access"]; // openid is added by the library

impl App {
    async fn client(&self) -> Result<&OidcClient, String> {
        let (id, secret) = self.creds.clone().ok_or("OIDC not configured")?;
        self.client.get_or_try_init(|| async {
            let issuer = IssuerUrl::new(format!("{}/v2.0", self.authority)).map_err(|e| e.to_string())?;
            let meta = CoreProviderMetadata::discover_async(issuer, &self.http).await
                .map_err(|e| format!("OIDC discovery failed (TENANT_ID must be the tenant GUID): {e}"))?;
            Ok(CoreClient::from_provider_metadata(meta, ClientId::new(id), Some(ClientSecret::new(secret)))
                .set_auth_type(AuthType::RequestBody) // client_secret in the body, as MSAL does
                .set_redirect_uri(RedirectUrl::new(self.redirect.clone()).map_err(|e| e.to_string())?))
        }).await
    }
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

fn mask(v: &str) -> String {
    let n = v.chars().count();
    if n <= 16 { return v.into() }
    let head: String = v.chars().take(8).collect();
    let tail: String = v.chars().skip(n - 4).collect();
    format!("{head}…{tail} (len {n})")
}

fn json_res(status: StatusCode, body: Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json; charset=utf-8")], serde_json::to_string_pretty(&body).unwrap()).into_response()
}

// What the browser actually delivered to the callback.
fn arrived(method: &Method, uri: &axum::http::Uri, headers: &HeaderMap, query: &Params, mask_fields: &[&str]) -> Value {
    let query: serde_json::Map<_, _> = query.iter()
        .map(|(k, v)| (k.clone(), json!(if mask_fields.contains(&k.as_str()) { mask(v) } else { v.clone() }))).collect();
    let headers: serde_json::Map<_, _> = headers.iter()
        .filter(|(k, _)| ["host", "origin", "referer", "content-type", "cookie"].contains(&k.as_str()) || k.as_str().starts_with("sec-fetch-"))
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or("<binary>"))))
        .collect();
    json!({ "method": method.as_str(), "path": uri.path(), "query": query, "headers": headers })
}

// ---------- OIDC (authorization code + PKCE) ----------
async fn oidc_login(State(app): State<Arc<App>>, Query(q): Query<Params>) -> Response {
    if app.creds.is_none() {
        return json_res(StatusCode::SERVICE_UNAVAILABLE, json!({ "error": "OIDC not configured: set CLIENT_ID and CLIENT_SECRET" }));
    }
    let client = match app.client().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return json_res(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": e }));
        }
    };
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut req = client
        .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scopes(SCOPES.map(|s| Scope::new(s.into())))
        .set_pkce_challenge(challenge)
        .add_extra_param("response_mode", "query");
    if let Some(hint) = param(&q, "login_hint").filter(|h| !h.is_empty()) {
        req = req.add_extra_param("login_hint", hint.clone());
    }
    let (url, state, nonce) = req.url();
    app.pending.lock().unwrap().insert(state.secret().clone(), (verifier, nonce));
    Redirect::to(url.as_str()).into_response()
}

async fn oidc_callback(State(app): State<Arc<App>>, method: Method, OriginalUri(uri): OriginalUri, headers: HeaderMap, Query(q): Query<Params>) -> Response {
    let seen = arrived(&method, &uri, &headers, &q, &["code"]);
    if let Some(err) = param(&q, "error") {
        return json_res(StatusCode::BAD_REQUEST, json!({ "ok": false, "arrived": seen, "error": err, "description": param(&q, "error_description") }));
    }

    // remove = one use only
    let Some((verifier, nonce)) = param(&q, "state").and_then(|s| app.pending.lock().unwrap().remove(s)) else {
        return json_res(StatusCode::BAD_REQUEST, json!({ "ok": false, "arrived": seen, "error": "invalid_state", "description": "Unknown or already used state. Start again at /oidc/login." }));
    };

    // Err = (errorCode, description), like MSAL's e.errorCode / e.errorMessage.
    let result: Result<Value, (String, String)> = async {
        let client = app.client().await.map_err(|e| ("discovery_failed".into(), e))?;
        let r = client
            .exchange_code(AuthorizationCode::new(param(&q, "code").cloned().unwrap_or_default()))
            .map_err(|e| ("configuration_error".into(), e.to_string()))?
            .set_pkce_verifier(verifier)
            .request_async(&app.http).await
            .map_err(|e| match &e {
                RequestTokenError::ServerResponse(r) => (r.error().to_string(), r.error_description().cloned().unwrap_or_default()),
                _ => ("request_failed".into(), e.to_string()),
            })?;
        let id_token = r.id_token().ok_or(("no_id_token".to_string(), "Token response has no id_token".to_string()))?;
        // Checks signature (Entra JWKS), iss, aud, exp and nonce.
        id_token.claims(&client.id_token_verifier(), &nonce).map_err(|e| ("invalid_id_token".into(), e.to_string()))?;
        // The verified token's full payload, so Entra claims like roles / groups / oid / tid are shown too.
        let claims = id_token.to_string().split('.').nth(1).and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok()).unwrap_or(Value::Null);
        let expires_on = r.expires_in().map(|d| (chrono::Utc::now() + d).to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        Ok(json!({
            "ok": true,
            "arrived": seen.clone(),
            "tokenType": r.token_type().as_ref(),
            "scopes": r.scopes().map(|s| s.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "expiresOn": expires_on,
            "idTokenClaims": claims,
        }))
    }.await;

    match result {
        Ok(out) => {
            let c = &out["idTokenClaims"];
            println!("[oidc] signed in {} roles {}", c["preferred_username"], c.get("roles").unwrap_or(&json!([])));
            json_res(StatusCode::OK, out)
        }
        Err((code, description)) => {
            eprintln!("[oidc] {code} {description}");
            json_res(StatusCode::BAD_REQUEST, json!({ "ok": false, "arrived": seen, "error": code, "description": description }))
        }
    }
}

// ---------- start page ----------
async fn index(State(app): State<Arc<App>>) -> Html<String> {
    Html(format!(r#"<!doctype html><meta charset="utf-8"><title>Entra callback API</title>
<body style="font:16px system-ui;max-width:640px;margin:40px auto;padding:0 16px">
<h1 style="font-size:20px">Entra callback API (dev)</h1>
<form onsubmit="event.preventDefault();location.href=event.submitter.value+'?login_hint='+encodeURIComponent(this.email.value)">
<label>Work email (login_hint)<br><input name="email" type="email" required style="width:100%;padding:8px;font:inherit"></label>
<p><button value="/oidc/login" {}>Sign in with OIDC</button></p></form>
<p style="color:#666">OIDC callback: {}</p></body>"#,
        if app.creds.is_some() { "" } else { "disabled" }, app.redirect))
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let Some(tenant) = env("TENANT_ID") else {
        eprintln!("Missing TENANT_ID. Copy .env.example to .env and fill it in.");
        std::process::exit(1);
    };
    let port: u16 = env("PORT").and_then(|p| p.parse().ok()).unwrap_or(4000);
    let base = format!("http://localhost:{port}");
    let creds = env("CLIENT_ID").zip(env("CLIENT_SECRET"));

    println!("Open {base}");
    println!("OIDC {}  callback {base}/auth/callback", if creds.is_some() { "on " } else { "off" });

    let app = Arc::new(App {
        authority: format!("https://login.microsoftonline.com/{tenant}"),
        redirect: format!("{base}/auth/callback"),
        creds,
        client: OnceCell::new(),
        // No redirects: following them on token / discovery calls opens SSRF holes.
        http: reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build().unwrap(),
        pending: Mutex::default(),
    });
    let router = Router::new()
        .route("/", get(index))
        .route("/oidc/login", get(oidc_login))
        .route("/auth/callback", get(oidc_callback))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(("::", port)).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
