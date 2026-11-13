// Real Entra ID SAML 2.0 callback API for local testing: ACS at /auth/saml/acs.
// The ACS validates with samael (xmlsec1) and answers with JSON: what arrived + the validation result.
// DEV ONLY: http, no session, in-memory state.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::extract::{Form, OriginalUri, Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use samael::crypto::AllowedSignatureAlgorithm;
use samael::metadata::EntityDescriptor;
use samael::schema::Assertion;
use samael::service_provider::{ServiceProvider, ServiceProviderBuilder};
use serde_json::{Value, json};

type Params = HashMap<String, String>;

struct App {
    base: String,
    sp: ServiceProvider,
    // ponytail: outstanding AuthnRequest IDs in memory; lost on restart, single process only.
    ids: Mutex<HashSet<String>>,
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
    (status, [(header::CONTENT_TYPE, "application/json")], serde_json::to_string_pretty(&body).unwrap()).into_response()
}

// What the browser actually delivered to the ACS.
fn arrived(method: &Method, uri: &axum::http::Uri, headers: &HeaderMap, body: &Params) -> Value {
    let body: serde_json::Map<_, _> = body.iter()
        .map(|(k, v)| (k.clone(), json!(if k == "SAMLResponse" { mask(v) } else { v.clone() }))).collect();
    let headers: serde_json::Map<_, _> = headers.iter()
        .filter(|(k, _)| ["host", "origin", "referer", "content-type", "cookie"].contains(&k.as_str()) || k.as_str().starts_with("sec-fetch-"))
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap_or("<binary>"))))
        .collect();
    json!({ "method": method.as_str(), "path": uri.path(), "body": body, "headers": headers })
}

fn cert_base64(s: &str) -> String {
    s.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").split_whitespace().collect()
}

async fn load_idp_certs() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    if let Some(url) = env("SAML_IDP_METADATA_URL") {
        // No redirects: the metadata URL is fixed, following redirects opens SSRF holes.
        let http = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build()?;
        let xml = http.get(url).send().await?.error_for_status()?.text().await?;
        let mut certs: Vec<String> = xml.split("X509Certificate>").skip(1).step_by(2)
            .map(|s| cert_base64(s.split('<').next().unwrap_or(""))).collect();
        certs.dedup();
        return Ok(certs);
    }
    let v = env("ENTRA_SAML_CERT").unwrap_or_default();
    let text = std::fs::read_to_string(&v).unwrap_or(v);
    Ok(vec![cert_base64(&text)])
}

fn build_sp(tenant: &str, entity_id: &str, acs: &str, certs: &[String]) -> Result<ServiceProvider, Box<dyn std::error::Error>> {
    let keys: String = certs.iter().map(|c| format!(
        r#"<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{c}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#
    )).collect();
    // Entra's SAML issuer is https://sts.windows.net/{tenant}/ (trailing slash matters).
    let idp: EntityDescriptor = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://sts.windows.net/{tenant}/"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{keys}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/{tenant}/saml2"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
    ).parse()?;
    let sp = ServiceProviderBuilder::default()
        .entity_id(entity_id.to_string())
        .acs_url(acs.to_string())
        .metadata_url(None) // no metadata URL in Entra's config
        .slo_url(None)
        .idp_metadata(idp)
        .max_issue_delay(chrono::Duration::minutes(5))
        .max_clock_skew(chrono::Duration::minutes(5))
        // Entra signs the Assertion with RSA-SHA256 by default; samael checks the signature, issuer,
        // audience, time window, Recipient and InResponseTo. No RequestedAuthnContext is sent (avoids AADSTS75011).
        .allowed_signature_algorithms(Some(vec![AllowedSignatureAlgorithm::RsaSha256]))
        .build()?;
    if sp.idp_signing_certs()?.is_none() {
        return Err("no IdP signing certificate".into()); // samael would skip signature checks without one
    }
    Ok(sp)
}

async fn login(State(app): State<Arc<App>>, Query(q): Query<Params>) -> Response {
    let url = (|| -> Result<url::Url, Box<dyn std::error::Error>> {
        let sso = app.sp.sso_binding_location("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect").ok_or("no SSO URL")?;
        let req = app.sp.make_authentication_request(&sso)?;
        let mut url = req.redirect("/")?.ok_or("no destination")?;
        if let Some(hint) = q.get("login_hint").filter(|h| !h.is_empty()) {
            url.query_pairs_mut().append_pair("login_hint", hint);
        }
        app.ids.lock().unwrap().insert(req.id);
        Ok(url)
    })();
    match url {
        Ok(url) => Redirect::to(url.as_str()).into_response(),
        Err(e) => json_res(StatusCode::INTERNAL_SERVER_ERROR, json!({ "error": e.to_string() })),
    }
}

fn in_response_to(a: &Assertion) -> Option<String> {
    a.subject.as_ref()?.subject_confirmations.as_ref()?.iter()
        .find_map(|c| c.subject_confirmation_data.as_ref()?.in_response_to.clone())
}

async fn acs(State(app): State<Arc<App>>, method: Method, OriginalUri(uri): OriginalUri, headers: HeaderMap, Form(body): Form<Params>) -> Response {
    let seen = arrived(&method, &uri, &headers, &body);
    let encoded = body.get("SAMLResponse").map(String::as_str).unwrap_or("");
    let xml = STANDARD.decode(encoded).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_default();

    let result = {
        // Held across validation so a replayed response can't race the one-time removal below.
        let mut ids = app.ids.lock().unwrap();
        let possible: Vec<&str> = ids.iter().map(String::as_str).collect();
        let r = app.sp.parse_base64_response(encoded, Some(&possible)).map_err(|e| e.to_string());
        if let Ok(a) = &r && let Some(id) = in_response_to(a) {
            ids.remove(&id); // one use only: a replay fails InResponseTo
        }
        r
    };
    match result {
        Ok(a) => {
            let name_id = a.subject.as_ref().and_then(|s| s.name_id.as_ref()).map(|n| n.value.clone());
            let mut attributes = serde_json::Map::new();
            for attr in a.attribute_statements.iter().flatten().flat_map(|s| &s.attributes) {
                let vals: Vec<Value> = attr.values.iter().map(|v| json!(v.value)).collect();
                let v = if vals.len() == 1 { vals[0].clone() } else { Value::Array(vals) };
                attributes.insert(attr.name.clone().unwrap_or_default(), v);
            }
            println!("[saml] signed in {}", name_id.as_deref().unwrap_or("-"));
            json_res(StatusCode::OK, json!({ "ok": true, "arrived": seen, "nameID": name_id, "attributes": attributes, "samlResponseXml": xml }))
        }
        Err(e) => {
            eprintln!("[saml] {e}");
            json_res(StatusCode::BAD_REQUEST, json!({ "ok": false, "arrived": seen, "error": e, "samlResponseXml": (!xml.is_empty()).then_some(xml) }))
        }
    }
}

async fn metadata(State(app): State<Arc<App>>) -> Response {
    // Hand-written: samael's metadata() insists on an SLO URL, which this API doesn't have.
    let xml = format!(
        r#"<?xml version="1.0"?><EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}"><SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAssertionsSigned="true"><NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat><AssertionConsumerService index="1" isDefault="true" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{}"/></SPSSODescriptor></EntityDescriptor>"#,
        app.sp.entity_id.as_deref().unwrap_or(""), app.sp.acs_url.as_deref().unwrap_or(""));
    ([(header::CONTENT_TYPE, "application/xml")], xml).into_response()
}

async fn index(State(app): State<Arc<App>>) -> Html<String> {
    Html(format!(r#"<!doctype html><meta charset="utf-8"><title>Entra SAML callback</title>
<body style="font:16px system-ui;max-width:640px;margin:40px auto;padding:0 16px">
<h1 style="font-size:20px">Entra SAML callback API (dev, Rust)</h1>
<form action="/saml/login">
<label>Work email (login_hint)<br><input name="login_hint" type="email" required style="width:100%;padding:8px;font:inherit"></label>
<p><button>Sign in with SAML</button></p></form>
<p style="color:#666">ACS: {}/auth/saml/acs</p></body>"#, app.base))
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    let (Some(tenant), Some(entity)) = (env("TENANT_ID"), env("SAML_ENTITY_ID")) else {
        eprintln!("Missing TENANT_ID / SAML_ENTITY_ID. Copy .env.example to .env and fill it in.");
        std::process::exit(1);
    };
    if env("ENTRA_SAML_CERT").is_none() && env("SAML_IDP_METADATA_URL").is_none() {
        eprintln!("Set ENTRA_SAML_CERT or SAML_IDP_METADATA_URL.");
        std::process::exit(1);
    }
    let port: u16 = env("PORT").and_then(|p| p.parse().ok()).unwrap_or(4000);
    let base = format!("http://localhost:{port}");
    let acs_url = format!("{base}/auth/saml/acs");

    let sp = match load_idp_certs().await {
        Ok(certs) => build_sp(&tenant, &entity, &acs_url, &certs),
        Err(e) => Err(e),
    }.unwrap_or_else(|e| {
        eprintln!("Bad ENTRA_SAML_CERT / SAML_IDP_METADATA_URL: {e}");
        std::process::exit(1);
    });

    println!("Open {base}");
    println!("SAML ACS {acs_url}  entity {entity}");

    let app = Arc::new(App { base, sp, ids: Mutex::default() });
    let router = Router::new()
        .route("/", get(index))
        .route("/saml/login", get(login))
        .route("/auth/saml/acs", post(acs))
        .route("/saml/metadata", get(metadata))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(("::", port)).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}
