use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request};
use axum::http::{Response, StatusCode};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{middleware, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::SigningKey;
use gateway::config::Config;
use gateway::key_manager::KeyMananger;
use serde_json::{json, Value};
use dotenv::dotenv;
use http_body_util::BodyExt;

#[tokio::main]
async fn main() {
    dotenv().ok();
    let config = Config::new();

    let rustls_config = RustlsConfig::from_pem_file(config.x509_cert_path().clone(), config.x509_key_path().clone()).await.unwrap();
    let key_manager = KeyMananger::new();
    
    let listening_socket = SocketAddr::new(config.listening_ip_addr(), config.listening_port());

    let app = Router::new()
        .route("/.well-known/matrix/server", get(well_known_server))
        .route("/_matrix/federation/v1/version", get(server_version))
        .route("/_matrix/key/v2/server", get(server_keys))
        .route("/.well-known/matrix/client", get(well_known_client))
        .route("/_matrix/client/versions", get(client_version))
        .layer(middleware::from_fn(print_responses))
        .layer(Extension(config))
        .layer(Extension(key_manager));

    println!("listening on {}", listening_socket);

    axum_server::bind_rustls(listening_socket, rustls_config).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn well_known_client(config: Extension<Config>) -> impl IntoResponse {
    let body = format!(r#"{{"m.homeserver": {{ "base_url": "{}" }}}}"#, config.client_api_uri());

    Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        .header("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization")
        .body(body.to_string()).unwrap()
}

async fn client_version() -> impl IntoResponse {
    let body = "{\"versions\": [\"v1.11\", \"v1.13\"]}";

    Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        .header("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization")
        .body(body.to_string()).unwrap()
}

async fn well_known_server(config: Extension<Config>) -> String {
    format!("{{ \"m.server\": \"{}:{}\" }}\n", config.delegated_addr(), config.delegated_port())
}

async fn server_version() -> String {
    "{\"server\": {\"name\": \"matrix-oxide\", \"version\": \"0.0.1\"}}".to_string()
}

async fn server_keys(config: Extension<Config>, key_manager: Extension<KeyMananger>) -> String {
    let mut json = json!({
        "server_name": config.server_name(),
        "valid_until_ts": key_manager.valid_until_ts().await,
        "verify_keys": {
            "ed25519:abc123": {
                "key": key_manager.public_key_b64().read().await.to_string(),
            }
        }
    });

    sign_json(&mut json, config.server_name(), &mut *key_manager.private_key().write().await);

    json.to_string()
}

fn sign_json(json: &mut Value, server_name: &str, private_key: &mut SigningKey) {
    let signature = private_key.sign(json.to_string().as_bytes());
    base64::prelude::BASE64_STANDARD_NO_PAD.encode(signature.to_bytes());

    json["signatures"] = json!({
        server_name: {
            "ed25519:abc123": base64::prelude::BASE64_STANDARD_NO_PAD.encode(signature.to_bytes()),
        }
    });
}

async fn print_responses(ConnectInfo(info): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Result<impl IntoResponse, (StatusCode, String)> {
    println!("Got {} request from: {} at {}", req.method(), dns_lookup::lookup_addr(&info.ip()).unwrap_or(info.to_string()), req.uri());
    println!("origin: {}", req.headers().get("origin").map_or("none", |origin| origin.to_str().unwrap()));
    // let (parts, body) = req.into_parts();
    
    // let bytes = buffer_and_print("request", body).await?;
    // let req = Request::from_parts(parts, Body::from(bytes));
    
    let res = next.run(req).await;

    // let (parts, body) = res.into_parts();

    // let bytes = buffer_and_print("response", body).await?;
    // let res = Response::from_parts(parts, Body::from(bytes));

    Ok(res)
}

async fn buffer_and_print<B>(direction: &str, body: B) -> Result<Bytes, (StatusCode, String)>
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(err) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("failed to read {direction} body: {err}"),
            ));
        }
    };

    if let Ok(body) = std::str::from_utf8(&bytes) {
        println!("{direction}:\n{body}");
    }

    Ok(bytes)
}