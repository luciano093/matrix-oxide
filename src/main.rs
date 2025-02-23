use std::io::Read;
use std::net::SocketAddr;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{middleware, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use ed25519_dalek::ed25519::signature::SignerMut;
use ed25519_dalek::SigningKey;
use matrix_oxide::config::Config;
use matrix_oxide::key_manager::KeyMananger;
use reqwest::StatusCode;
use serde_json::{json, Value};
use dotenv::dotenv;
use http_body_util::BodyExt;

#[derive(Debug, Default)]
struct Server {
    delegated_name: String,
}

impl Server {
    fn connect(url: &str) {  
        // get delegated server name
        let mut res = reqwest::blocking::get(format!("{}/.well-known/matrix/server", url)).unwrap();
        let mut body = String::new();
        res.read_to_string(&mut body).unwrap();

        let mut server = Server::default();
        server.delegated_name = serde_json::from_str::<Value>(&body).unwrap()["m.server"].as_str().unwrap().to_owned();

        println!("{}", body);

        // get server implemenation name and version
        let mut res = reqwest::blocking::get(format!("https://{}/_matrix/federation/v1/version", server.delegated_name)).unwrap();
        let mut body = String::new();
        res.read_to_string(&mut body).unwrap();

        let implementation_name = serde_json::from_str::<Value>(&body).unwrap()["server"]["name"].to_string();
        let implementation_version = serde_json::from_str::<Value>(&body).unwrap()["server"]["version"].to_string();

        println!("implementation name: {} implementation version: {}", implementation_name, implementation_version);

        // get server published signing keys
        let mut res = reqwest::blocking::get(format!("{}/_matrix/key/v2/server", url)).unwrap();
        let mut body = String::new();
        res.read_to_string(&mut body).unwrap();
        let res = serde_json::from_str::<Value>(&body).unwrap();

        println!("server_name: {}\nsignatures: {}\nvalid_until_ts: {}\nverify_keys: {}", res["server_name"], res["signatures"], res["valid_until_ts"], res["verify_keys"]);
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let config = Config::new();

    let rustls_config = RustlsConfig::from_pem_file(config.x509_cert_path().clone(), config.x509_key_path().clone()).await.unwrap();
    let key_manager = KeyMananger::new();

    tokio::task::block_in_place(|| {
        Server::connect("https://matrix.org");
    });
    
    let listening_socket = SocketAddr::new(config.listening_ip_addr(), config.listening_port());

    let app = Router::new()
        .route("/.well-known/matrix/server", get(well_known))
        .route("/_matrix/federation/v1/version", get(server_version))
        .route("/_matrix/key/v2/server", get(server_keys))
        .layer(middleware::from_fn(print_responses))
        .layer(Extension(config))
        .layer(Extension(key_manager));

    println!("listening on {}", listening_socket);

    axum_server::bind_rustls(listening_socket, rustls_config).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();

    Server::connect("https://matrix.org");
}

async fn well_known(config: Extension<Config>) -> String {
    format!("{{ \"m.server\": \"{}:{}\" }}\n", config.delegated_addr(), config.delegated_port())
}

async fn server_version() -> String {
    "{\"server\": {\"name\": \"matrix-oxide\", \"version\": \"0.0.1\"}}".to_string()
}

// temporary dummy response
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

    println!("{}", json.to_string());

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