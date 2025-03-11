use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Request};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::engine::general_purpose;
use base64::Engine;
use chrono::{Duration, Utc};
use client_api::token_info::TokenInfo;
use dotenv::dotenv;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;

#[derive(Debug, Clone)]
struct Config {
    server_name: String,
    client_uri: String,
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    let listening_ip = std::env::var("LISTENING_IP_ADDR").unwrap();
    let cert = std::env::var("X509_CERT_PATH").unwrap();
    let privkey = std::env::var("X509_KEY_PATH").unwrap();
    
    let server_name = std::env::var("SERVER_NAME").unwrap();
    let client_uri = std::env::var("CLIENT_API_URI").unwrap();

    let config = Config {
        server_name,
        client_uri,
    };

    let rustls_config = RustlsConfig::from_pem_file(cert, privkey).await.unwrap();
    
    let listening_socket = SocketAddr::new(IpAddr::from_str(&listening_ip).unwrap(), 8449);

    let mut default_headers = HeaderMap::new();
    default_headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    default_headers.insert("Access-Control-Allow-Origin", HeaderValue::from_static("*"));
    default_headers.insert("Access-Control-Allow-Methods", HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"));
    default_headers.insert("Access-Control-Allow-Headers", HeaderValue::from_static("X-Requested-With, Content-Type, Authorization"));

    let cors = CorsLayer::new()
        .allow_origin("*".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([HeaderName::from_str("X-Requested-With").unwrap(), header::CONTENT_TYPE, header::AUTHORIZATION]);

    let access_tokens = Arc::new(RwLock::new(HashMap::<String, TokenInfo>::new()));

    let app = Router::new()
        .route("/_matrix/client/versions", get(client_version)) // TODO: add optional authentication
        .route("/_matrix/client/v3/login", get(login))
        .route("/_matrix/client/v3/login", post(post_login))
        .merge(Router::new()
            .route("/_matrix/client/v3/pushrules/", get(push_rules))
            .route("/_matrix/client/v3/user/{user_id}/filter", post(post_filter))
            .route("/_matrix/client/v3/sync", get(sync))
            .route("/_matrix/client/v3/user/{userId}/account_data/{type}", put(account_data))
            .route("/_matrix/client/v3/keys/upload", post(upload_keys))
            .route("/_matrix/client/v3/keys/query", post(query_keys))
            .layer(middleware::from_fn(require_auth))
        )
        .fallback(default)
        .layer(Extension(access_tokens))
        .layer(Extension(config))
        .layer(cors)
        .layer(tower_default_headers::DefaultHeadersLayer::new(default_headers))
        .layer(middleware::from_fn(print_responses));

    println!("listening on {}", listening_socket);

    axum_server::bind_rustls(listening_socket, rustls_config).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn default() -> impl IntoResponse {
    let body = r#"{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}"#;

    Response::builder()
        .status(404)
        .body(body.to_string())
        .unwrap()
}

async fn client_version() -> impl IntoResponse {
    let body = r#"{"versions":["v1.8", "v1.9","v1.10", "v1.11", "v1.12", "v1.13"]}"#;

    Response::new(body.to_string())
}

async fn login() -> impl IntoResponse {
    let body = r#"{"flows": [{"type": "m.login.password"}]}"#;

    Response::new(body.to_string())
}

// TODO: replace dummy identity server with real one
// TODO: store refresh_token in a database
// TODO: tie device_id to access_token
// TODO: save valid access tokens in db before program exits to load them when program starts
async fn post_login(
    Extension(access_tokens): Extension<Arc<RwLock<HashMap<String, TokenInfo>>>>,
    Extension(config): Extension<Config>,
    Json(body): Json<Value>,
    ) -> impl IntoResponse {
    println!("{:?}", body);

    let username = body["identifier"]["user"].as_str().unwrap();
    let password = body["password"].as_str().unwrap();

    println!("username: {} password: {}", username, password);

    let device_id = uuid::Uuid::new_v4().to_string();
    let access_token = generate_access_token();
    let expires_in_ms = Utc::now() + Duration::minutes(60); // 60 minutes
    let refresh_token = generate_refresh_token();

    // TODO: see if there is a way to not use clone()
    let token_info = TokenInfo::new(access_token.clone(), expires_in_ms);
    access_tokens.write().await.insert(access_token.clone(), token_info); 

    let expires_in_ms = (expires_in_ms - Utc::now()).num_milliseconds();

    let server_name = &config.server_name;
    let client_uri = &config.client_uri;
    
    let body = format!("{{\
        \"access_token\": \"{access_token}\",\
        \"device_id\": \"{device_id}\",\
        \"expires_in_ms\": {expires_in_ms},\
        \"refresh_token\": \"{refresh_token}\",\
        \"user_id\": \"@{username}:{server_name}\",\
        \"well_known\": {{\
          \"m.homeserver\": {{\
            \"base_url\": \"{client_uri}\"\
        }},
        \"m.identity_server\": {{
            \"base_url\": \"https://id.example.org\"\
        }}\
        }}\
    }}"); 

    Response::builder().status(200).body(body.to_string()).unwrap()
}

// TODO: implement push rules
async fn push_rules(headers: HeaderMap) -> impl IntoResponse {
    println!("{:?}", headers);
    let body = "{}";

    Response::builder().status(200).body(body.to_string()).unwrap()
}

// TODO: implement id creation
async fn post_filter(Path(user_id): Path<String>) -> impl IntoResponse {
    let body = format!(r#"{{
        "filter_id": "{user_id}"
    }}"#);

    Response::builder().status(200).body(body.to_string()).unwrap()
}

// TODO: implement real sync response parameters
async fn sync() -> impl IntoResponse {
    let body = format!(r#"{{
        "next_batch": "dummy"
    }}"#);

    Response::builder().status(200).body(body.to_string()).unwrap()
}

// TODO: load actual account data 
async fn account_data() -> impl IntoResponse {
    let body = format!(r#"{{}}"#);

    Response::builder().status(200).body(body.to_string()).unwrap()
}

// TODO: implement key count
async fn upload_keys() -> impl IntoResponse {
    let body: String = format!(r#"{{
        "one_time_key_counts": {{
            "signed_curve25519": 0
        }}
    }}"#);

    Response::builder().status(200).body(body.to_string()).unwrap()
}

// TODO: implement query_keys function
async fn query_keys() -> impl IntoResponse {
    let body = format!(r#"{{
    }}"#);

    Response::builder().status(200).body(body.to_string()).unwrap()
}


// TODO: replace dummy error with real one
async fn require_auth(
        Extension(access_tokens): Extension<Arc<RwLock<HashMap<String, TokenInfo>>>>,
        headers: HeaderMap,
        req: Request,
        next: Next
    ) -> Result<impl IntoResponse, impl IntoResponse> {
    let error_body = r#"
        {
            "errcode": "M_UNKNOWN_TOKEN",
            "error": "The access token specified was not recognised."
        }
    "#;

    let error_res = Response::builder().status(401).body(error_body.to_string()).unwrap();

    if headers.get("authorization").is_none() {
        return Err(error_res);
    }

    let access_token = &headers.get("authorization").unwrap().to_str().unwrap()[7..];

    if !access_tokens.read().await.contains_key(access_token) {
        return Err(error_res);
    }

    let res = next.run(req).await;

    Ok(res)
}

async fn print_responses(ConnectInfo(info): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Result<impl IntoResponse, (StatusCode, String)> {
    println!("Got {} request from: {} at {}", req.method(), dns_lookup::lookup_addr(&info.ip()).unwrap_or(info.to_string()), req.uri());
    println!("origin: {}", req.headers().get("origin").map_or("none", |origin| origin.to_str().unwrap()));
    
    let res = next.run(req).await;

    Ok(res)
}

fn generate_access_token() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];  // 32 bytes = 256-bit security
    rng.fill(&mut bytes).unwrap();
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_refresh_token() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 64];  // 64 bytes = 512-bit security
    rng.fill(&mut bytes).unwrap();
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}