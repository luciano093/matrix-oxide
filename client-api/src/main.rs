use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use axum::extract::{ConnectInfo, Path, Request};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;
use serde_json::Value;
use tower_http::cors::CorsLayer;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let listening_ip = std::env::var("LISTENING_IP_ADDR").unwrap();
    let cert = std::env::var("X509_CERT_PATH").unwrap();
    let privkey = std::env::var("X509_KEY_PATH").unwrap();

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

    let app = Router::new()
        .route("/_matrix/client/versions", get(client_version))
        .route("/_matrix/client/v3/login", get(login))
        .route("/_matrix/client/v3/login", post(post_login))
        .route("/_matrix/client/v3/pushrules/", get(push_rules))
        .route("/_matrix/client/v3/user/{user_id}/filter", post(post_filter))
        .route("/_matrix/client/v3/sync", get(sync))
        .route("/_matrix/client/v3/user/{userId}/account_data/{type}", put(account_data))
        .route("/_matrix/client/v3/keys/upload", post(upload_keys))
        .route("/_matrix/client/v3/keys/query", post(query_keys))
        .fallback(default)
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

// TODO: replace dummy parameters with real ones
async fn post_login(Json(body): Json<Value>) -> impl IntoResponse {
    println!("{:?}", body);

    let username = body["identifier"]["user"].as_str().unwrap();
    let password = body["password"].as_str().unwrap();

    println!("username: {} password: {}", username, password);

    let body = format!("{{\
        \"access_token\": \"abc123\",\
        \"device_id\": \"GHTYAJCE\",\
        \"expires_in_ms\": 60000,\
        \"refresh_token\": \"def456\",\
        \"user_id\": \"@{}:matrix-oxide.kyun.li:8448\",\
        \"well_known\": {{\
          \"m.homeserver\": {{\
            \"base_url\": \"https://matrix-oxide.kyun.li:8449\"\
        }},
          \"m.identity_server\": {{
            \"base_url\": \"https://id.example.org\"\
        }}\
        }}\
    }}", username);      

    Response::builder().status(200).body(body.to_string()).unwrap()
}

// TODO: implement push rules
async fn push_rules() -> impl IntoResponse {
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
    let body = format!(r#"{{
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

async fn print_responses(ConnectInfo(info): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Result<impl IntoResponse, (StatusCode, String)> {
    println!("Got {} request from: {} at {}", req.method(), dns_lookup::lookup_addr(&info.ip()).unwrap_or(info.to_string()), req.uri());
    println!("origin: {}", req.headers().get("origin").map_or("none", |origin| origin.to_str().unwrap()));
    
    let res = next.run(req).await;

    Ok(res)
}