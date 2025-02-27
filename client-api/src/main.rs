use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use axum::extract::{ConnectInfo, Request};
use axum::http::{Response, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use dotenv::dotenv;

#[tokio::main]
async fn main() {
    dotenv().ok();

    let listening_ip = std::env::var("LISTENING_IP_ADDR").unwrap();
    let cert = std::env::var("X509_CERT_PATH").unwrap();
    let privkey = std::env::var("X509_KEY_PATH").unwrap();

    let rustls_config = RustlsConfig::from_pem_file(cert, privkey).await.unwrap();
    
    let listening_socket = SocketAddr::new(IpAddr::from_str(&listening_ip).unwrap(), 8449);

    let app = Router::new()
        .route("/_matrix/client/versions", get(client_version))
        .layer(middleware::from_fn(print_responses));

    println!("listening on {}", listening_socket);

    axum_server::bind_rustls(listening_socket, rustls_config).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
}

async fn client_version() -> impl IntoResponse {
    let body = r#"{"versions":["v1.8", "v1.9","v1.10", "v1.11", "v1.12", "v1.13"]}"#;

    Response::builder()
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        .header("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization")
        .body(body.to_string()).unwrap()
}

async fn print_responses(ConnectInfo(info): ConnectInfo<SocketAddr>, req: Request, next: Next) -> Result<impl IntoResponse, (StatusCode, String)> {
    println!("Got {} request from: {} at {}", req.method(), dns_lookup::lookup_addr(&info.ip()).unwrap_or(info.to_string()), req.uri());
    println!("origin: {}", req.headers().get("origin").map_or("none", |origin| origin.to_str().unwrap()));
    
    let res = next.run(req).await;

    Ok(res)
}