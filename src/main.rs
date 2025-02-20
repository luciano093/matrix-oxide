use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::Response;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{middleware, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::StatusCode;
use serde_json::Value;
use dotenv::dotenv;
use http_body_util::BodyExt;

#[derive(Debug, Default)]
struct Server {
    delegated_name: String,
}

impl Server {
    fn connect(url: &str) {  
        if !Path::new("./.keys").exists() {
            create_dir("./.keys").unwrap();
        }

        let private_key = if Path::new("./.keys/id_ed25519").exists() {
            let mut bytes = [0; 32];

            File::open("./.keys/id_ed25519").unwrap().read_exact(&mut bytes).unwrap();

            SigningKey::from_bytes(&bytes)
        } else {
            let mut csprng = OsRng;
            let private_key = SigningKey::generate(&mut csprng);
            let mut private_key_file = File::create_new("./.keys/id_ed25519").unwrap();

            private_key_file.write_all(private_key.as_bytes()).unwrap();

            private_key
        };

        let public_key = if Path::new("./.keys/id_ed25519.pub").exists() {
            let mut bytes = [0; 32];

            File::open("./.keys/id_ed25519.pub").unwrap().read_exact(&mut bytes).unwrap();

            VerifyingKey::from_bytes(&bytes).unwrap()
        } else {
            let public_key = VerifyingKey::from(&private_key);
            
            let mut public_key_file = File::create_new("./.keys/id_ed25519.pub").unwrap();
            public_key_file.write_all(public_key.as_bytes()).unwrap();

            public_key
        };
        
        println!("private_key: {}", base64::prelude::BASE64_STANDARD.encode(private_key.to_bytes()));
        println!("public_key: {}", base64::prelude::BASE64_STANDARD.encode(public_key.to_bytes()));

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
    let listening_ip = std::env::var("LISTENING_IP_ADDR").expect("LISTENING_IP_ADDR must be set");
    let listening_port = std::env::var("LISTENING_PORT").expect("LISTENING_PORT must be set");
    std::env::var("DELEGATED_IP_ADDR").expect("DELEGATED_IP_ADDR must be set");
    std::env::var("DELEGATED_PORT").expect("DELEGATED_PORT must be set");

    let cert = std::env::var("SSL_CERT").expect("SSL_CERT must be set");
    let key = std::env::var("SSL_KEY").expect("SSL_KEY must be set");


    let config: RustlsConfig = RustlsConfig::from_pem_file(PathBuf::from(cert), PathBuf::from(key)).await.unwrap();

    tokio::task::block_in_place(|| {
        Server::connect("https://matrix.org");
    });
    
    let ip = if listening_ip == "localhost" {
        IpAddr::from_str("127.0.0.1").unwrap()
    } else {
        IpAddr::from_str(&listening_ip).unwrap()
    };
    let socket = SocketAddr::new(ip, u16::from_str_radix(&listening_port, 10).unwrap());
    
    let app = Router::new()
        .route("/.well-known/matrix/server", get(well_known))
        .layer(middleware::from_fn(print_responses));

    println!("listening on {}", socket);

    axum_server::bind_rustls(socket, config).serve(app.into_make_service()).await.unwrap();

    Server::connect("https://matrix.org");
}

async fn well_known() -> String {
    let delegated_ip = std::env::var("DELEGATED_IP_ADDR").expect("DELEGATED_IP_ADDR must be set.");
    let delegated_port = std::env::var("DELEGATED_PORT").expect("DELEGATED_PORT must be set.");

    let ip = if delegated_ip == "localhost" {
        IpAddr::from_str("127.0.0.1").unwrap()
    } else {
        IpAddr::from_str(&delegated_ip).unwrap()
    };
    let socket = SocketAddr::new(ip, u16::from_str_radix(&delegated_port, 10).unwrap());

    format!("{{ \"m.server\": \"{}:{}\" }}\n", socket.ip(), socket.port())
}

async fn print_responses(req: Request, next: Next) -> Result<impl IntoResponse, (StatusCode, String)> {
    let (parts, body) = req.into_parts();
    let bytes = buffer_and_print("request", body).await?;
    let req = Request::from_parts(parts, Body::from(bytes));
    
    let res = next.run(req).await;

    let (parts, body) = res.into_parts();

    let bytes = buffer_and_print("response", body).await?;
    let res = Response::from_parts(parts, Body::from(bytes));

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