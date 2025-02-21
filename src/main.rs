use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;

use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::Response;
use axum::middleware::Next;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{middleware, Extension, Router};
use axum_server::tls_rustls::RustlsConfig;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use reqwest::StatusCode;
use serde_json::Value;
use dotenv::dotenv;
use http_body_util::BodyExt;
use url::Url;

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

#[derive(Debug, Clone)]
struct Config {
    listening_ip_addr: IpAddr,
    listening_port: u16,
    delegated_addr: String,
    delegated_port: u16,
    x509_cert_path: PathBuf,
    x509_key_path: PathBuf,
}

impl Config {
    fn new() -> Self {
        let mut error_flag = false;

        let listening_ip_addr = match std::env::var("LISTENING_IP_ADDR") {
            Ok(mut str) => {
                if str == "localhost" {
                    str = "127.0.0.1".to_string();
                }

                match IpAddr::from_str(&str) {
                    Ok(ip) => Ok(ip),
                    Err(_) => {
                        eprintln!("Error: LISTENING_IP_ADDR has an invalid ip address.");
                        error_flag = true;
                        Err(())
                    }
                }
            },
            Err(_) => {
                eprintln!("Error: LISTENING_IP_ADDR must be set.");
                error_flag = true;
                Err(())
            }
        };

        let listening_port = match std::env::var("LISTENING_PORT") {
            Ok(str) => {
                if is_valid_port(&str) {
                    // parse should never error out due to is_valid_port verification
                    Ok(str.parse::<u16>().unwrap())
                } else {
                    eprintln!("Error: LISTENING_PORT has an invalid port.");
                    error_flag = true;
                    Err(())
                }
            },
            Err(_) => {
                eprintln!("Error: LISTENING_PORT must be set.");
                error_flag = true;
                Err(())
            }
        };

        let delegated_addr = match std::env::var("DELEGATED_ADDR") {
            Ok(mut str) => {
                if str == "localhost" {
                    str = "127.0.0.1".to_string();
                }

                if IpAddr::from_str(&str).is_ok() || is_valid_address(&str) {
                    Ok(str)
                }
                else {
                    eprintln!("Error: DELEGATED_ADDR has either an invalid ip address or an invalid url.");
                    error_flag = true;
                    Err(())
                }
            },
            Err(_) => {
                eprintln!("Error: DELEGATED_ADDR must be set.");
                error_flag = true;
                Err(())
            }
        };

        let delegated_port = match std::env::var("DELEGATED_PORT") {
            Ok(str) => {
                if is_valid_port(&str) {
                    // parse should never error out due to is_valid_port verification
                    Ok(str.parse::<u16>().unwrap())
                } else {
                    eprintln!("Error: DELEGATED_PORT has an invalid port.");
                    error_flag = true;
                    Err(())
                }
            },
            Err(_) => {
                eprintln!("Error: DELEGATED_PORT must be set.");
                error_flag = true;
                Err(())
            }
        };

        let x509_cert_path = match std::env::var("X509_CERT_PATH") {
            Ok(str) => {
                match PathBuf::from_str(&str) {
                    Ok(path) => Ok(path),
                    Err(_) => {
                        eprintln!("Error: X509_CERT_PATH has an invalid path.");
                        error_flag = true;
                        Err(()) 
                    }
                }
            },
            Err(_) => {
                eprintln!("Error: X509_CERT_PATH must be set.");
                error_flag = true;
                Err(())
            }
        };

        let x509_key_path = match std::env::var("X509_KEY_PATH") {
            Ok(str) => {
                match PathBuf::from_str(&str) {
                    Ok(path) => Ok(path),
                    Err(_) => {
                        eprintln!("Error: X509_KEY_PATH has an invalid path.");
                        error_flag = true;
                        Err(()) 
                    }
                }
            },
            Err(_) => {
                eprintln!("Error: X509_KEY_PATH must be set.");
                error_flag = true;
                Err(())
            }
        };

        if error_flag {
            exit(-1);
        }

        // safe to call unwrap due to error flag exiting the program if there was an error
        let listening_ip_addr = listening_ip_addr.unwrap();
        let listening_port = listening_port.unwrap();
        let delegated_addr = delegated_addr.unwrap();
        let delegated_port = delegated_port.unwrap();
        let x509_cert_path = x509_cert_path.unwrap();
        let x509_key_path = x509_key_path.unwrap();

        Config { listening_ip_addr, listening_port, delegated_addr, delegated_port, x509_cert_path, x509_key_path }
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let config = Config::new();

    let rustls_config = RustlsConfig::from_pem_file(config.x509_cert_path.clone(), config.x509_key_path.clone()).await.unwrap();

    tokio::task::block_in_place(|| {
        Server::connect("https://matrix.org");
    });
    
    let listening_socket = SocketAddr::new(config.listening_ip_addr, config.listening_port);

    let app = Router::new()
        .route("/.well-known/matrix/server", get(well_known))
        .layer(middleware::from_fn(print_responses))
        .layer(Extension(config));


    println!("listening on {}", listening_socket);

    axum_server::bind_rustls(listening_socket, rustls_config).serve(app.into_make_service()).await.unwrap();

    Server::connect("https://matrix.org");
}

async fn well_known(config: Extension<Config>) -> String {
    format!("{{ \"m.server\": \"{}:{}\" }}\n", config.delegated_addr, config.delegated_port)
}

fn is_valid_address(str: &str) -> bool {
    let input_with_scheme = if str.contains("://") {
        str.to_string()
    } else {
        format!("http://{}", str)
    };

    Url::parse(&input_with_scheme).is_ok()
}

fn is_valid_port(str: &str) -> bool {
    str.parse::<u16>().map_or(false, |port| port != 0)
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