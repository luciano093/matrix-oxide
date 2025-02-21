use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::str::FromStr;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Request};
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

fn key_pair_exists() -> bool {
    let key_pair_dir = Path::new("./.keys");
    key_pair_dir.join("id_ed25519").exists() && key_pair_dir.join("id_ed25519.pub").exists()
}

fn is_key_pair_valid(private_key: &SigningKey, public_key: &VerifyingKey) -> bool {
    private_key.verifying_key() == *public_key
}

fn create_key_pair() -> (SigningKey, VerifyingKey) {
    if !Path::new("./.keys").exists() {
        create_dir("./.keys").unwrap();
    }

    let mut csprng = OsRng;
    let private_key = SigningKey::generate(&mut csprng);
    let mut private_key_file = File::create_new("./.keys/id_ed25519").unwrap();

    private_key_file.write_all(private_key.as_bytes()).unwrap();

    let public_key = VerifyingKey::from(&private_key);
    
    let mut public_key_file = File::create_new("./.keys/id_ed25519.pub").unwrap();
    public_key_file.write_all(public_key.as_bytes()).unwrap();

    (private_key, public_key)
}

fn load_key_pair() -> (SigningKey, VerifyingKey) {
    let private_key = {
        let mut bytes = [0; 32];

        File::open("./.keys/id_ed25519").unwrap().read_exact(&mut bytes).unwrap();

        SigningKey::from_bytes(&bytes)
    };

    let public_key = {
        let mut bytes = [0; 32];

        File::open("./.keys/id_ed25519.pub").unwrap().read_exact(&mut bytes).unwrap();

        VerifyingKey::from_bytes(&bytes).unwrap()
    };

    (private_key, public_key)
}

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

#[derive(Debug, Clone)]
struct Config {
    // .env configurations
    listening_ip_addr: IpAddr,
    listening_port: u16,
    delegated_addr: String,
    delegated_port: u16,
    x509_cert_path: PathBuf,
    x509_key_path: PathBuf,

    // key pair
    private_key: SigningKey,
    public_key: VerifyingKey,
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

        let (private_key, public_key) = if !key_pair_exists() {
            create_key_pair()
        } else {
            let (private_key, public_key) = load_key_pair();
            if !is_key_pair_valid(&private_key, &public_key) {
                create_key_pair()
            } else {
                (private_key, public_key)
            }
        };

        Config { listening_ip_addr, listening_port, delegated_addr, delegated_port, x509_cert_path, x509_key_path, private_key, public_key }
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
        .route("/_matrix/federation/v1/version", get(server_version))
        .route("/_matrix/key/v2/server", get(server_keys))
        .layer(middleware::from_fn(print_responses))
        .layer(Extension(config));

    println!("listening on {}", listening_socket);

    axum_server::bind_rustls(listening_socket, rustls_config).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();

    Server::connect("https://matrix.org");
}

async fn well_known(config: Extension<Config>) -> String {
    format!("{{ \"m.server\": \"{}:{}\" }}\n", config.delegated_addr, config.delegated_port)
}

async fn server_version() -> String {
    "{\"server\": {\"name\": \"matrix-oxide\", \"version\": \"0.0.1\"}}".to_string()
}

// temporary dummy response
async fn server_keys() -> String {
    format!(r#"{{
        "old_verify_keys": {{
            "ed25519:0ldk3y": {{
                "expired_ts": 1532645052628,
                "key": "VGhpcyBzaG91bGQgYmUgeW91ciBvbGQga2V5J3MgZWQyNTUxOSBwYXlsb2FkLg"
            }}
        }},
        "server_name": "example.org",
        "signatures": {{
            "example.org": {{
            "ed25519:auto2": "VGhpcyBzaG91bGQgYWN0dWFsbHkgYmUgYSBzaWduYXR1cmU"
        }}
        }},
        "valid_until_ts": 1652262000000,
        "verify_keys": {{
            "ed25519:abc123": {{
                "key": "VGhpcyBzaG91bGQgYmUgYSByZWFsIGVkMjU1MTkgcGF5bG9hZA"
            }}
        }}
    }}
    "#)
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