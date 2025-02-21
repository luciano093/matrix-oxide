use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::{net::IpAddr, process::exit};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

use crate::{is_valid_address, is_valid_port};

#[derive(Debug, Clone)]
pub struct Config {
    // .env configurations
    server_name: String,
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
    pub fn new() -> Self {
        let mut error_flag = false;

        let server_name = match std::env::var("SERVER_NAME") {
            Ok(str) => Ok(str),
            Err(_) => {
                eprintln!("Error: SERVER_NAME must be set.");
                error_flag = true;
                Err(())
            }
        };

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
        let server_name = server_name.unwrap();
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

        Config { server_name, listening_ip_addr, listening_port, delegated_addr, delegated_port, x509_cert_path, x509_key_path, private_key, public_key }
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub const fn listening_ip_addr(&self) -> IpAddr {
        self.listening_ip_addr
    }

    pub const fn listening_port(&self) -> u16 {
        self.listening_port
    }
    
    pub fn delegated_addr(&self) -> &str {
        &self.delegated_addr
    }

    pub const fn delegated_port(&self) -> u16 {
        self.delegated_port
    }

    pub const fn x509_cert_path(&self) -> &PathBuf {
        &self.x509_cert_path
    }
    
    pub fn x509_key_path(&self) -> &PathBuf {
        &self.x509_key_path
    }
}

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