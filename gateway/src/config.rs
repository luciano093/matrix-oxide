use std::{net::IpAddr, process::exit};
use std::path::PathBuf;
use std::str::FromStr;

use url::Url;

use crate::{is_valid_address, is_valid_port};

// .env configurations
#[derive(Debug, Clone)]
pub struct Config {
    server_name: String,
    listening_ip_addr: IpAddr,
    listening_port: u16,
    delegated_addr: String,
    delegated_port: u16,
    client_api_uri: String,
    x509_cert_path: PathBuf,
    x509_key_path: PathBuf,
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

        let client_api_uri = match std::env::var("CLIENT_API_URI") {
            Ok(str) => {
                if Url::parse(&str).is_ok() {
                    Ok(str)
                }
                else {
                    eprintln!("Error: CLIENT_API_URI has an invalid URI.");
                    error_flag = true;
                    Err(())
                }
            },
            Err(_) => {
                eprintln!("Error: CLIENT_API_URI must be set.");
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
        let client_api_uri = client_api_uri.unwrap();
        let x509_cert_path = x509_cert_path.unwrap();
        let x509_key_path = x509_key_path.unwrap();

        Config { server_name, listening_ip_addr, listening_port, delegated_addr, delegated_port, client_api_uri, x509_cert_path, x509_key_path }
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

    pub fn client_api_uri(&self) -> &str {
        &self.client_api_uri
    }

    pub const fn x509_cert_path(&self) -> &PathBuf {
        &self.x509_cert_path
    }
    
    pub fn x509_key_path(&self) -> &PathBuf {
        &self.x509_key_path
    }
}