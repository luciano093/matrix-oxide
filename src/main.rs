use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::path::Path;

use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::Value;

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

        println!("m.server: {}", server.delegated_name);

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

fn main() {
    Server::connect("https://matrix.org");    
}
