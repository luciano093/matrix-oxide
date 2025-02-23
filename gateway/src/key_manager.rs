
use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::{path::Path, sync::Arc};

use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::Value;
use tokio::sync::RwLock;
use tokio::time::sleep;

#[derive(Debug, Clone)]
pub struct KeyMananger {
    private_key: Arc<RwLock<SigningKey>>,
    public_key: Arc<RwLock<VerifyingKey>>,
    public_key_b64: Arc<RwLock<String>>,
    valid_until_ts: Arc<RwLock<DateTime<Utc>>>,
}

impl KeyMananger {
    pub fn new() -> Self {
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

        let valid_until_ts = if !valid_until_ts_exists() {
            let valid_until_ts = Utc::now() + Duration::days(6);
            create_valid_until_ts_file(Utc::now() + Duration::days(6));

            valid_until_ts
        } else {
            let mut file = File::open("./.keys/key_rotation.json").unwrap();
            let mut json = String::new();
            file.read_to_string(&mut json).unwrap();

            let json = serde_json::from_str::<Value>(&json).unwrap();

            let valid_until_ts = json["valid_until_ts"].as_str().unwrap();
            let valid_until_ts = DateTime::parse_from_str(&valid_until_ts, "%+").unwrap().to_utc();

            valid_until_ts
        };

        let public_key_b64 = Arc::new(RwLock::new(base64::prelude::BASE64_STANDARD_NO_PAD.encode(public_key)));

        let private_key = Arc::new(RwLock::new(private_key));
        let public_key = Arc::new(RwLock::new(public_key));
        let valid_until_ts = Arc::new(RwLock::new(valid_until_ts));

        let private_key_clone= private_key.clone();
        let public_key_clone = public_key.clone();
        let valid_until_ts_clone = valid_until_ts.clone();
        let public_key_b64_clone = public_key_b64.clone();

        tokio::spawn(async move {
            loop {
                sleep(std::time::Duration::from_millis(((valid_until_ts_clone.read().await.timestamp_millis() as u64).checked_sub(Utc::now().timestamp_millis() as u64)).unwrap_or(0) as u64)).await;
                println!("Initiating key rotation.");

                let (new_private_key, new_public_key) = create_key_pair();
                *private_key_clone.write().await = new_private_key;
                *public_key_clone.write().await = new_public_key;

                *public_key_b64_clone.write().await = base64::prelude::BASE64_STANDARD_NO_PAD.encode(new_public_key);

                let valid_until_ts = Utc::now() + Duration::days(6);
                *valid_until_ts_clone.write().await = valid_until_ts;

                create_valid_until_ts_file(valid_until_ts);

                println!("Key rotation finished.");
            }
        });

        KeyMananger {
            private_key, 
            public_key,
            public_key_b64,
            valid_until_ts,
        }
    }

    pub fn private_key(&self) -> Arc<RwLock<SigningKey>> {
        self.private_key.clone()
    }

    pub fn public_key(&self) -> Arc<RwLock<VerifyingKey>> {
        self.public_key.clone()
    }

    pub fn public_key_b64(&self) -> Arc<RwLock<String>> {
        self.public_key_b64.clone()
    }

    pub async fn valid_until_ts(&self) -> i64 {
        self.valid_until_ts.read().await.timestamp_millis()
    }
}

fn valid_until_ts_exists() -> bool {
    Path::new("./.keys/key_rotation.json").exists()
}

fn create_valid_until_ts_file(valid_until_ts: DateTime<Utc>) {
    if !Path::new("./.keys").exists() {
        create_dir("./.keys").unwrap();
    }

    let json = serde_json::json!({
        "valid_until_ts": valid_until_ts.to_rfc3339(),
    });

    let json = serde_json::to_string_pretty(&json).unwrap();

    let mut file = File::create("./.keys/key_rotation.json").unwrap();
    file.write_all(json.as_bytes()).unwrap();
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
    let mut private_key_file = File::create("./.keys/id_ed25519").unwrap();

    private_key_file.write_all(private_key.as_bytes()).unwrap();

    let public_key = VerifyingKey::from(&private_key);
    
    let mut public_key_file = File::create("./.keys/id_ed25519.pub").unwrap();
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