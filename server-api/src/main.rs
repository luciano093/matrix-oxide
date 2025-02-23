use serde_json::Value;

#[derive(Debug, Default)]
struct Server {
    delegated_name: String,
}

impl Server {
    async fn connect(url: &str) {
        // get delegated server name
        let res = reqwest::get(format!("{}/.well-known/matrix/server", url)).await.unwrap();
        let body = res.text().await.unwrap();

        let mut server = Server::default();
        server.delegated_name = serde_json::from_str::<Value>(&body).unwrap()["m.server"].as_str().unwrap().to_owned();

        println!("{}", body);

        // get server implemenation name and version
        let res = reqwest::get(format!("https://{}/_matrix/federation/v1/version", server.delegated_name)).await.unwrap();
        let body = res.text().await.unwrap();

        let implementation_name = serde_json::from_str::<Value>(&body).unwrap()["server"]["name"].to_string();
        let implementation_version = serde_json::from_str::<Value>(&body).unwrap()["server"]["version"].to_string();

        println!("implementation name: {} implementation version: {}", implementation_name, implementation_version);

        // get server published signing keys
        let res = reqwest::get(format!("{}/_matrix/key/v2/server", url)).await.unwrap();
        let body = res.text().await.unwrap();
        let res = serde_json::from_str::<Value>(&body).unwrap();

        println!("server_name: {}\nsignatures: {}\nvalid_until_ts: {}\nverify_keys: {}", res["server_name"], res["signatures"], res["valid_until_ts"], res["verify_keys"]);
    }
}

#[tokio::main]
async fn main() {
    Server::connect("https://matrix.org").await;
}
