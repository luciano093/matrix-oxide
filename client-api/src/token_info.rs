use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct TokenInfo {
    token: String,
    expires_in_ms: DateTime<Utc>,
    username: String,
}

impl TokenInfo {
    pub fn new(token: String, expires_in_ms: DateTime<Utc>, username: &str) -> Self {
        Self {
            token,
            expires_in_ms,
            username: username.to_string(),
        }
    }

    pub const fn username(&self) -> &String {
        &self.username
    }
}