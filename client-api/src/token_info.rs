use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct TokenInfo {
    token: String,
    expires_in_ms: DateTime<Utc>
}

impl TokenInfo {
    pub fn new(token: String, expires_in_ms: DateTime<Utc>) -> Self {
        Self {
            token,
            expires_in_ms,
        }
    }
}