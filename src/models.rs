//! Request and Response models for the proxy API

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Incoming proxy request from the client
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyRequest {
    /// Target URL to request
    pub url: String,

    /// HTTP method (GET, POST, PUT, DELETE, etc.)
    pub method: String,

    /// Custom HTTP headers to send
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// Request body for POST/PUT requests
    #[serde(default)]
    pub body: Option<String>,

    /// Upstream proxy URL (HTTP/HTTPS/SOCKS5)
    /// Format: http://user:pass@host:port or socks5://host:port
    #[serde(default)]
    pub proxy: Option<String>,

    /// Request timeout in seconds (default: 30)
    #[serde(default = "default_timeout")]
    pub timeout: u64,

    /// TLS profile to emulate (e.g., "chrome_131", "firefox_139")
    #[serde(default)]
    pub tls_profile: Option<String>,
}

fn default_timeout() -> u64 {
    30
}

/// Successful proxy response
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyResponse {
    /// HTTP status code from the target
    pub status: u16,

    /// Response headers (values are arrays for headers with multiple values)
    pub headers: HashMap<String, Vec<String>>,

    /// Response body as UTF-8 text (for JSON/HTML/text responses)
    pub body: String,

    /// Response body as Base64 (for binary data like images)
    pub body_base64: String,

    /// Request duration in milliseconds
    pub elapsed: u64,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service status
    pub status: &'static str,

    /// Service version
    pub version: &'static str,

    /// List of available TLS profiles
    pub profiles: Vec<String>,
}

impl HealthResponse {
    pub fn new(profiles: Vec<String>) -> Self {
        Self {
            status: "ok",
            version: env!("CARGO_PKG_VERSION"),
            profiles,
        }
    }
}
