//! Configuration module for environment variables

use std::{env, net::IpAddr, str::FromStr};

/// Server configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    /// Server port (default: 8080)
    pub port: u16,
    /// Log level (default: info)
    pub log_level: String,
    /// Maximum concurrent requests (default: 100)
    pub max_concurrent: usize,
    /// Default request timeout in seconds (default: 30)
    pub default_timeout: u64,
    /// Maximum request body size in bytes (default: 10MB)
    pub max_request_body_size: usize,
    /// Maximum response body size in bytes (default: 50MB)
    pub max_response_body_size: usize,
    /// Server request timeout in seconds (default: 120)
    pub server_timeout: u64,
    /// Blocked IP ranges for SSRF protection (internal networks)
    pub blocked_ip_ranges: Vec<IpRange>,
    /// Allow requests to private/internal IPs (default: false)
    pub allow_private_ips: bool,
}

/// Represents an IP range for blocking
#[derive(Debug, Clone)]
pub struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        Self {
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
            max_concurrent: env::var("MAX_CONCURRENT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
            default_timeout: env::var("DEFAULT_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            max_request_body_size: env::var("MAX_REQUEST_BODY_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10 * 1024 * 1024), // 10MB
            max_response_body_size: env::var("MAX_RESPONSE_BODY_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50 * 1024 * 1024), // 50MB
            server_timeout: env::var("SERVER_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(120),
            blocked_ip_ranges: Self::default_blocked_ranges(),
            allow_private_ips: env::var("ALLOW_PRIVATE_IPS")
                .ok()
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        }
    }

    /// Default blocked IP ranges (RFC 1918, loopback, link-local, etc.)
    fn default_blocked_ranges() -> Vec<IpRange> {
        vec![
            // Loopback
            IpRange {
                start: IpAddr::from_str("127.0.0.0").unwrap(),
                end: IpAddr::from_str("127.255.255.255").unwrap(),
            },
            // Private Class A
            IpRange {
                start: IpAddr::from_str("10.0.0.0").unwrap(),
                end: IpAddr::from_str("10.255.255.255").unwrap(),
            },
            // Private Class B
            IpRange {
                start: IpAddr::from_str("172.16.0.0").unwrap(),
                end: IpAddr::from_str("172.31.255.255").unwrap(),
            },
            // Private Class C
            IpRange {
                start: IpAddr::from_str("192.168.0.0").unwrap(),
                end: IpAddr::from_str("192.168.255.255").unwrap(),
            },
            // Link-local
            IpRange {
                start: IpAddr::from_str("169.254.0.0").unwrap(),
                end: IpAddr::from_str("169.254.255.255").unwrap(),
            },
            // AWS/Cloud Metadata
            IpRange {
                start: IpAddr::from_str("169.254.169.254").unwrap(),
                end: IpAddr::from_str("169.254.169.254").unwrap(),
            },
            // IPv6 loopback
            IpRange {
                start: IpAddr::from_str("::1").unwrap(),
                end: IpAddr::from_str("::1").unwrap(),
            },
        ]
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}
