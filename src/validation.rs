//! URL validation and SSRF protection module

use std::net::{IpAddr, ToSocketAddrs};
use url::Url;

use crate::config::Config;
use crate::error::ProxyError;

/// Allowed URL schemes for outgoing requests
const ALLOWED_SCHEMES: &[&str] = &["http", "https"];

/// Blocked hostnames (case-insensitive)
const BLOCKED_HOSTNAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal", // GCP metadata
    "metadata.google.com",      // GCP metadata alt
    "instance-data",            // AWS metadata hostname
];

/// Validate a URL for SSRF protection
///
/// Checks:
/// 1. URL scheme is http or https
/// 2. Hostname is not on blocklist
/// 3. Resolved IP is not in private/internal ranges (unless allowed)
pub fn validate_url(url_str: &str, config: &Config) -> Result<Url, ProxyError> {
    // Parse URL
    let url = Url::parse(url_str)
        .map_err(|e| ProxyError::invalid_request(format!("Invalid URL: {}", e)))?;

    // Check scheme
    let scheme = url.scheme().to_lowercase();
    if !ALLOWED_SCHEMES.contains(&scheme.as_str()) {
        return Err(ProxyError::invalid_request(format!(
            "URL scheme '{}' not allowed. Only http and https are permitted.",
            scheme
        )));
    }

    // Check for blocked hostnames
    if let Some(host) = url.host_str() {
        let host_lower = host.to_lowercase();

        // Check blocked hostname list
        if BLOCKED_HOSTNAMES
            .iter()
            .any(|&blocked| host_lower == blocked)
        {
            return Err(ProxyError::invalid_request(format!(
                "Hostname '{}' is blocked for security reasons.",
                host
            )));
        }

        // Check for IP in hostname directly
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !config.allow_private_ips && is_ip_blocked(&ip, config) {
                return Err(ProxyError::invalid_request(format!(
                    "IP address '{}' is blocked. Private/internal IPs are not allowed.",
                    ip
                )));
            }
        } else if !config.allow_private_ips {
            // Resolve hostname and check IP
            let port = url.port_or_known_default().unwrap_or(80);
            let addr = format!("{}:{}", host, port);

            if let Ok(mut addrs) = addr.to_socket_addrs() {
                if let Some(socket_addr) = addrs.next() {
                    let ip = socket_addr.ip();
                    if is_ip_blocked(&ip, config) {
                        return Err(ProxyError::invalid_request(format!(
                            "Hostname '{}' resolves to blocked IP '{}'. Private/internal IPs are not allowed.",
                            host, ip
                        )));
                    }
                }
            }
            // Note: If DNS resolution fails, we let wreq handle it and return appropriate error
        }
    } else {
        return Err(ProxyError::invalid_request(
            "URL must have a valid hostname.",
        ));
    }

    Ok(url)
}

/// Check if an IP address is in the blocked ranges
fn is_ip_blocked(ip: &IpAddr, config: &Config) -> bool {
    // Check if IP is in any blocked range
    for range in &config.blocked_ip_ranges {
        if is_ip_in_range(ip, &range.start, &range.end) {
            return true;
        }
    }

    // Additional checks for special addresses
    match ip {
        IpAddr::V4(ipv4) => {
            // 0.0.0.0/8 - Current network
            if ipv4.octets()[0] == 0 {
                return true;
            }
            // 224.0.0.0/4 - Multicast
            if ipv4.octets()[0] >= 224 && ipv4.octets()[0] <= 239 {
                return true;
            }
            // 240.0.0.0/4 - Reserved
            if ipv4.octets()[0] >= 240 {
                return true;
            }
        }
        IpAddr::V6(ipv6) => {
            // fe80::/10 - Link-local
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // fc00::/7 - Unique local
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
        }
    }

    false
}

/// Check if an IP is within a range (simple comparison)
fn is_ip_in_range(ip: &IpAddr, start: &IpAddr, end: &IpAddr) -> bool {
    match (ip, start, end) {
        (IpAddr::V4(ip), IpAddr::V4(s), IpAddr::V4(e)) => {
            let ip_num = u32::from(*ip);
            let start_num = u32::from(*s);
            let end_num = u32::from(*e);
            ip_num >= start_num && ip_num <= end_num
        }
        (IpAddr::V6(ip), IpAddr::V6(s), IpAddr::V6(e)) => {
            let ip_num = u128::from(*ip);
            let start_num = u128::from(*s);
            let end_num = u128::from(*e);
            ip_num >= start_num && ip_num <= end_num
        }
        _ => false, // Mismatched IP versions
    }
}

/// Sanitize a URL for logging by removing credentials
pub fn sanitize_url_for_logging(url_str: &str) -> String {
    match Url::parse(url_str) {
        Ok(mut url) => {
            if url.username() != "" || url.password().is_some() {
                let _ = url.set_username("***");
                let _ = url.set_password(Some("***"));
            }
            url.to_string()
        }
        Err(_) => "[invalid URL]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::from_env()
    }

    #[test]
    fn test_valid_https_url() {
        let config = test_config();
        let result = validate_url("https://www.google.com/search?q=test", &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_blocked_localhost() {
        let config = test_config();
        let result = validate_url("http://localhost:8080/api", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_blocked_loopback_ip() {
        let config = test_config();
        let result = validate_url("http://127.0.0.1:8080/api", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_blocked_private_ip() {
        let config = test_config();
        let result = validate_url("http://192.168.1.1/admin", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_blocked_aws_metadata() {
        let config = test_config();
        let result = validate_url("http://169.254.169.254/latest/meta-data/", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_blocked_file_scheme() {
        let config = test_config();
        let result = validate_url("file:///etc/passwd", &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_url_with_credentials() {
        let sanitized = sanitize_url_for_logging("http://user:password@proxy.example.com:8080");
        assert!(!sanitized.contains("password"));
        assert!(sanitized.contains("***"));
    }

    #[test]
    fn test_sanitize_url_without_credentials() {
        let url = "https://api.example.com/data";
        let sanitized = sanitize_url_for_logging(url);
        assert_eq!(sanitized, url);
    }
}
