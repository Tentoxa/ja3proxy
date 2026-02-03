//! Dynamic TLS profile mapping using wreq-util's Emulation enum
//!
//! This module provides runtime parsing of TLS profile strings (e.g., "chrome_131")
//! to wreq_util::Emulation variants. It leverages strum's VariantArray trait to
//! dynamically discover all available profiles, making it future-proof when new
//! browser versions are added to wreq-util.

use strum::VariantArray;
use wreq_util::Emulation;

/// Parse a TLS profile string into an Emulation variant.
///
/// # Arguments
/// * `profile` - Profile string like "chrome_131", "firefox_139", etc.
///
/// # Returns
/// * `Ok(Emulation)` if the profile is valid
/// * `Err(String)` with the invalid profile name if not found
///
/// # Example
/// ```
/// let emulation = parse_tls_profile("chrome_131").unwrap();
/// ```
pub fn parse_tls_profile(profile: &str) -> Result<Emulation, String> {
    // Use serde deserialization which handles the snake_case naming convention
    // wreq-util serializes as "chrome_131", "firefox_139", etc.
    serde_json::from_str(&format!("\"{}\"", profile)).map_err(|_| profile.to_string())
}

/// Get a list of all available TLS profile names.
///
/// This dynamically reads from Emulation::VARIANTS, so it automatically
/// includes any new profiles added in future wreq-util versions.
///
/// # Returns
/// A vector of profile names like ["chrome_100", "chrome_101", ..., "firefox_139"]
pub fn available_profiles() -> Vec<String> {
    Emulation::VARIANTS
        .iter()
        .filter_map(|e| {
            serde_json::to_string(e)
                .ok()
                .map(|s| s.trim_matches('"').to_string())
        })
        .collect()
}

/// Get the default TLS profile (latest Chrome)
pub fn default_profile() -> Emulation {
    Emulation::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chrome_profile() {
        let result = parse_tls_profile("chrome_131");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_firefox_profile() {
        let result = parse_tls_profile("firefox_139");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_profile() {
        let result = parse_tls_profile("invalid_999");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "invalid_999");
    }

    #[test]
    fn test_available_profiles_not_empty() {
        let profiles = available_profiles();
        assert!(!profiles.is_empty());
        // Should contain common profiles
        assert!(profiles.iter().any(|p| p.starts_with("chrome_")));
        assert!(profiles.iter().any(|p| p.starts_with("firefox_")));
    }
}
