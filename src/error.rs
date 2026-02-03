//! Error types and error codes for the proxy service

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::fmt;

/// Error codes returned by the API
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(dead_code)]
pub enum ErrorCode {
    /// Connection timeout
    Timeout,
    /// DNS resolution failed
    DnsError,
    /// SSL/TLS error
    TlsError,
    /// Invalid or unreachable proxy
    ProxyError,
    /// Request was cancelled
    Cancelled,
    /// Invalid TLS profile specified
    InvalidProfile,
    /// Invalid request parameters
    InvalidRequest,
    /// Unknown/internal error
    Unknown,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCode::Timeout => write!(f, "TIMEOUT"),
            ErrorCode::DnsError => write!(f, "DNS_ERROR"),
            ErrorCode::TlsError => write!(f, "TLS_ERROR"),
            ErrorCode::ProxyError => write!(f, "PROXY_ERROR"),
            ErrorCode::Cancelled => write!(f, "CANCELLED"),
            ErrorCode::InvalidProfile => write!(f, "INVALID_PROFILE"),
            ErrorCode::InvalidRequest => write!(f, "INVALID_REQUEST"),
            ErrorCode::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Standard error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_profiles: Option<Vec<String>>,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>, code: ErrorCode) -> Self {
        Self {
            error: error.into(),
            code,
            available_profiles: None,
        }
    }

    pub fn with_profiles(mut self, profiles: Vec<String>) -> Self {
        self.available_profiles = Some(profiles);
        self
    }
}

/// Proxy error with HTTP status code
#[derive(Debug)]
pub struct ProxyError {
    pub status: StatusCode,
    pub response: ErrorResponse,
}

#[allow(dead_code)]
impl ProxyError {
    pub fn new(status: StatusCode, error: impl Into<String>, code: ErrorCode) -> Self {
        Self {
            status,
            response: ErrorResponse::new(error, code),
        }
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(StatusCode::GATEWAY_TIMEOUT, message, ErrorCode::Timeout)
    }

    pub fn dns_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message, ErrorCode::DnsError)
    }

    pub fn tls_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message, ErrorCode::TlsError)
    }

    pub fn proxy_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_GATEWAY, message, ErrorCode::ProxyError)
    }

    pub fn invalid_profile(profile: &str, available: Vec<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            response: ErrorResponse::new(
                format!("Unknown TLS profile: {}", profile),
                ErrorCode::InvalidProfile,
            )
            .with_profiles(available),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message, ErrorCode::InvalidRequest)
    }

    pub fn unknown(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            message,
            ErrorCode::Unknown,
        )
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        (self.status, Json(self.response)).into_response()
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.response.code, self.response.error)
    }
}

impl std::error::Error for ProxyError {}

/// Classify wreq errors into appropriate error codes
pub fn classify_wreq_error(err: &wreq::Error) -> (ErrorCode, String) {
    let message = err.to_string();

    if err.is_timeout() {
        (
            ErrorCode::Timeout,
            format!("Connection timeout: {}", message),
        )
    } else if err.is_connect() {
        // Check for DNS or TLS errors in the message
        let lower = message.to_lowercase();
        if lower.contains("dns") || lower.contains("resolve") || lower.contains("getaddrinfo") {
            (
                ErrorCode::DnsError,
                format!("DNS resolution failed: {}", message),
            )
        } else if lower.contains("ssl") || lower.contains("tls") || lower.contains("certificate") {
            (ErrorCode::TlsError, format!("TLS error: {}", message))
        } else if lower.contains("proxy") {
            (
                ErrorCode::ProxyError,
                format!("Proxy connection failed: {}", message),
            )
        } else {
            (ErrorCode::Unknown, format!("Connection error: {}", message))
        }
    } else if err.is_request() {
        (
            ErrorCode::InvalidRequest,
            format!("Invalid request: {}", message),
        )
    } else {
        (ErrorCode::Unknown, message)
    }
}
