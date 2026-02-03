//! HTTP route handlers for the proxy service

use axum::{extract::State, Json};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::{collections::HashMap, sync::Arc, time::Instant};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use wreq::{Client, Method, Proxy};

use crate::{
    config::Config,
    emulation::{available_profiles, default_profile, parse_tls_profile},
    error::{classify_wreq_error, ProxyError},
    models::{HealthResponse, ProxyRequest, ProxyResponse},
    validation::{sanitize_url_for_logging, validate_url},
};

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub semaphore: Arc<Semaphore>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));
        Self { config, semaphore }
    }
}

/// GET /health - Health check endpoint
pub async fn health_handler() -> Json<HealthResponse> {
    let profiles = available_profiles();
    Json(HealthResponse::new(profiles))
}

/// POST /request - Execute a proxied HTTP request with TLS fingerprint emulation
pub async fn request_handler(
    State(state): State<AppState>,
    Json(req): Json<ProxyRequest>,
) -> Result<Json<ProxyResponse>, ProxyError> {
    // Acquire semaphore permit for concurrency limiting
    let _permit = state
        .semaphore
        .acquire()
        .await
        .map_err(|_| ProxyError::unknown("Service unavailable"))?;

    // Sanitize URL for logging (remove credentials)
    let safe_url = sanitize_url_for_logging(&req.url);

    debug!(
        url = %safe_url,
        method = %req.method,
        profile = ?req.tls_profile,
        "Processing proxy request"
    );

    // SSRF Protection: Validate URL scheme and target
    let validated_url = validate_url(&req.url, &state.config)?;

    // Parse and validate TLS profile
    let emulation = match &req.tls_profile {
        Some(profile) => parse_tls_profile(profile).map_err(|invalid| {
            warn!(profile = %invalid, "Invalid TLS profile requested");
            ProxyError::invalid_profile(&invalid, available_profiles())
        })?,
        None => default_profile(),
    };

    // Parse HTTP method
    let method: Method = req
        .method
        .to_uppercase()
        .parse()
        .map_err(|_| ProxyError::invalid_request(format!("Invalid HTTP method: {}", req.method)))?;

    // Determine timeout (minimum 1 second, maximum 300 seconds)
    let timeout = if req.timeout > 0 && req.timeout <= 300 {
        req.timeout
    } else if req.timeout > 300 {
        300 // Cap at 5 minutes
    } else {
        state.config.default_timeout
    };

    // Build the wreq client with TLS emulation
    let mut client_builder = Client::builder()
        .emulation(emulation)
        .timeout(std::time::Duration::from_secs(timeout));

    // Configure proxy if provided
    if let Some(proxy_url) = &req.proxy {
        // Sanitize proxy URL for logging (credentials removed)
        let safe_proxy_url = sanitize_url_for_logging(proxy_url);
        
        let proxy = Proxy::all(proxy_url).map_err(|e| {
            // Log with sanitized URL only
            error!(proxy = %safe_proxy_url, error = %e, "Invalid proxy configuration");
            ProxyError::proxy_error(format!("Invalid proxy URL: {}", e))
        })?;
        client_builder = client_builder.proxy(proxy);
    }

    let client = client_builder.build().map_err(|e| {
        error!(error = %e, "Failed to build HTTP client");
        ProxyError::unknown(format!("Failed to build client: {}", e))
    })?;

    // Build the request using validated URL
    let mut request_builder = client.request(method.clone(), validated_url.as_str());

    // Add custom headers (with basic validation)
    for (name, value) in &req.headers {
        // Skip potentially dangerous headers
        let name_lower = name.to_lowercase();
        if name_lower == "host" || name_lower == "content-length" || name_lower == "transfer-encoding" {
            continue; // Let wreq handle these
        }
        request_builder = request_builder.header(name.as_str(), value.as_str());
    }

    // Add body if present
    if let Some(body) = &req.body {
        // Body size is already limited by axum's DefaultBodyLimit
        request_builder = request_builder.body(body.clone());
    }

    // Execute the request and measure time
    let start = Instant::now();
    let response = request_builder.send().await.map_err(|e| {
        let (code, message) = classify_wreq_error(&e);
        error!(
            url = %safe_url,
            error = %e,
            code = ?code,
            "Request failed"
        );
        ProxyError::new(axum::http::StatusCode::BAD_GATEWAY, message, code)
    })?;
    let elapsed = start.elapsed().as_millis() as u64;

    // Extract response data
    let status = response.status().as_u16();

    // Collect headers (preserving multiple values)
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in response.headers() {
        let name_str = name.to_string();
        let value_str = value.to_str().unwrap_or_default().to_string();
        headers
            .entry(name_str)
            .or_insert_with(Vec::new)
            .push(value_str);
    }

    // Read body bytes with size limit
    let max_response_size = state.config.max_response_body_size;
    let body_bytes = read_response_body_with_limit(response, max_response_size).await?;

    // Convert to string (lossy for non-UTF8 content)
    let body = String::from_utf8_lossy(&body_bytes).to_string();

    // Also provide Base64 encoding for binary data
    let body_base64 = BASE64.encode(&body_bytes);

    info!(
        url = %safe_url,
        status = status,
        elapsed_ms = elapsed,
        body_size = body_bytes.len(),
        "Request completed"
    );

    Ok(Json(ProxyResponse {
        status,
        headers,
        body,
        body_base64,
        elapsed,
    }))
}

/// Read response body with size limit to prevent OOM
async fn read_response_body_with_limit(
    response: wreq::Response,
    max_size: usize,
) -> Result<Vec<u8>, ProxyError> {
    // Check Content-Length header first if available
    if let Some(content_length) = response.content_length() {
        if content_length as usize > max_size {
            return Err(ProxyError::invalid_request(format!(
                "Response body too large: {} bytes (max: {} bytes)",
                content_length, max_size
            )));
        }
    }

    // Read body bytes
    let body_bytes = response.bytes().await.map_err(|e| {
        error!(error = %e, "Failed to read response body");
        ProxyError::unknown(format!("Failed to read response body: {}", e))
    })?;

    // Final size check
    if body_bytes.len() > max_size {
        return Err(ProxyError::invalid_request(format!(
            "Response body too large: {} bytes (max: {} bytes)",
            body_bytes.len(),
            max_size
        )));
    }

    Ok(body_bytes.to_vec())
}
