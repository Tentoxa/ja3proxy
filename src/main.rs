//! JA3Proxy - TLS-Impersonate HTTP Proxy Service
//!
//! A high-performance HTTP API service that forwards requests with Chrome/Firefox
//! TLS fingerprinting (JA3/JA4) to bypass bot detection systems.

mod config;
mod emulation;
mod error;
mod handlers;
mod models;
mod validation;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::TcpListener, signal};
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use crate::{
    config::Config,
    handlers::{health_handler, request_handler, AppState},
};

/// Create the timeout layer (separate function to allow #[allow(deprecated)])
#[allow(deprecated)]
fn create_timeout_layer(timeout_secs: u64) -> tower_http::timeout::TimeoutLayer {
    tower_http::timeout::TimeoutLayer::new(Duration::from_secs(timeout_secs))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load configuration from environment
    let config = Config::from_env();

    // Initialize tracing/logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer())
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        port = config.port,
        max_concurrent = config.max_concurrent,
        default_timeout = config.default_timeout,
        max_request_body_size = config.max_request_body_size,
        max_response_body_size = config.max_response_body_size,
        server_timeout = config.server_timeout,
        allow_private_ips = config.allow_private_ips,
        "Starting JA3Proxy"
    );

    // Log available profiles at startup
    let profiles = emulation::available_profiles();
    info!(profile_count = profiles.len(), "Loaded TLS profiles");

    // Create shared application state
    let state = AppState::new(config.clone());

    // Build router with layers applied in correct order
    // Note: Layers are applied bottom-up, so the last layer added is the outermost
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/request", post(request_handler))
        .with_state(state)
        // Limit request body size (protects against large payload attacks)
        .layer(DefaultBodyLimit::max(config.max_request_body_size))
        // Request tracing
        .layer(TraceLayer::new_for_http())
        // Server-side request timeout (protects against slow clients)
        .layer(create_timeout_layer(config.server_timeout));

    // Bind to address
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await?;

    info!(address = %addr, "Server listening");

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shutdown complete");
    Ok(())
}

/// Wait for shutdown signals (Ctrl+C or SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down...");
        }
        _ = terminate => {
            info!("Received SIGTERM, shutting down...");
        }
    }
}
