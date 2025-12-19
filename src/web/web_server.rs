//! Web server module for GhostLink.
//!
//! This module handles the HTTP layer of the application. It serves:
//! 1. The Static UI files (HTML/JS/CSS) from the `static/` directory.
//! 2. The API endpoints (e.g., status, configuration) for the frontend.

use super::shared_state::SharedState;
use anyhow::Result;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, services::ServeDir};
use tracing::debug;

/// Starts the HTTP server on the specified port.
///
/// # Arguments
///
/// * `shared_state` - The thread safe application state.
/// * `port` - The port number to listen on (e.g., 8080).
///
/// # Returns
///
/// * `Ok(())` - If the server runs and stops gracefully.
/// * `Err` - If binding the port fails.
pub async fn serve(shared_state: SharedState, port: u16) -> Result<()> {
    let app = router(shared_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("Web UI available at http://{}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

/// Creates the Axum Router with all routes and middleware configured.
///
/// # Arguments
/// * `shared_state` - The thread safe application state.
pub fn router(shared_state: SharedState) -> Router {
    Router::new()
        .route("/api/ip", get(get_ip))
        .route("/api/status", get(get_status))
        .route("/api/connect", post(post_peer_ip))
        // Serve the "static" directory for all non-API requests
        .fallback_service(ServeDir::new("static"))
        .layer(CorsLayer::permissive())
        .with_state(shared_state)
}

/// Handler for `GET /api/ip`
///
/// Returns the public ip and port of the local node.
async fn get_ip(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let data = state.read().await;
    Json(json!({
        "public_ip": data.public_ip,
    }))
}

/// Handler for `GET /api/status`.
///
/// Returns the current connection state of the application.
///
/// # Returns
/// JSON object: `{ "status": "disconnected" | "punching" | "connected" }`
async fn get_status(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let data = state.read().await;
    Json(json!({
        "status": data.status,
    }))
}

#[derive(Debug, Deserialize)]
struct ConnectionRequest {
    ip: String,
    port: u16,
}

/// Handler for `POST /api/connect`.
///
/// Initiates a P2P connection to the specified peer.
///
/// # Arguments
/// * `input` - JSON payload containing `ip` (String) and `port` (u16).
///
/// # Returns
/// * `200 OK` - If the connection request was received (process starts asynchronously).
/// * `422 Unprocessable Entity` - If the JSON input is invalid (wrong types).
async fn post_peer_ip(Json(input): Json<ConnectionRequest>) -> Result<(), (StatusCode, String)> {
    debug!("peer to connect: {}:{}", input.ip, input.port);

    // TODO: Pass this information to the P2P networking layer to initiate hole punching.
    // Example: state.write().await.target_peer = Some((input.ip, input.port));

    Ok(())
}
